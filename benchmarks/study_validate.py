"""Evaluate one independent whole-RAM capture without exporting target URLs."""

import argparse
import hashlib
import json
import platform
from pathlib import Path

from tor_whole_image_validate import file_sha256, run_vol


def evaluate(args):
    control = json.loads(args.control.read_text(encoding="utf-8"))
    target = control["target_url"]
    absent = control["absent_control_url"]
    scenario = control["scenario"]
    root = Path(__file__).resolve().parents[1]
    common = []
    if args.cache:
        args.cache.mkdir(parents=True, exist_ok=True)
        common += ["--cache-path", str(args.cache.resolve())]
    common += ["-p", str(root / "plugins")]
    if args.symbols:
        common += ["-s", str(args.symbols.resolve())]
    common += ["-f", str(args.image.resolve()), "-r", "json"]
    pslist, pslist_seconds = run_vol(common, f"{args.target}.pslist")
    if args.pslist_output:
        args.pslist_output.write_text(json.dumps(pslist, indent=2) + "\n", encoding="utf-8")
    process_map = {int(r["PID"]): r for r in pslist if isinstance(r.get("PID"), int)}
    pids = [int(pid) for pid in control["browser_pids"] if int(pid) in process_map]
    missing_pids = [int(pid) for pid in control["browser_pids"] if int(pid) not in process_map]
    if not pids:
        candidates = [(r.get("PID"), r.get("ImageFileName", r.get("COMM")))
                      for r in pslist if "firefox" in str(r.get("ImageFileName", r.get("COMM", ""))).lower()]
        raise RuntimeError(f"Recorded Tor Browser PIDs {control['browser_pids']} missing "
                           f"from whole-RAM pslist; Firefox candidates: {candidates}")
    plugin = f"tor_session_trace.{args.target}.TorSessionTrace{args.target.title()}"
    print(f"Scanning captured Tor Browser PIDs {pids}", flush=True)
    hits, adapter_seconds_total = run_vol(
        common, plugin, "--pid", *(str(pid) for pid in pids), "--max-hits", "1000000"
    )
    if args.hits_output:
        args.hits_output.write_text(json.dumps(hits, indent=2) + "\n", encoding="utf-8")
    if any(row.get("PID") not in pids or row.get("Evidence") != "E1:process_memory_string"
           for row in hits):
        raise RuntimeError("Invalid adapter evidence or unexpected PID")
    scans = []
    for pid in pids:
        process_hits = [row for row in hits if row.get("PID") == pid]
        scans.append({
            "pid": pid,
            "process": process_map[pid].get("ImageFileName", process_map[pid].get("COMM")),
            "string_hits": len(process_hits),
            "target_hits": sum(row.get("Artifact") == target for row in process_hits),
            "absent_control_hits": sum(row.get("Artifact") == absent for row in process_hits),
        })
    baseline = None
    if args.baseline_yara:
        yara_plugin = ("windows.vadyarascan.VadYaraScan" if args.target == "windows"
                       else "linux.vmayarascan.VmaYaraScan")
        try:
            yara_rows, yara_seconds = run_vol(
                common, yara_plugin, "--pid", *(str(pid) for pid in pids),
                "--yara-string", target,
            )
            yara_hits = sum(row.get("PID") in pids for row in yara_rows)
            baseline = {
                "method": "Volatility process-scoped YARA exact known target",
                "target_hits": yara_hits,
                "target_detected": yara_hits > 0,
                "seconds_total": yara_seconds,
            }
        except Exception as exc:
            baseline = {"method": "Volatility process-scoped YARA exact known target",
                        "error_type": type(exc).__name__}
    target_hits = sum(row["target_hits"] for row in scans)
    absent_hits = sum(row["absent_control_hits"] for row in scans)
    failures = []
    if missing_pids:
        failures.append(f"Captured browser PIDs missing from pslist: {missing_pids}")
    if absent_hits:
        failures.append("Absent control found in Tor Browser process memory")
    if scenario == "absent" and target_hits:
        failures.append("Target found despite being absent from browser page")
    if scenario != "absent" and not target_hits:
        failures.append("Rendered target missing from Tor Browser process memory")
    if (scenario == "clicked") != (control["target_http_requests"] > 0):
        failures.append("HTTP request ground truth disagrees with scenario")
    result = {
        "schema_version": 1,
        "protocol_pass": not failures,
        "protocol_failures": failures,
        "target_os": args.target,
        "scenario": scenario,
        "replicate": control["replicate"],
        "target_present_in_page": scenario != "absent",
        "target_http_requests": control["target_http_requests"],
        "target_detected_in_browser_memory": target_hits > 0,
        "target_hits": target_hits,
        "absent_control_hits": absent_hits,
        "target_sha256": hashlib.sha256(target.encode()).hexdigest(),
        "analysis_host": platform.platform(),
        "image_bytes": args.image.stat().st_size,
        "image_sha256": file_sha256(args.image),
        "browser_binary_sha256": control["browser_binary_sha256"],
        "browser_pids_recorded_live": control["browser_pids"],
        "browser_pids_found_in_image": pids,
        "browser_pids_missing_from_image": missing_pids,
        "pslist_process_count": len(pslist),
        "pslist_seconds": pslist_seconds,
        "adapter_seconds_total": adapter_seconds_total,
        "exact_target_yara_baseline": baseline,
        "scans": scans,
    }
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=("windows", "linux"), required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--symbols", type=Path)
    parser.add_argument("--cache", type=Path,
                        help="Writable Volatility cache directory")
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline-yara", action="store_true")
    parser.add_argument("--pslist-output", type=Path,
                        help="Save all flattened process rows; may contain private data")
    parser.add_argument("--hits-output", type=Path,
                        help="Save all extracted hits; may contain private URLs")
    args = parser.parse_args()
    result = evaluate(args)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2), flush=True)
    if not result["protocol_pass"]:
        raise SystemExit("Scenario protocol failed; aggregate result retained")


if __name__ == "__main__":
    main()
