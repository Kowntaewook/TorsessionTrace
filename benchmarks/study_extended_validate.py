"""Evaluate extended onion controls with a target-blind YARA URL rule."""

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from study_validate import evaluate
from tor_whole_image_validate import run_vol


ONION_HOST = re.compile(r"^[a-z2-7]{56}\.onion$")
# Locked before acquisition. This rule contains no fixture hostname, target path,
# or target token; the target is used only after the scan to score its output.
BLIND_ONION_URL = r"/https?:\/\/[a-z2-7]{56}\.onion\/[a-z0-9\/._?=&%-]{1,128}/"
DETECTION_FAILURES = {
    "Target found despite being absent from browser page",
    "Rendered target missing from Tor Browser process memory",
}


def decode_yara_value(value):
    raw = bytes.fromhex(value)
    if not raw:
        return ""
    return raw.decode("utf-16le" if b"\x00" in raw else "ascii", errors="replace")


def blind_yara(common, target_os, pids, target):
    plugin = ("windows.vadyarascan.VadYaraScan" if target_os == "windows"
              else "linux.vmayarascan.VmaYaraScan")
    rows, seconds = run_vol(
        common, plugin, "--pid", *(str(pid) for pid in pids),
        "--yara-string", BLIND_ONION_URL, "--insensitive", "--wide",
    )
    candidates = []
    for row in rows:
        if row.get("PID") not in pids:
            raise RuntimeError("Blind YARA returned a process outside selected PIDs")
        candidates.append(decode_yara_value(row["Value"]))
    return {
        "method": "Volatility process-scoped YARA generic v3 onion URL regex, ascii and wide",
        "rule": BLIND_ONION_URL,
        "target_in_rule": False,
        "candidate_string_hits": len(candidates),
        "unique_candidate_strings": len(set(candidates)),
        "target_string_hits": sum(target in candidate for candidate in candidates),
        "target_detected": any(target in candidate for candidate in candidates),
        "seconds_total": seconds,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=("linux", "windows"), required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--symbols", type=Path)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    control = json.loads(args.control.read_text(encoding="utf-8"))
    if control.get("transport") != "real_tor_v3_onion":
        raise RuntimeError("Fixture did not declare real Tor v3 onion transport")
    target = control["target_url"]
    if not ONION_HOST.fullmatch(urlsplit(target).hostname or ""):
        raise RuntimeError("Target URL has no v3 onion hostname")
    result = evaluate(args)
    result["protocol_failures"] = [failure for failure in result["protocol_failures"]
                                   if failure not in DETECTION_FAILURES]
    if control["scenario"] not in ("absent", "text_only", "input_field",
                                   "background_link", "clicked"):
        result["protocol_failures"].append("Unknown extended scenario")
    root = Path(__file__).resolve().parents[1]
    common = ["-p", str(root / "plugins")]
    if args.symbols:
        common += ["-s", str(args.symbols.resolve())]
    common += ["-f", str(args.image.resolve()), "-r", "json"]
    pslist, _ = run_vol(common, f"{args.target}.pslist")
    process_map = {int(row["PID"]): row for row in pslist if isinstance(row.get("PID"), int)}
    tor_pids = [int(pid) for pid in control["tor_process_pids"]]
    found = [pid for pid in tor_pids if pid in process_map]
    if len(tor_pids) != 2 or len(set(tor_pids)) != 2 or len(found) != 2:
        result["protocol_failures"].append("Both distinct Tor daemon PIDs must be in RAM")
    if control["onion_readiness_requests"] < 1 or control["onion_landing_requests"] < 1:
        result["protocol_failures"].append("Onion route or landing request not observed")
    if control["scenario"] == "background_link" and control["neutral_requests"] < 1:
        result["protocol_failures"].append("Neutral foreground tab was not requested")
    pids = result["browser_pids_found_in_image"]
    result["blind_onion_yara_baseline"] = blind_yara(common, args.target, pids, target)
    result["schema_version"] = 2
    result["transport"] = "real_tor_v3_onion"
    result["presentation"] = control["presentation"]
    result["tor_network"] = {
        "onion_hostname_sha256": control["onion_hostname_sha256"],
        "tor_version": control["tor_version"],
        "separate_tor_processes_recorded_live": tor_pids,
        "tor_processes_found_in_image": found,
        "onion_readiness_requests": control["onion_readiness_requests"],
        "onion_landing_requests": control["onion_landing_requests"],
        "onion_readiness_curl_attempts": control["onion_readiness_curl_attempts"],
        "neutral_requests": control["neutral_requests"],
    }
    result["protocol_pass"] = not result["protocol_failures"]
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2), flush=True)
    if not result["protocol_pass"]:
        raise SystemExit("Extended-onion protocol failed; result retained")


if __name__ == "__main__":
    main()
