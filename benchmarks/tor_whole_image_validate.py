"""Validate a Tor Browser URL hit through a whole-system Volatility image.

The caller creates a page with a link-only URL, records live browser PIDs,
and captures the entire machine's RAM. This script only publishes aggregates.
"""

import argparse
import hashlib
import json
import platform
import statistics
import subprocess
import time
from pathlib import Path


def rows_deep(rows):
    for row in rows:
        yield row
        yield from rows_deep(row.get("__children", []))


def run_vol(common, plugin, *options):
    start = time.perf_counter()
    result = subprocess.run(
        ["vol", *common, plugin, *options], capture_output=True,
        text=True, encoding="utf-8", errors="replace", timeout=1800,
    )
    elapsed = round(time.perf_counter() - start, 3)
    if result.returncode:
        raise RuntimeError(f"{plugin} exited {result.returncode}: {result.stderr[-1200:]}")
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{plugin} returned invalid JSON: {result.stdout[-600:]}") from exc
    if not isinstance(data, list):
        raise RuntimeError(f"{plugin} did not return row list")
    return list(rows_deep(data)), elapsed


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=("windows", "linux"), required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--symbols", type=Path)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    controls = json.loads(args.control.read_text(encoding="utf-8"))
    link = controls["rendered_link_url"]
    absent = controls["absent_control_url"]
    expected = [int(pid) for pid in controls["browser_pids"]]
    root = Path(__file__).resolve().parents[1]
    common = ["-p", str(root / "plugins")]
    if args.symbols:
        common += ["-s", str(args.symbols.resolve())]
    common += ["-f", str(args.image.resolve()), "-r", "json"]
    pslist, pslist_seconds = run_vol(common, f"{args.target}.pslist")
    pid_field = {int(r["PID"]): r for r in pslist if isinstance(r.get("PID"), int)}
    browser_rows = [pid_field[pid] for pid in expected if pid in pid_field]
    if not browser_rows:
        raise RuntimeError("No live Tor Browser PID was found in the whole-system image")
    plugin = f"tor_session_trace.{args.target}.TorSessionTrace{args.target.title()}"
    attempts = []
    winner = None
    first_duration = None
    first_counts = None
    for process in browser_rows:
        pid = int(process["PID"])
        print(f"Scanning captured browser PID {pid}", flush=True)
        hits, duration = run_vol(common, plugin, "--pid", str(pid), "--max-hits", "1000000")
        if any(row.get("PID") != pid or row.get("Evidence") != "E1:process_memory_string" for row in hits):
            raise RuntimeError(f"Invalid adapter output for PID {pid}")
        link_hits = sum(row.get("Artifact") == link for row in hits)
        absent_hits = sum(row.get("Artifact") == absent for row in hits)
        attempts.append({"pid": pid, "process": process.get("ImageFileName", process.get("COMM")),
                         "seconds": duration, "total_hits": len(hits),
                         "rendered_link_hits": link_hits, "absent_control_hits": absent_hits})
        if absent_hits:
            raise RuntimeError("Absent control was found in browser process memory")
        if link_hits:
            winner = pid
            first_duration = duration
            first_counts = (len(hits), link_hits)
            break
    if winner is None:
        print(json.dumps({"attempts": attempts}, indent=2), flush=True)
        raise RuntimeError("Rendered link was not found through the whole-system adapter")

    durations = [first_duration]
    for _ in range(2):
        hits, duration = run_vol(common, plugin, "--pid", str(winner), "--max-hits", "1000000")
        counts = (len(hits), sum(row.get("Artifact") == link for row in hits))
        if counts != first_counts or any(row.get("Artifact") == absent for row in hits):
            raise RuntimeError(f"Unstable control results for PID {winner}: {counts}")
        durations.append(duration)

    result = {
        "test_type": "Tor Browser in whole-system RAM image via Volatility OS adapter",
        "target_os": args.target,
        "analysis_host": platform.platform(),
        "image_bytes": args.image.stat().st_size,
        "image_sha256": file_sha256(args.image),
        "browser_binary_sha256": controls["browser_binary_sha256"],
        "browser_pids_recorded_live": expected,
        "browser_pids_found_in_image": [int(r["PID"]) for r in browser_rows],
        "selected_pid": winner,
        "pslist_process_count": len(pslist),
        "pslist_seconds": pslist_seconds,
        "run_seconds": durations,
        "median_seconds": round(statistics.median(durations), 3),
        "total_string_hits_per_run": first_counts[0],
        "rendered_unvisited_link_hits_per_run": first_counts[1],
        "absent_control_hits_per_run": 0,
        "attempts": attempts,
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
