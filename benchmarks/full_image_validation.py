"""Exercise each Volatility adapter on an actual whole-system memory image.

The official Volatility test images are not Tor Browser fixtures. This checks
OS symbol resolution, PID selection, VAD/VMA traversal, and URL extraction.
Only aggregate measurements are saved; no extracted artifacts are published.
"""

import argparse
import hashlib
import json
import platform
import statistics
import subprocess
import time
from pathlib import Path


PREFERRED_NAMES = {
    "windows": ("chrome.exe", "firefox.exe", "msedge.exe", "explorer.exe", "svchost.exe"),
    "linux": ("firefox", "chrome", "NetworkManager", "bash", "systemd"),
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def flatten(rows):
    for row in rows:
        yield row
        yield from flatten(row.get("__children", []))


def invoke(common, plugin, *options):
    command = ["vol", *common, plugin, *options]
    start = time.perf_counter()
    completed = subprocess.run(command, capture_output=True, text=True, timeout=1200)
    elapsed = time.perf_counter() - start
    if completed.returncode:
        raise RuntimeError(
            f"{plugin} failed with exit {completed.returncode}:\n{completed.stderr[-4000:]}"
        )
    try:
        rows = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{plugin} returned invalid JSON: {completed.stdout[-1000:]}") from exc
    if not isinstance(rows, list):
        raise RuntimeError(f"{plugin} did not return a row list")
    return rows, elapsed


def choose_process(rows, target):
    candidates = list(flatten(rows))
    for wanted in PREFERRED_NAMES[target]:
        for row in candidates:
            name = str(row.get("ImageFileName", row.get("COMM", row.get("Name", ""))))
            pid = row.get("PID")
            if name.casefold() == wanted.casefold() and isinstance(pid, int) and pid > 0:
                return pid, name
    raise RuntimeError(f"No suitable {target} user process found in pslist")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=("windows", "linux"), required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--symbols", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("--repetitions must be positive")

    root = Path(__file__).resolve().parents[1]
    common = [
        "-p", str(root / "plugins"), "-s", str(args.symbols.resolve()),
        "-f", str(args.image.resolve()), "-r", "json",
    ]
    pslist, pslist_seconds = invoke(common, f"{args.target}.pslist")
    pid, name = choose_process(pslist, args.target)
    plugin = f"tor_session_trace.{args.target}.TorSessionTrace{args.target.title()}"
    durations = []
    hit_counts = []
    for _ in range(args.repetitions):
        rows, duration = invoke(common, plugin, "--pid", str(pid), "--max-hits", "1000000")
        for row in flatten(rows):
            if row.get("PID") != pid or row.get("Evidence") != "E1:process_memory_string":
                raise RuntimeError(f"Unexpected plugin row for PID {pid}: {row}")
        durations.append(round(duration, 3))
        hit_counts.append(len(list(flatten(rows))))
    if not all(hit_counts) or len(set(hit_counts)) != 1:
        raise RuntimeError(f"Expected stable, nonempty extracted hits: {hit_counts}")

    result = {
        "test_type": "Volatility adapter on whole-system image; fixture is not Tor Browser",
        "target_os": args.target,
        "analysis_host": platform.platform(),
        "image_name": args.image.name,
        "image_bytes": args.image.stat().st_size,
        "image_sha256": sha256(args.image),
        "selected_pid": pid,
        "selected_process": name,
        "pslist_process_count": len(list(flatten(pslist))),
        "pslist_seconds": round(pslist_seconds, 3),
        "run_seconds": durations,
        "median_seconds": round(statistics.median(durations), 3),
        "string_hits_per_run": hit_counts[0],
        "max_hits": 1000000,
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
