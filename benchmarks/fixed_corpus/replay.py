"""Reanalyze an unchanged TorSessionTrace RAM archive and compare its results."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from capture import ROOT, sha256, verify_journal


STABLE_FIELDS = (
    "protocol_pass", "protocol_failures", "target_os", "scenario", "replicate",
    "target_present_in_page", "target_http_requests", "target_detected_in_browser_memory",
    "target_hits", "absent_control_hits", "target_sha256", "image_bytes",
    "image_sha256", "browser_binary_sha256", "browser_pids_recorded_live",
    "browser_pids_found_in_image", "browser_pids_missing_from_image",
    "pslist_process_count", "scans",
)


def restore(archive: Path, destination: Path, expected_hash: str) -> None:
    digest = hashlib.sha256()
    with destination.open("wb") as output:
        decoder = subprocess.Popen(["zstd", "-q", "-d", "-c", str(archive)],
                                   stdout=subprocess.PIPE)
        assert decoder.stdout is not None
        for block in iter(lambda: decoder.stdout.read(4 * 1024 * 1024), b""):
            output.write(block)
            digest.update(block)
        if decoder.wait(timeout=900):
            raise RuntimeError("zstd decompression failed")
    if digest.hexdigest() != expected_hash:
        raise ValueError("restored image hash mismatch")


def main() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True, type=Path)
    parser.add_argument("--symbols", required=True, type=Path)
    parser.add_argument("--vol", required=True, type=Path)
    parser.add_argument("--scratch", type=Path,
                        help="Directory with at least one uncompressed image of free space")
    args = parser.parse_args()
    case = args.case.resolve()
    manifest = json.loads((case / "capture-manifest.json").read_text(encoding="utf-8"))
    archive = case / "ram.elf.zst"
    if sha256(archive) != manifest["archive_sha256"]:
        raise ValueError("RAM archive hash mismatch")
    symbol_file = args.symbols.resolve() / manifest["symbols_file"]
    if sha256(symbol_file) != manifest["symbols_sha256"]:
        raise ValueError("symbol file hash mismatch")
    for name, expected_hash in manifest["files_sha256"].items():
        if sha256(case / name) != expected_hash:
            raise ValueError(f"original {name} hash mismatch")
    for name, expected_hash in manifest["source_sha256"].items():
        if sha256(ROOT / name) != expected_hash:
            raise ValueError(f"source changed since capture: {name}")
    control = json.loads((case / "ready.json").read_text(encoding="utf-8"))
    verify_journal(case / "http-requests.jsonl", control)
    original = json.loads((case / "study-result.json").read_text(encoding="utf-8"))

    scratch = args.scratch.resolve() if args.scratch else None
    with tempfile.TemporaryDirectory(prefix="tor-corpus-replay-", dir=scratch) as temp:
        temp = Path(temp)
        image = temp / "ram.elf"
        restore(archive, image, manifest["image_sha256"])
        if image.stat().st_size != manifest["image_bytes"]:
            raise ValueError("restored image length mismatch")
        env = os.environ.copy()
        env["PATH"] = str(args.vol.resolve().parent) + os.pathsep + env.get("PATH", "")
        result = temp / "study-result.json"
        pslist = temp / "pslist.json"
        hits = temp / "tor-session-trace.json"
        process = subprocess.run(
            [str(args.vol.resolve().parent / "python"),
             str(ROOT / "benchmarks" / "study_validate.py"),
             "--target", "linux", "--image", str(image), "--symbols",
             str(args.symbols.resolve()), "--control", str(case / "ready.json"),
             "--output", str(result), "--cache", str(temp / "vol-cache"),
             "--pslist-output", str(pslist),
             "--hits-output", str(hits)],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=3600,
        )
        if process.returncode:
            raise RuntimeError(f"replay analysis failed: {process.stderr[-1000:]}")
        replayed = json.loads(result.read_text(encoding="utf-8"))
        mismatches = [field for field in STABLE_FIELDS if replayed[field] != original[field]]
        if mismatches:
            raise ValueError(f"stable result fields differ: {mismatches}")
        for name, path in (("pslist.json", pslist), ("tor-session-trace.json", hits)):
            if sha256(path) != manifest["files_sha256"][name]:
                raise ValueError(f"replayed {name} differs from original")
    print(json.dumps({"replay_pass": True, "scenario": manifest["scenario"],
                      "image_sha256": manifest["image_sha256"],
                      "target_hits": original["target_hits"],
                      "target_http_requests": original["target_http_requests"]}))


if __name__ == "__main__":
    main()
