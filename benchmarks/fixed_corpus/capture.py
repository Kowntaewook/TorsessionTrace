"""Capture one held Linux x86-64 Tor Browser VM as a replayable private corpus case."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import socket
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[2]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class QMP:
    def __init__(self, path: Path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(900)
        self.sock.connect(str(path))
        self.reader = self.sock.makefile("r", encoding="utf-8")
        if "QMP" not in json.loads(self.reader.readline()):
            raise RuntimeError("invalid QMP greeting")
        self.command("qmp_capabilities")

    def command(self, name: str, arguments: dict | None = None) -> dict:
        command = {"execute": name}
        if arguments is not None:
            command["arguments"] = arguments
        self.sock.sendall((json.dumps(command) + "\n").encode())
        while True:
            line = self.reader.readline()
            if not line:
                raise RuntimeError(f"QMP disconnected during {name}")
            response = json.loads(line)
            if "error" in response:
                raise RuntimeError(f"QMP {name}: {response['error']}")
            if "return" in response:
                return response["return"]

    def close(self) -> None:
        self.reader.close()
        self.sock.close()


def ssh_options(args: argparse.Namespace) -> list[str]:
    return ["-i", str(args.ssh_key), "-o", "BatchMode=yes", "-o",
            "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={args.known_hosts}"]


def remote(args: argparse.Namespace, command: str, *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["ssh", *ssh_options(args), "-p", str(args.ssh_port),
                           args.ssh_target, command], check=check, capture_output=True,
                          text=True, timeout=60)


def copy_from_guest(args: argparse.Namespace, name: str, destination: Path) -> None:
    source = f"{args.ssh_target}:{args.guest_dir.rstrip('/')}/{name}"
    subprocess.run(["scp", "-q", *ssh_options(args), "-P", str(args.ssh_port),
                    source, str(destination)], check=True, timeout=120)


def verify_journal(path: Path, control: dict) -> None:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    target_path = urlsplit(control["target_url"]).path
    if sum(r.get("path") == "/landing" for r in rows) < 1:
        raise ValueError("no landing request in independent HTTP journal")
    target_count = sum(r.get("method") == "GET" and r.get("path") == target_path for r in rows)
    if target_count != control["target_http_requests"]:
        raise ValueError("HTTP journal disagrees with guest readiness record")
    if (target_count > 0) != (control["scenario"] == "clicked"):
        raise ValueError("HTTP journal disagrees with assigned scenario")


def verify_archive(archive: Path, expected_sha256: str) -> None:
    digest = hashlib.sha256()
    decoder = subprocess.Popen(["zstd", "-q", "-d", "-c", str(archive)],
                               stdout=subprocess.PIPE)
    assert decoder.stdout is not None
    for block in iter(lambda: decoder.stdout.read(4 * 1024 * 1024), b""):
        digest.update(block)
    if decoder.wait(timeout=900) or digest.hexdigest() != expected_sha256:
        raise ValueError("compressed archive does not restore the captured image")


def main() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qmp", type=Path, required=True)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--ssh-port", type=int, default=2223)
    parser.add_argument("--ssh-target", default="ubuntu@127.0.0.1")
    parser.add_argument("--guest-dir", required=True)
    parser.add_argument("--private-dir", type=Path, required=True)
    parser.add_argument("--symbols", type=Path, required=True)
    parser.add_argument("--vol", type=Path, required=True)
    parser.add_argument("--wait-seconds", type=int, default=600)
    parser.add_argument("--resume", action="store_true",
                        help="Finish analysis of an existing raw case after a local tool failure")
    parser.add_argument("--archive-only", action="store_true",
                        help="Resume after successful analysis; verify outputs then archive")
    args = parser.parse_args()
    if args.archive_only and not args.resume:
        parser.error("--archive-only requires --resume")
    private = args.private_dir.resolve()
    if private.is_relative_to(ROOT):
        parser.error("private corpus cases must be outside the repository")
    ready = private / "ready.json"
    journal_before = private / "http-requests.before.jsonl"
    journal = private / "http-requests.jsonl"
    image = private / "ram.elf"
    if args.resume:
        if not all(path.is_file() for path in (ready, journal_before, journal, image)):
            parser.error("resume requires the existing ready, journals, and raw image")
    else:
        private.mkdir(mode=0o700, parents=True, exist_ok=False)
        ready_path = shlex.quote(args.guest_dir.rstrip("/") + "/ready.json")
        deadline = time.monotonic() + args.wait_seconds
        while time.monotonic() < deadline:
            if remote(args, f"test -f {ready_path}", check=False).returncode == 0:
                break
            time.sleep(2)
        else:
            raise TimeoutError(f"guest did not write {ready_path}; private case retained")
        copy_from_guest(args, "ready.json", ready)
        copy_from_guest(args, "http-requests.jsonl", journal_before)
    control = json.loads(ready.read_text(encoding="utf-8"))
    verify_journal(journal_before, control)
    capture_seconds = None
    if not args.resume:
        # Keep the caller's short symlink spelling: macOS limits AF_UNIX path length.
        qmp = QMP(args.qmp)
        started = time.monotonic()
        try:
            qmp.command("stop")
            try:
                qmp.command("dump-guest-memory", {"paging": False,
                                                    "protocol": f"file:{image}"})
            finally:
                qmp.command("cont")
        finally:
            qmp.close()
        capture_seconds = round(time.monotonic() - started, 3)
        try:
            copy_from_guest(args, "http-requests.jsonl", journal)
        finally:
            remote(args, "touch " + shlex.quote(args.guest_dir.rstrip("/") + "/stop"),
                   check=False)
    if sha256(journal) != sha256(journal_before):
        raise ValueError("HTTP journal changed during RAM acquisition")

    image_sha = sha256(image)
    result_path = private / "study-result.json"
    env = os.environ.copy()
    env["PATH"] = str(args.vol.resolve().parent) + os.pathsep + env.get("PATH", "")
    if not args.archive_only:
        analysis = subprocess.run(
            [str(args.vol.resolve().parent / "python"), str(ROOT / "benchmarks" / "study_validate.py"),
             "--target", "linux", "--image", str(image), "--symbols", str(args.symbols.resolve()),
             "--control", str(ready), "--output", str(result_path),
             "--cache", str(private / "vol-cache"),
             "--pslist-output", str(private / "pslist.json"),
             "--hits-output", str(private / "tor-session-trace.json")],
            cwd=ROOT, env=env, text=True, capture_output=True, timeout=3600,
        )
        (private / "analysis-stdout.txt").write_text(analysis.stdout, encoding="utf-8")
        (private / "analysis-stderr.txt").write_text(analysis.stderr, encoding="utf-8")
        if analysis.returncode:
            raise RuntimeError("Volatility validation failed; raw image retained for inspection")
    elif not all((private / name).is_file() for name in
                 ("pslist.json", "tor-session-trace.json", "study-result.json")):
        raise ValueError("archive-only requires completed original analysis outputs")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if not result["protocol_pass"] or result["image_sha256"] != image_sha:
        raise ValueError("validation mismatch; raw image retained for inspection")

    archive = private / "ram.elf.zst"
    if not archive.is_file():
        subprocess.run(["zstd", "-q", "-3", "-o", str(archive), str(image)],
                       check=True, timeout=900)
    verify_archive(archive, image_sha)
    symbol_files = sorted(args.symbols.rglob("*.json.xz")) + sorted(args.symbols.rglob("*.json"))
    if len(symbol_files) != 1:
        raise ValueError("expected exactly one Linux symbol file; archive and image retained")
    manifest = {
        "schema_version": 1,
        "status": "private_pending_content_audit",
        "fixture": "Tor Browser x86-64 in Ubuntu QEMU; loopback HTTP via local SOCKS; no Tor circuit",
        "scenario": control["scenario"],
        "replicate": control["replicate"],
        "kernel_release": control["kernel_release"],
        "browser_binary_sha256": control["browser_binary_sha256"],
        "capture_seconds": capture_seconds,
        "resumed_after_local_analysis_failure": args.resume,
        "image_bytes": image.stat().st_size,
        "image_sha256": image_sha,
        "archive_bytes": archive.stat().st_size,
        "archive_sha256": sha256(archive),
        "symbols_file": str(symbol_files[0].relative_to(args.symbols)),
        "symbols_sha256": sha256(symbol_files[0]),
        "files_sha256": {name: sha256(private / name) for name in (
            "ready.json", "http-requests.jsonl", "pslist.json",
            "tor-session-trace.json", "study-result.json")},
        "source_sha256": {name: sha256(ROOT / name) for name in (
            "benchmarks/fixed_corpus/guest_fixture.py", "benchmarks/fixed_corpus/capture.py",
            "benchmarks/study_validate.py", "benchmarks/local_socks.py",
            "plugins/tor_session_trace/core.py", "plugins/tor_session_trace/linux.py")},
    }
    (private / "capture-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    image.unlink()
    print(json.dumps({"scenario": control["scenario"],
                      "target_detected": result["target_detected_in_browser_memory"],
                      "target_http_requests": control["target_http_requests"],
                      "archive": str(archive), "archive_sha256": manifest["archive_sha256"]}))


if __name__ == "__main__":
    main()
