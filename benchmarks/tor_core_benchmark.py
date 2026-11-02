"""Capture Tor Browser ELF process cores and benchmark the shared extractor.

This validates real browser process memory, not Volatility's whole-image OS adapters.
Only aggregate results and controlled test URLs are written to the output JSON.
"""

import argparse
import bisect
import hashlib
import json
import mmap
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psutil
from elftools.elf.elffile import ELFFile
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
from tor_session_trace import core  # noqa: E402


class CoreLayer:
    def __init__(self, path):
        self.file = open(path, "rb")
        self.mapping = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        with open(path, "rb") as source:
            elf = ELFFile(source)
            if elf["e_type"] != "ET_CORE":
                raise ValueError("Expected an ELF process core")
            self.segments = sorted(
                (int(p["p_vaddr"]), int(p["p_vaddr"] + p["p_filesz"]), int(p["p_offset"]))
                for p in elf.iter_segments()
                if p["p_type"] == "PT_LOAD" and p["p_filesz"] > 0
            )
        self.starts = [start for start, _, _ in self.segments]
        self.sections = [(start, end - start) for start, end, _ in self.segments]
        self.mapped_bytes = sum(length for _, length in self.sections)

    def close(self):
        self.mapping.close()
        self.file.close()

    def read(self, address, length, pad=False):
        index = bisect.bisect_right(self.starts, address) - 1
        if index < 0 or address >= self.segments[index][1]:
            if pad:
                return b"\0" * length
            raise ValueError("unmapped core address")
        start, end, offset = self.segments[index]
        available = min(length, end - address)
        data = self.mapping[offset + address - start:offset + address - start + available]
        return data.ljust(length, b"\0") if pad else data

    def scan(self, context, scanner, sections, progress_callback=None):
        for start, size in sections:
            end = start + size
            for address in range(start, end, scanner.chunk_size):
                length = min(scanner.chunk_size + scanner.overlap, end - address)
                yield from scanner(self.read(address, length), address)


def scan_core(path, visited, link_only, repetitions):
    layer = CoreLayer(path)
    try:
        samples = []
        visit_hits = 0
        link_hits = 0
        total_hits = 0
        for _ in range(repetitions):
            start = time.perf_counter()
            counts = {visited: 0, link_only: 0}
            count = 0
            for hit in core.scan_layer(layer, None, layer.sections, max_hits=1000000):
                count += 1
                if hit.artifact in counts:
                    counts[hit.artifact] += 1
            samples.append(time.perf_counter() - start)
            visit_hits = counts[visited]
            link_hits = counts[link_only]
            total_hits = count
        return {
            "file_bytes": os.path.getsize(path),
            "mapped_bytes": layer.mapped_bytes,
            "segments": len(layer.sections),
            "run_seconds": [round(x, 3) for x in samples],
            "median_seconds": round(statistics.median(samples), 3),
            "median_mib_per_second": round(layer.mapped_bytes / (1024 * 1024) / statistics.median(samples), 2),
            "total_hits": total_hits,
            "visited_url_string_hits": visit_hits,
            "link_only_url_string_hits": link_hits,
        }
    finally:
        layer.close()


def make_server(visited_path, link_only):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = (
                f'<html><body><h1>TorSessionTrace controlled page</h1>'
                f'<a href="{link_only}">Link only</a>'
                f'<p id="marker">{visited_path}</p></body></html>'
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def browser_pids(driver_pid):
    parent = psutil.Process(driver_pid)
    children = parent.children(recursive=True)
    matches = []
    for proc in children:
        try:
            name = proc.name().lower()
            if "firefox" in name or "tor-browser" in name:
                matches.append((proc.memory_info().rss, proc.pid, "-contentproc" in " ".join(proc.cmdline())))
        except psutil.Error:
            continue
    return [pid for _, pid, _ in sorted(matches, reverse=True)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    token = uuid.uuid4().hex
    visited_path = f"/visited-{token}"
    link_only = f"https://link-only.invalid/{token}"
    server = make_server(visited_path, link_only)
    visited = f"http://127.0.0.1:{server.server_port}{visited_path}"

    options = Options()
    options.binary_location = str(args.browser.resolve())
    options.add_argument("-headless")
    options.set_preference("network.proxy.type", 0)
    options.set_preference("browser.shell.checkDefaultBrowser", False)
    options.set_preference("app.update.enabled", False)
    options.set_preference("browser.aboutConfig.showWarning", False)

    driver = None
    result = {
        "test_type": "Tor Browser ELF process core; not whole-system RAM",
        "browser_binary": str(args.browser),
        "browser_binary_sha256": hashlib.sha256(args.browser.read_bytes()).hexdigest(),
        "runner": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "visited_test_url": visited,
        "link_only_test_url": link_only,
        "navigation_verified_by_webdriver": False,
        "cores": [],
    }
    try:
        driver = webdriver.Firefox(service=Service(executable_path=str(args.driver.resolve())), options=options)
        driver.set_page_load_timeout(45)
        driver.get(visited)
        if visited_path not in driver.page_source:
            raise RuntimeError("Controlled page did not load")
        result["navigation_verified_by_webdriver"] = True
        time.sleep(2)
        pids = browser_pids(driver.service.process.pid)
        if not pids:
            raise RuntimeError("No Tor Browser Firefox processes found")
        result["browser_process_count"] = len(pids)
        with tempfile.TemporaryDirectory(prefix="tor-core-") as tempdir:
            for pid in pids[:4]:
                prefix = str(Path(tempdir) / f"firefox-{pid}")
                acquire_start = time.perf_counter()
                capture = subprocess.run(
                    ["sudo", "-n", "gcore", "-o", prefix, str(pid)],
                    text=True, capture_output=True, timeout=120,
                )
                core_path = Path(f"{prefix}.{pid}")
                if capture.returncode or not core_path.exists():
                    result["cores"].append({"pid": pid, "capture_error": capture.stderr[-600:]})
                    continue
                record = {"pid": pid, "acquire_seconds": round(time.perf_counter() - acquire_start, 3)}
                record.update(scan_core(core_path, visited, link_only, args.repetitions))
                result["cores"].append(record)
                core_path.unlink()
                if record["visited_url_string_hits"]:
                    break
        if not any(c.get("visited_url_string_hits", 0) for c in result["cores"]):
            raise RuntimeError("Visited test URL was not found in captured browser cores")
    finally:
        if driver is not None:
            driver.quit()
        server.shutdown()
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
