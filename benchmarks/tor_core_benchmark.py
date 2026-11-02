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
import time
import uuid
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


def scan_core(path, rendered_link, absent_control, repetitions):
    layer = CoreLayer(path)
    try:
        samples = []
        rendered_hits = 0
        absent_hits = 0
        total_hits = 0
        for _ in range(repetitions):
            start = time.perf_counter()
            counts = {rendered_link: 0, absent_control: 0}
            count = 0
            for hit in core.scan_layer(layer, None, layer.sections, max_hits=1000000):
                count += 1
                if hit.artifact in counts:
                    counts[hit.artifact] += 1
            samples.append(time.perf_counter() - start)
            rendered_hits = counts[rendered_link]
            absent_hits = counts[absent_control]
            total_hits = count
        return {
            "file_bytes": os.path.getsize(path),
            "mapped_bytes": layer.mapped_bytes,
            "segments": len(layer.sections),
            "run_seconds": [round(x, 3) for x in samples],
            "median_seconds": round(statistics.median(samples), 3),
            "median_mib_per_second": round(layer.mapped_bytes / (1024 * 1024) / statistics.median(samples), 2),
            "total_hits": total_hits,
            "rendered_link_string_hits": rendered_hits,
            "absent_control_string_hits": absent_hits,
        }
    finally:
        layer.close()


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
    rendered_link = f"https://rendered-link.invalid/{token}"
    absent_control = f"https://absent-control.invalid/{token}"

    options = Options()
    options.binary_location = str(args.browser.resolve())
    options.add_argument("-headless")
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
        "rendered_link_url": rendered_link,
        "absent_control_url": absent_control,
        "dom_render_verified_by_webdriver": False,
        "cores": [],
    }
    try:
        driver = webdriver.Firefox(service=Service(executable_path=str(args.driver.resolve())), options=options)
        driver.set_page_load_timeout(45)
        driver.get("about:blank")
        driver.execute_script(
            "document.body.innerHTML = arguments[0]",
            f'<h1>TorSessionTrace offline page</h1><a href="{rendered_link}">Not visited</a>',
        )
        if rendered_link not in driver.page_source:
            raise RuntimeError("Controlled link was not rendered")
        result["dom_render_verified_by_webdriver"] = True
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
                record.update(scan_core(core_path, rendered_link, absent_control, args.repetitions))
                result["cores"].append(record)
                core_path.unlink()
                if record["rendered_link_string_hits"]:
                    break
        if not any(c.get("rendered_link_string_hits", 0) for c in result["cores"]):
            raise RuntimeError("Rendered link URL was not found in captured browser cores")
    finally:
        if driver is not None:
            driver.quit()
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
