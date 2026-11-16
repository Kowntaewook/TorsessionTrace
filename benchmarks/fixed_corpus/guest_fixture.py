"""Hold a synthetic Tor Browser scenario open for a host-side QEMU RAM dump.

Run inside a dedicated Linux x86-64 VM. This fixture never contacts an onion
service: a local SOCKS relay forwards only to its loopback HTTP server.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psutil
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

from local_socks import LocalSocksHandler, LocalSocksServer


SCENARIOS = ("absent", "link_only", "clicked")


def browser_pids(browser: Path) -> list[int]:
    root = browser.parent.resolve()
    found = []
    for process in psutil.process_iter():
        try:
            executable = process.exe()
            if executable and Path(executable).name.lower().startswith("firefox"):
                if Path(executable).resolve().is_relative_to(root):
                    found.append((process.memory_info().rss, process.pid))
        except (psutil.Error, OSError):
            continue
    return [pid for _, pid in sorted(found, reverse=True)]


def atomic_json(path: Path, data: dict) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", required=True, choices=SCENARIOS)
    parser.add_argument("--replicate", type=int, default=1)
    parser.add_argument("--browser", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--hold-seconds", type=int, default=900)
    args = parser.parse_args()
    if args.replicate < 1:
        parser.error("replicate must be positive")
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    token = uuid.uuid4().hex
    target_path = f"/target/{token}"
    state = {"requests": [], "lock": threading.Lock()}
    journal = out / "http-requests.jsonl"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            entry = {"method": "GET", "path": self.path, "time_ns": time.time_ns()}
            with state["lock"]:
                state["requests"].append(entry)
                with journal.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(entry, sort_keys=True) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
            if self.path == "/landing":
                if args.scenario == "absent":
                    body = b"<html><body>Neutral page</body></html>"
                else:
                    body = ("<html><body><a id='target' href='" + target_url +
                            "'>Synthetic target</a></body></html>").encode()
            elif self.path == target_path:
                body = b"<html><body>Synthetic target loaded</body></html>"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    target_url = f"http://127.0.0.1:{server.server_port}{target_path}"
    absent_control_url = f"http://127.0.0.1:{server.server_port}/absent/{token}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    socks = LocalSocksServer(("127.0.0.1", 9150), LocalSocksHandler)
    socks.target_port = server.server_port
    threading.Thread(target=socks.serve_forever, daemon=True).start()

    browser = args.browser.resolve()
    options = Options()
    options.binary_location = str(browser)
    options.add_argument("-headless")
    options.set_preference("app.update.enabled", False)
    driver = webdriver.Firefox(service=Service(str(args.driver.resolve())), options=options)
    try:
        driver.get(f"http://127.0.0.1:{server.server_port}/landing")
        if args.scenario == "absent":
            if token in driver.page_source:
                raise RuntimeError("absent target leaked into landing page")
        elif target_url not in driver.page_source:
            raise RuntimeError("target link missing from landing page")
        if args.scenario == "clicked":
            driver.find_element(By.ID, "target").click()
            if driver.current_url != target_url:
                raise RuntimeError("click did not navigate to target")
        time.sleep(2)
        with state["lock"]:
            target_requests = sum(row["path"] == target_path for row in state["requests"])
            landing_requests = sum(row["path"] == "/landing" for row in state["requests"])
        if landing_requests < 1 or (target_requests > 0) != (args.scenario == "clicked"):
            raise RuntimeError("HTTP ground truth disagrees with scenario")
        pids = browser_pids(browser)
        if not pids:
            raise RuntimeError("Tor Browser Firefox processes not found")
        ready = {
            "schema_version": 1,
            "scenario": args.scenario,
            "replicate": args.replicate,
            "target_url": target_url,
            "absent_control_url": absent_control_url,
            "target_http_requests": target_requests,
            "landing_http_requests": landing_requests,
            "browser_pids": pids,
            "browser_binary_sha256": hashlib.sha256(browser.read_bytes()).hexdigest(),
            "kernel_release": os.uname().release,
            "ready_time_ns": time.time_ns(),
            "fixture": "loopback HTTP via restricted local SOCKS; no Tor circuit",
        }
        atomic_json(out / "ready.json", ready)
        print(json.dumps({"ready": str(out / "ready.json"), "pids": pids}), flush=True)
        stop = out / "stop"
        deadline = time.monotonic() + args.hold_seconds
        while not stop.exists() and time.monotonic() < deadline:
            time.sleep(0.25)
    finally:
        driver.quit()
        socks.shutdown()
        socks.server_close()
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
