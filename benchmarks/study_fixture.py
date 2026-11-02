"""Create one independently captured, ground-truthed Tor Browser RAM fixture.

The random target is never passed on the browser command line. A local HTTP
server records whether the target was actually requested. No raw RAM or URL
is uploaded by the workflows.
"""

import argparse
import hashlib
import json
import os
import platform
import subprocess
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


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == state["target_path"]:
                state["target_requests"] += 1
                body = b"<html><body>Target loaded</body></html>"
            elif self.path == "/landing":
                if state["scenario"] == "absent":
                    body = b"<html><body>Control landing page</body></html>"
                else:
                    body = ("<html><body><a id='target' href='" +
                            state["target_url"] + "'>Target link</a></body></html>").encode()
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

    return Handler


def browser_pids(driver_pid):
    parent = psutil.Process(driver_pid)
    found = []
    for process in parent.children(recursive=True):
        try:
            if "firefox" in process.name().lower():
                found.append((process.memory_info().rss, process.pid))
        except psutil.Error:
            continue
    return [pid for _, pid in sorted(found, reverse=True)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    parser.add_argument("--replicate", type=int, required=True)
    parser.add_argument("--browser", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--capture-tool", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    args = parser.parse_args()
    if args.replicate < 1:
        parser.error("replicate must be positive")

    token = uuid.uuid4().hex
    state = {"scenario": args.scenario,
             "target_path": f"/target/{token}", "target_requests": 0}
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
    base = f"http://127.0.0.1:{server.server_port}"
    state["target_url"] = base + state["target_path"]
    absent_url = base + f"/absent/{token}"
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    socks = LocalSocksServer(("127.0.0.1", 9150), LocalSocksHandler)
    socks.target_port = server.server_port
    socks_thread = threading.Thread(target=socks.serve_forever, daemon=True)
    socks_thread.start()

    browser = args.browser.resolve()
    options = Options()
    options.binary_location = str(browser)
    options.add_argument("-headless")
    options.set_preference("app.update.enabled", False)
    driver = webdriver.Firefox(
        service=Service(executable_path=str(args.driver.resolve())), options=options
    )
    try:
        driver.get(base + "/landing")
        if args.scenario != "absent":
            if state["target_url"] not in driver.page_source:
                raise RuntimeError("Target link missing from rendered page")
        elif token in driver.page_source:
            raise RuntimeError("Absent target leaked into rendered page")
        if args.scenario == "clicked":
            driver.find_element(By.ID, "target").click()
            if driver.current_url != state["target_url"]:
                raise RuntimeError("Browser did not navigate to target")
        time.sleep(2)
        request_count = state["target_requests"]
        print(f"Target HTTP requests: {request_count}", flush=True)
        pids = browser_pids(driver.service.process.pid)
        if not pids:
            raise RuntimeError("No Tor Browser Firefox process found")
        control = {
            "scenario": args.scenario,
            "replicate": args.replicate,
            "target_url": state["target_url"],
            "absent_control_url": absent_url,
            "target_http_requests": request_count,
            "browser_pids": pids,
            "browser_binary_sha256": hashlib.sha256(browser.read_bytes()).hexdigest(),
        }
        args.control.write_text(json.dumps(control, indent=2) + "\n", encoding="utf-8")
        tool = str(args.capture_tool.resolve())
        command = (["sudo", "-n", tool, "acquire", str(args.image.resolve())]
                   if platform.system() == "Linux" else
                   [tool, "acquire", str(args.image.resolve())])
        print(f"Capturing {args.scenario} replicate {args.replicate}; "
              f"browser PIDs: {len(pids)}", flush=True)
        capture = subprocess.run(command, capture_output=True, text=True, timeout=900)
        if capture.returncode or not args.image.exists() or not args.image.stat().st_size:
            raise RuntimeError(f"RAM capture failed: {capture.stderr[-1200:]}")
        print(f"Captured bytes: {os.path.getsize(args.image)}", flush=True)
    finally:
        driver.quit()
        socks.shutdown()
        socks.server_close()
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
