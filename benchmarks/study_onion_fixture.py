"""Capture Tor Browser using a real ephemeral v3 onion service and Tor client."""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

from study_fixture import browser_pids
from tor_onion_probe import log_has_bootstrap, start_tor


def handler_for(state):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/ready":
                body = b"ready"
                state["readiness_requests"] += 1
            elif self.path == "/landing":
                state["landing_requests"] += 1
                if state["scenario"] == "absent":
                    body = b"<html><body>Control landing page</body></html>"
                else:
                    body = ("<html><body><a id='target' href='" +
                            state["target_url"] + "'>Target link</a></body></html>").encode()
            elif self.path == state["target_path"]:
                state["target_requests"] += 1
                body = b"<html><body>Onion target loaded</body></html>"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    return Handler


def wait_for_onion(service, client, service_log, client_log, hostname_path, deadline):
    while time.monotonic() < deadline:
        if service.poll() is not None or client.poll() is not None:
            raise RuntimeError("Tor process exited before onion service was ready")
        if (hostname_path.exists() and log_has_bootstrap(service_log) and
                log_has_bootstrap(client_log)):
            hostname = hostname_path.read_text().strip()
            if hostname.endswith(".onion") and len(hostname.split(".")[0]) == 56:
                return hostname
            raise RuntimeError("Onion service did not create a v3 hostname")
        time.sleep(2)
    raise RuntimeError("Tor bootstrap or onion hostname timed out")


def wait_for_route(hostname, deadline):
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        try:
            response = subprocess.run([
                "curl", "--fail", "--silent", "--show-error", "--noproxy", "",
                "--proxy", "socks5h://127.0.0.1:9150", "--max-time", "30",
                f"http://{hostname}/ready",
            ], capture_output=True, timeout=35)
        except subprocess.TimeoutExpired:
            response = None
        if response is not None and response.returncode == 0 and response.stdout == b"ready":
            return attempts
        time.sleep(3)
    raise RuntimeError("Tor client could not reach onion service through SOCKS5h")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=("absent", "link_only", "clicked"), required=True)
    parser.add_argument("--replicate", type=int, required=True)
    parser.add_argument("--browser", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--tor-binary", type=Path, default=Path("/usr/bin/tor"))
    parser.add_argument("--capture-tool", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--network-timeout", type=int, default=420)
    args = parser.parse_args()
    if args.replicate < 1:
        parser.error("replicate must be positive")

    state = {"scenario": args.scenario, "target_path": "/target/" + uuid.uuid4().hex,
             "target_requests": 0, "landing_requests": 0, "readiness_requests": 0}
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(state))
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="tor-onion-study-") as tmp:
            root = Path(tmp)
            processes = []
            logs = []
            driver = None
            try:
                onion_dir = root / "service" / "onion"
                tor_binary = args.tor_binary.resolve()
                service, service_log = start_tor("service", root, [
                    "SocksPort 0", f"HiddenServiceDir {onion_dir.as_posix()}",
                    f"HiddenServicePort 80 127.0.0.1:{server.server_port}",
                ], binary=tor_binary)
                processes.append(service)
                logs.append(service_log)
                client, client_log = start_tor("client", root, [
                    "SocksPort 127.0.0.1:9150",
                ], binary=tor_binary)
                processes.append(client)
                logs.append(client_log)
                hostname = wait_for_onion(
                    service, client, service_log, client_log, onion_dir / "hostname",
                    time.monotonic() + args.network_timeout,
                )
                ready_attempts = wait_for_route(hostname, time.monotonic() + args.network_timeout)
                base = f"http://{hostname}"
                state["target_url"] = base + state["target_path"]
                absent_url = base + "/absent/" + uuid.uuid4().hex
                browser = args.browser.resolve()
                options = Options()
                options.binary_location = str(browser)
                options.add_argument("-headless")
                options.set_preference("app.update.enabled", False)
                options.set_preference("network.proxy.type", 1)
                options.set_preference("network.proxy.socks", "127.0.0.1")
                options.set_preference("network.proxy.socks_port", 9150)
                options.set_preference("network.proxy.socks_remote_dns", True)
                options.set_preference("network.proxy.no_proxies_on", "")
                os.environ["TOR_PROVIDER"] = "none"
                os.environ["TOR_SOCKS_PORT"] = "9150"
                driver = webdriver.Firefox(
                    service=Service(executable_path=str(args.driver.resolve())), options=options,
                )
                driver.set_page_load_timeout(120)
                try:
                    driver.get(base + "/landing")
                except Exception:
                    raise RuntimeError("Tor Browser could not load onion landing page") from None
                if state["landing_requests"] < 1:
                    raise RuntimeError("Onion landing request not observed by service")
                if args.scenario != "absent":
                    if state["target_url"] not in driver.page_source:
                        raise RuntimeError("Onion target link absent from rendered page")
                elif state["target_url"] in driver.page_source:
                    raise RuntimeError("Absent target leaked into onion landing page")
                if args.scenario == "clicked":
                    try:
                        driver.find_element(By.ID, "target").click()
                    except Exception:
                        raise RuntimeError("Tor Browser could not click onion target") from None
                    if driver.current_url != state["target_url"]:
                        raise RuntimeError("Tor Browser did not navigate to onion target")
                time.sleep(2)
                pids_before = browser_pids(browser)
                if not pids_before:
                    raise RuntimeError("No Tor Browser Firefox process found")
                control = {
                    "transport": "real_tor_v3_onion",
                    "scenario": args.scenario,
                    "replicate": args.replicate,
                    "target_url": state["target_url"],
                    "absent_control_url": absent_url,
                    "target_http_requests": state["target_requests"],
                    "onion_landing_requests": state["landing_requests"],
                    "onion_readiness_requests": state["readiness_requests"],
                    "onion_readiness_curl_attempts": ready_attempts,
                    "onion_hostname_sha256": hashlib.sha256(hostname.encode()).hexdigest(),
                    "tor_version": subprocess.check_output([str(tor_binary), "--version"], text=True).splitlines()[0],
                    "tor_process_pids": [service.pid, client.pid],
                    "browser_pids": pids_before,
                    "browser_pids_before_capture": pids_before,
                    "browser_binary_sha256": hashlib.sha256(browser.read_bytes()).hexdigest(),
                }
                tool = str(args.capture_tool.resolve())
                command = (["sudo", "-n", tool, "acquire", str(args.image.resolve())]
                           if platform.system() == "Linux" else
                           [tool, "acquire", str(args.image.resolve())])
                print(f"Capturing real onion {args.scenario} replicate {args.replicate}; "
                      f"target requests: {state['target_requests']}; browser PIDs: {pids_before}", flush=True)
                capture = subprocess.run(command, capture_output=True, text=True, timeout=900)
                if capture.returncode or not args.image.exists() or not args.image.stat().st_size:
                    raise RuntimeError("Whole-RAM capture failed")
                pids_after = browser_pids(browser)
                stable_pids = [pid for pid in pids_before if pid in pids_after]
                if not stable_pids:
                    raise RuntimeError("No Tor Browser PID survived onion capture")
                if service.poll() is not None or client.poll() is not None:
                    raise RuntimeError("Tor process exited during RAM capture")
                control["target_http_requests"] = state["target_requests"]
                control["onion_landing_requests"] = state["landing_requests"]
                control["onion_readiness_requests"] = state["readiness_requests"]
                control["browser_pids_after_capture"] = pids_after
                control["browser_pids"] = stable_pids
                args.control.write_text(json.dumps(control, indent=2) + "\n", encoding="utf-8")
                print(f"Captured bytes: {args.image.stat().st_size}; "
                      f"stable browser PIDs: {stable_pids}", flush=True)
            finally:
                if driver is not None:
                    driver.quit()
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                for process in processes:
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                for logfile in logs:
                    logfile.close()
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
