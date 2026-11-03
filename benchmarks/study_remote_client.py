"""Capture Tor Browser RAM on a runner separate from the onion service host."""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

from study_fixture import browser_pids
from study_onion_fixture import wait_for_route
from tor_onion_probe import log_has_bootstrap, start_tor


def get_onion(hostname, path):
    response = subprocess.run([
        "curl", "--fail", "--silent", "--show-error", "--noproxy", "",
        "--proxy", "socks5h://127.0.0.1:9150", "--max-time", "90",
        f"http://{hostname}{path}",
    ], capture_output=True, timeout=95)
    if response.returncode:
        raise RuntimeError(f"Remote onion request failed for {path.split('/')[1]}")
    return response.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--service-run-id", required=True)
    parser.add_argument("--target-os", choices=("linux", "windows"), required=True)
    parser.add_argument("--scenario", choices=("link_only", "clicked"), required=True)
    parser.add_argument("--browser", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--tor-binary", type=Path, required=True)
    parser.add_argument("--capture-tool", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    args = parser.parse_args()
    if len(args.hostname.split(".")[0]) != 56 or not args.hostname.endswith(".onion"):
        parser.error("hostname must be a v3 onion hostname")
    if len(args.token) != 32 or any(c not in "0123456789abcdef" for c in args.token):
        parser.error("token must be a 32-character lowercase hex value")
    hostname = args.hostname
    base = f"http://{hostname}"
    target = f"{base}/target/{args.token}/{args.target_os}/{args.scenario}"
    absent = f"{base}/absent/{uuid.uuid4().hex}"
    status_path = f"/status/{args.token}/{args.target_os}/{args.scenario}"
    finish_path = f"/finish/{args.token}/{args.target_os}/{args.scenario}"
    client = None
    logfile = None
    driver = None
    route_ready = False
    with tempfile.TemporaryDirectory(prefix="remote-onion-client-") as tmp:
        try:
            root = Path(tmp)
            tor_binary = args.tor_binary.resolve()
            client, logfile = start_tor("client", root, [
                "SocksPort 127.0.0.1:9150",
            ], binary=tor_binary)
            deadline = time.monotonic() + 420
            while time.monotonic() < deadline:
                if client.poll() is not None:
                    raise RuntimeError("Remote-client Tor exited before bootstrap")
                if log_has_bootstrap(logfile):
                    break
                time.sleep(2)
            else:
                raise RuntimeError("Remote-client Tor bootstrap timed out")
            ready_attempts = wait_for_route(hostname, time.monotonic() + 420)
            route_ready = True
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
            landing_attempts = 0
            for landing_attempts in range(1, 4):
                try:
                    driver.get(f"{base}/landing/{args.target_os}/{args.scenario}")
                    source = driver.page_source
                except Exception:
                    try:
                        source = driver.page_source
                    except Exception:
                        source = ""
                if target in source:
                    break
                time.sleep(3)
            else:
                raise RuntimeError("Tor Browser could not load remote onion landing page in three attempts")
            if target not in driver.page_source:
                raise RuntimeError("Remote onion target link missing from browser page")
            click_attempts = 0
            if args.scenario == "clicked":
                for click_attempts in range(1, 4):
                    try:
                        driver.find_element(By.ID, "target").click()
                    except Exception:
                        pass
                    time.sleep(3)
                    try:
                        status = json.loads(get_onion(hostname, status_path))
                    except Exception:
                        status = {"target_requests": 0}
                    if status["target_requests"] > 0:
                        break
                    try:
                        driver.get(f"{base}/landing/{args.target_os}/{args.scenario}")
                    except Exception:
                        pass
                    try:
                        source = driver.page_source
                    except Exception:
                        source = ""
                    if target not in source:
                        raise RuntimeError("Remote onion link missing during click retry")
                else:
                    raise RuntimeError("Tor Browser click produced no remote target request in three attempts")
            time.sleep(2)
            pids_before = browser_pids(browser)
            if not pids_before:
                raise RuntimeError("No Tor Browser process found on client runner")
            tool = str(args.capture_tool.resolve())
            command = (["sudo", "-n", tool, "acquire", str(args.image.resolve())]
                       if platform.system() == "Linux" else
                       [tool, "acquire", str(args.image.resolve())])
            print(f"Capturing remote onion {args.target_os}/{args.scenario}; "
                  f"browser PIDs: {pids_before}", flush=True)
            capture = subprocess.run(command, capture_output=True, text=True, timeout=900)
            if capture.returncode or not args.image.exists() or not args.image.stat().st_size:
                raise RuntimeError("Remote-client whole-RAM capture failed")
            pids_after = browser_pids(browser)
            stable = [pid for pid in pids_before if pid in pids_after]
            if not stable or client.poll() is not None:
                raise RuntimeError("Browser or Tor client did not survive RAM capture")
            status = json.loads(get_onion(hostname, status_path))
            if status["landing_requests"] < 1 or status["ready_requests"] < 1:
                raise RuntimeError("Remote service did not observe readiness and landing")
            if (args.scenario == "clicked") != (status["target_requests"] > 0):
                raise RuntimeError("Remote service request truth disagrees with scenario")
            control = {
                "transport": "remote_tor_v3_onion",
                "scenario": args.scenario,
                "replicate": 1,
                "target_url": target,
                "absent_control_url": absent,
                "target_http_requests": status["target_requests"],
                "onion_landing_requests": status["landing_requests"],
                "onion_readiness_requests": status["ready_requests"],
                "onion_readiness_curl_attempts": ready_attempts,
                "browser_landing_attempts": landing_attempts,
                "browser_click_attempts": click_attempts,
                "browser_current_url_matches_target": driver.current_url == target,
                "onion_hostname_sha256": hashlib.sha256(hostname.encode()).hexdigest(),
                "tor_version": subprocess.check_output(
                    [str(tor_binary), "--version"], text=True,
                ).splitlines()[0],
                "tor_process_pids": [client.pid],
                "browser_pids": stable,
                "browser_pids_before_capture": pids_before,
                "browser_pids_after_capture": pids_after,
                "browser_binary_sha256": hashlib.sha256(browser.read_bytes()).hexdigest(),
                "service_run_id": args.service_run_id,
            }
            args.control.write_text(json.dumps(control, indent=2) + "\n", encoding="utf-8")
            print(f"Captured bytes: {args.image.stat().st_size}; "
                  f"remote target requests: {status['target_requests']}", flush=True)
        finally:
            if driver is not None:
                driver.quit()
            if route_ready:
                for finish_attempt in range(1, 4):
                    try:
                        get_onion(hostname, finish_path)
                        print(f"Remote service completion acknowledged on attempt {finish_attempt}",
                              flush=True)
                        break
                    except Exception as exc:
                        if finish_attempt == 3:
                            print(f"Could not notify remote service of completion after "
                                  f"{finish_attempt} attempts: {exc}", flush=True)
                        else:
                            time.sleep(3)
            if client is not None and client.poll() is None:
                client.terminate()
                try:
                    client.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    client.kill()
                    client.wait()
            if logfile is not None:
                logfile.close()


if __name__ == "__main__":
    main()
