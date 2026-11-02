"""Run Tor Browser and capture whole Linux RAM while a link-only page is open."""

import argparse
import hashlib
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import psutil
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service


def browser_pids(browser):
    root = browser.parent.resolve()
    matches = []
    for process in psutil.process_iter():
        try:
            executable = process.exe()
            if (executable and Path(executable).name.lower().startswith("firefox") and
                    Path(executable).resolve().is_relative_to(root)):
                matches.append((process.memory_info().rss, process.pid))
        except psutil.Error:
            continue
    return [pid for _, pid in sorted(matches, reverse=True)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--avml", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    args = parser.parse_args()
    token = uuid.uuid4().hex
    link = f"https://rendered-link.invalid/{token}"
    absent = f"https://absent-control.invalid/{token}"
    browser = args.browser.resolve()
    options = Options()
    options.binary_location = str(browser)
    options.add_argument("-headless")
    options.set_preference("app.update.enabled", False)
    driver = webdriver.Firefox(
        service=Service(executable_path=str(args.driver.resolve())), options=options
    )
    try:
        driver.get("about:blank")
        driver.execute_script(
            "document.body.innerHTML = arguments[0]",
            f'<h1>TorSessionTrace whole-RAM test</h1><a href="{link}">Not visited</a>',
        )
        if link not in driver.page_source:
            raise RuntimeError("Offline link was not rendered")
        time.sleep(2)
        pids_before = browser_pids(browser)
        if not pids_before:
            raise RuntimeError("No Tor Browser Firefox process found")
        controls = {
            "rendered_link_url": link,
            "absent_control_url": absent,
            "browser_pids": pids_before,
            "browser_binary_sha256": hashlib.sha256(browser.read_bytes()).hexdigest(),
        }
        print(f"Capturing whole RAM with {len(pids_before)} Tor Browser processes", flush=True)
        capture = subprocess.run(
            ["sudo", "-n", str(args.avml.resolve()), "acquire", str(args.image.resolve())],
            text=True, capture_output=True, timeout=900,
        )
        if capture.returncode or not args.image.exists():
            raise RuntimeError(f"AVML failed: {capture.stderr[-1500:]}")
        pids_after = browser_pids(browser)
        controls["browser_pids"] = [pid for pid in pids_before if pid in pids_after]
        if not controls["browser_pids"]:
            raise RuntimeError("No Tor Browser PID survived capture")
        args.control.write_text(json.dumps(controls, indent=2) + "\n")
        print(f"Whole RAM image bytes: {os.path.getsize(args.image)}", flush=True)
    finally:
        driver.quit()


if __name__ == "__main__":
    main()
