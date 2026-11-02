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


def browser_pids(driver_pid):
    parent = psutil.Process(driver_pid)
    matches = []
    for process in parent.children(recursive=True):
        try:
            if "firefox" in process.name().lower():
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
        pids = browser_pids(driver.service.process.pid)
        if not pids:
            raise RuntimeError("No Tor Browser Firefox process found")
        controls = {
            "rendered_link_url": link,
            "absent_control_url": absent,
            "browser_pids": pids,
            "browser_binary_sha256": hashlib.sha256(browser.read_bytes()).hexdigest(),
        }
        args.control.write_text(json.dumps(controls, indent=2) + "\n")
        print(f"Capturing whole RAM with {len(pids)} Tor Browser processes", flush=True)
        capture = subprocess.run(
            ["sudo", "-n", str(args.avml.resolve()), "acquire", str(args.image.resolve())],
            text=True, capture_output=True, timeout=900,
        )
        if capture.returncode or not args.image.exists():
            raise RuntimeError(f"AVML failed: {capture.stderr[-1500:]}")
        print(f"Whole RAM image bytes: {os.path.getsize(args.image)}", flush=True)
    finally:
        driver.quit()


if __name__ == "__main__":
    main()
