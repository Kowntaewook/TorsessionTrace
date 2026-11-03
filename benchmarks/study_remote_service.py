"""Host an onion service on one runner while dispatching separate client runners."""

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

from tor_onion_probe import log_has_bootstrap, start_tor


CLIENTS = tuple((target_os, scenario)
                for target_os in ("linux", "windows")
                for scenario in ("link_only", "clicked"))


def handler_for(state):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parts = self.path.strip("/").split("/")
            body = None
            content_type = "text/html; charset=utf-8"
            if self.path == "/ready":
                with state["lock"]:
                    state["ready_requests"] += 1
                body = b"ready"
            elif len(parts) == 3 and parts[0] == "landing":
                key = tuple(parts[1:])
                if key in CLIENTS:
                    with state["lock"]:
                        state["landing_requests"][key] += 1
                    target = (f"http://{state['hostname']}/target/{state['token']}/"
                              f"{key[0]}/{key[1]}")
                    body = (f"<html><body><a id='target' href='{target}'>"
                            "Target link</a></body></html>").encode()
            elif len(parts) == 4 and parts[1] == state["token"]:
                key = tuple(parts[2:])
                if key in CLIENTS:
                    if parts[0] == "target":
                        with state["lock"]:
                            state["target_requests"][key] += 1
                        body = b"<html><body>Remote target loaded</body></html>"
                    elif parts[0] == "status":
                        with state["lock"]:
                            snapshot = {
                                "target_requests": state["target_requests"][key],
                                "landing_requests": state["landing_requests"][key],
                                "ready_requests": state["ready_requests"],
                            }
                        body = json.dumps(snapshot).encode()
                        content_type = "application/json"
                    elif parts[0] == "finish":
                        with state["lock"]:
                            state["finished"].add(key)
                        body = b"finished"
            if body is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    return Handler


def dispatch_client(hostname, token):
    repository = os.environ["GITHUB_REPOSITORY"]
    api = f"https://api.github.com/repos/{repository}/actions/workflows/study-remote-client.yml/dispatches"
    payload = json.dumps({"ref": "main", "inputs": {
        "onion_hostname": hostname, "token": token,
        "service_run_id": os.environ["GITHUB_RUN_ID"],
    }}).encode()
    request = Request(api, payload, headers={
        "Authorization": "Bearer " + os.environ["GITHUB_TOKEN"],
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
    }, method="POST")
    with urlopen(request, timeout=30) as response:
        if response.status != 204:
            raise RuntimeError(f"Client workflow dispatch returned {response.status}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tor-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    args = parser.parse_args()
    state = {
        "hostname": None, "token": uuid.uuid4().hex, "lock": threading.Lock(),
        "ready_requests": 0,
        "landing_requests": {key: 0 for key in CLIENTS},
        "target_requests": {key: 0 for key in CLIENTS},
        "finished": set(),
    }
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    process = None
    logfile = None
    dispatched = False
    try:
        with tempfile.TemporaryDirectory(prefix="remote-onion-host-") as tmp:
            root = Path(tmp)
            onion_dir = root / "service" / "onion"
            process, logfile = start_tor("service", root, [
                "SocksPort 0", f"HiddenServiceDir {onion_dir.as_posix()}",
                f"HiddenServicePort 80 127.0.0.1:{server.server_port}",
            ], binary=args.tor_binary.resolve())
            deadline = time.monotonic() + 420
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("Remote onion-service Tor exited")
                if (onion_dir / "hostname").exists() and log_has_bootstrap(logfile):
                    state["hostname"] = (onion_dir / "hostname").read_text().strip()
                    break
                time.sleep(2)
            if not state["hostname"] or len(state["hostname"].split(".")[0]) != 56:
                raise RuntimeError("Remote onion service did not bootstrap")
            print("Remote onion service bootstrapped; dispatching separate client runners", flush=True)
            dispatch_client(state["hostname"], state["token"])
            dispatched = True
            deadline = time.monotonic() + args.timeout_seconds
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("Remote onion-service Tor exited during client captures")
                with state["lock"]:
                    finished = set(state["finished"])
                if finished == set(CLIENTS):
                    break
                time.sleep(5)
            if finished != set(CLIENTS):
                raise RuntimeError(f"Client captures did not finish: {sorted(set(CLIENTS)-finished)}")
    finally:
        with state["lock"]:
            result = {
                "schema_version": 1,
                "service_host": "separate GitHub-hosted Ubuntu runner",
                "service_run_id": os.environ.get("GITHUB_RUN_ID"),
                "dispatch_succeeded": dispatched,
                "onion_hostname_sha256": (hashlib.sha256(state["hostname"].encode()).hexdigest()
                                          if state["hostname"] else None),
                "tor_version": subprocess.check_output(
                    [str(args.tor_binary.resolve()), "--version"], text=True,
                ).splitlines()[0],
                "ready_requests": state["ready_requests"],
                "clients": [{
                    "target_os": key[0], "scenario": key[1],
                    "landing_requests": state["landing_requests"][key],
                    "target_requests": state["target_requests"][key],
                    "finish_received": key in state["finished"],
                } for key in CLIENTS],
            }
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2), flush=True)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if logfile is not None:
            logfile.close()
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
