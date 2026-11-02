"""Prove that a fresh onion service receives a request over a Tor SOCKS client.

This is a network preflight, not a browser or memory experiment. It writes only
aggregate metadata; the onion service key and address stay on the ephemeral runner.
"""

import argparse
import hashlib
import json
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def handler_for(state):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != state["path"]:
                self.send_error(404)
                return
            state["requests"] += 1
            body = b"tor-onion-probe-ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    return Handler


def start_tor(name, root, lines, binary="tor"):
    directory = root / name
    directory.mkdir(mode=0o700)
    data = directory / "data"
    data.mkdir(mode=0o700)
    config = directory / "torrc"
    config.write_text("\n".join([f"DataDirectory {data.as_posix()}", "Log notice stdout", *lines]) + "\n")
    logfile = (directory / "tor.log").open("w+")
    process = subprocess.Popen([str(binary), "-f", str(config)], stdout=logfile,
                               stderr=subprocess.STDOUT)
    return process, logfile


def log_has_bootstrap(logfile):
    logfile.flush()
    return "Bootstrapped 100%" in Path(logfile.name).read_text(errors="replace")


def run(args):
    started = time.monotonic()
    state = {"path": "/probe/" + uuid.uuid4().hex, "requests": 0}
    result = {"schema_version": 1, "probe": "real Tor v3 onion service via SOCKS5h",
              "success": False, "request_count": 0, "service_bootstrap_100": False,
              "client_bootstrap_100": False, "onion_hostname_sha256": None,
              "curl_attempts": 0, "last_curl_exit": None,
              "tor_version": subprocess.check_output(["tor", "--version"], text=True).splitlines()[0]}
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(state))
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    processes = []
    logs = []
    try:
        with tempfile.TemporaryDirectory(prefix="tor-onion-probe-") as tmp:
            root = Path(tmp)
            onion_dir = root / "service" / "onion"
            service, service_log = start_tor("service", root, [
                "SocksPort 0", f"HiddenServiceDir {onion_dir}",
                f"HiddenServicePort 80 127.0.0.1:{server.server_port}",
            ])
            processes.append(service)
            logs.append(service_log)
            client, client_log = start_tor("client", root, ["SocksPort 127.0.0.1:9150"])
            processes.append(client)
            logs.append(client_log)
            deadline = started + args.timeout
            hostname_path = onion_dir / "hostname"
            while time.monotonic() < deadline:
                if service.poll() is not None or client.poll() is not None:
                    result["failure_stage"] = "tor_process_exited"
                    break
                result["service_bootstrap_100"] = log_has_bootstrap(service_log)
                result["client_bootstrap_100"] = log_has_bootstrap(client_log)
                if not hostname_path.exists() or not result["service_bootstrap_100"] or not result["client_bootstrap_100"]:
                    time.sleep(2)
                    continue
                hostname = hostname_path.read_text().strip()
                if not hostname.endswith(".onion") or len(hostname.split(".")[0]) != 56:
                    result["failure_stage"] = "invalid_v3_hostname"
                    break
                result["onion_hostname_sha256"] = hashlib.sha256(hostname.encode()).hexdigest()
                url = f"http://{hostname}{state['path']}"
                result["curl_attempts"] += 1
                try:
                    response = subprocess.run([
                        "curl", "--fail", "--silent", "--show-error", "--noproxy", "",
                        "--proxy", "socks5h://127.0.0.1:9150", "--max-time", "30", url,
                    ], capture_output=True, timeout=35)
                except subprocess.TimeoutExpired:
                    response = None
                result["last_curl_exit"] = response.returncode if response is not None else "timeout"
                if response is not None and response.returncode == 0 and response.stdout == b"tor-onion-probe-ok":
                    result["success"] = state["requests"] == 1
                    if not result["success"]:
                        result["failure_stage"] = "request_count_mismatch"
                    break
                time.sleep(3)
            else:
                result["failure_stage"] = "timeout"
    finally:
        result["request_count"] = state["requests"]
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
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
        server.shutdown()
        server.server_close()
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    if not result["success"]:
        raise SystemExit("Tor onion preflight failed; aggregate result retained")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=420)
    run(parser.parse_args())
