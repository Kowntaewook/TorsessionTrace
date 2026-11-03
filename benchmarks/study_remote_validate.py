"""Evaluate a whole-RAM image captured on a remote onion client runner."""

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from study_extended_validate import DETECTION_FAILURES, blind_yara
from study_validate import evaluate
from tor_whole_image_validate import run_vol


ONION_HOST = re.compile(r"^[a-z2-7]{56}\.onion$")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=("linux", "windows"), required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--symbols", type=Path)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.baseline_yara = False
    control = json.loads(args.control.read_text(encoding="utf-8"))
    if control.get("transport") != "remote_tor_v3_onion":
        raise RuntimeError("Fixture did not declare a remote Tor v3 onion service")
    target = control["target_url"]
    if not ONION_HOST.fullmatch(urlsplit(target).hostname or ""):
        raise RuntimeError("Target URL has no v3 onion hostname")
    result = evaluate(args)
    result["protocol_failures"] = [failure for failure in result["protocol_failures"]
                                   if failure not in DETECTION_FAILURES]
    root = Path(__file__).resolve().parents[1]
    common = ["-p", str(root / "plugins")]
    if args.symbols:
        common += ["-s", str(args.symbols.resolve())]
    common += ["-f", str(args.image.resolve()), "-r", "json"]
    pslist, _ = run_vol(common, f"{args.target}.pslist")
    process_map = {int(row["PID"]): row for row in pslist if isinstance(row.get("PID"), int)}
    tor_pids = [int(pid) for pid in control["tor_process_pids"]]
    found = [pid for pid in tor_pids if pid in process_map]
    if len(tor_pids) != 1 or len(found) != 1:
        result["protocol_failures"].append("Client Tor daemon PID missing from RAM")
    if control["onion_readiness_requests"] < 1 or control["onion_landing_requests"] < 1:
        result["protocol_failures"].append("Remote service readiness or landing not observed")
    pids = result["browser_pids_found_in_image"]
    result["blind_onion_yara_baseline"] = blind_yara(common, args.target, pids, target)
    result["schema_version"] = 2
    result["transport"] = "remote_tor_v3_onion"
    result["service_run_id"] = control["service_run_id"]
    result["tor_network"] = {
        "onion_hostname_sha256": control["onion_hostname_sha256"],
        "client_tor_version": control["tor_version"],
        "client_tor_pid_recorded_live": tor_pids[0],
        "client_tor_pid_found_in_image": found,
        "service_readiness_requests": control["onion_readiness_requests"],
        "service_landing_requests": control["onion_landing_requests"],
        "onion_readiness_curl_attempts": control["onion_readiness_curl_attempts"],
        "browser_landing_attempts": control.get("browser_landing_attempts", 1),
    }
    result["protocol_pass"] = not result["protocol_failures"]
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2), flush=True)
    if not result["protocol_pass"]:
        raise SystemExit("Remote-onion protocol failed; result retained")


if __name__ == "__main__":
    main()
