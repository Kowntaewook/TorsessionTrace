"""Validate a real-onion Tor Browser whole-RAM fixture and publish aggregate data."""

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

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
    parser.add_argument("--baseline-yara", action="store_true")
    args = parser.parse_args()
    control = json.loads(args.control.read_text(encoding="utf-8"))
    if control.get("transport") != "real_tor_v3_onion":
        raise RuntimeError("Fixture did not declare real Tor v3 onion transport")
    if not ONION_HOST.fullmatch(urlsplit(control["target_url"]).hostname or ""):
        raise RuntimeError("Target URL has no syntactically valid v3 onion hostname")
    result = evaluate(args)
    root = Path(__file__).resolve().parents[1]
    common = ["-p", str(root / "plugins")]
    if args.symbols:
        common += ["-s", str(args.symbols.resolve())]
    common += ["-f", str(args.image.resolve()), "-r", "json"]
    pslist, _ = run_vol(common, f"{args.target}.pslist")
    process_map = {int(row["PID"]): row for row in pslist if isinstance(row.get("PID"), int)}
    tor_pids = [int(pid) for pid in control["tor_process_pids"]]
    found = [pid for pid in tor_pids if pid in process_map]
    if len(tor_pids) != 2 or len(set(tor_pids)) != 2:
        result["protocol_failures"].append("Expected two distinct Tor daemon PIDs")
    if len(found) != len(tor_pids):
        result["protocol_failures"].append("Tor daemon PID missing from RAM process list")
    if control["onion_readiness_requests"] < 1 or control["onion_landing_requests"] < 1:
        result["protocol_failures"].append("Onion route or browser landing request not observed")
    result["protocol_pass"] = not result["protocol_failures"]
    result["transport"] = "real_tor_v3_onion"
    result["tor_network"] = {
        "onion_hostname_sha256": control["onion_hostname_sha256"],
        "tor_version": control["tor_version"],
        "separate_tor_processes_recorded_live": tor_pids,
        "tor_processes_found_in_image": found,
        "onion_readiness_requests": control["onion_readiness_requests"],
        "onion_landing_requests": control["onion_landing_requests"],
        "onion_readiness_curl_attempts": control["onion_readiness_curl_attempts"],
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2), flush=True)
    if not result["protocol_pass"]:
        raise SystemExit("Real-onion scenario protocol failed; aggregate result retained")


if __name__ == "__main__":
    main()
