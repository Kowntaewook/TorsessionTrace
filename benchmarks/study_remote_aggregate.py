"""Cross-check remote service request truth against four client RAM results."""

import argparse
import json
from pathlib import Path


EXPECTED = {(target_os, scenario)
            for target_os in ("linux", "windows")
            for scenario in ("link_only", "clicked")}


def aggregate(service_path, client_paths):
    service = json.loads(Path(service_path).read_text(encoding="utf-8"))
    clients = [json.loads(Path(path).read_text(encoding="utf-8")) for path in client_paths]
    service_cells = {(row["target_os"], row["scenario"]): row
                     for row in service["clients"]}
    client_cells = {(row["target_os"], row["scenario"]): row for row in clients}
    if (set(service_cells) != EXPECTED or set(client_cells) != EXPECTED or
            len(service["clients"]) != 4 or len(clients) != 4):
        raise ValueError("Remote service/client matrix incomplete or duplicated")
    if not service["dispatch_succeeded"] or not service["onion_hostname_sha256"]:
        raise ValueError("Remote service did not dispatch or create onion hostname")
    if len({row["image_sha256"] for row in clients}) != 4:
        raise ValueError("Client whole-RAM images are not independent")
    summary = []
    for target_os, scenario in sorted(EXPECTED):
        host = service_cells[(target_os, scenario)]
        client = client_cells[(target_os, scenario)]
        if (not host["finish_received"] or not client["protocol_pass"] or
                client["transport"] != "remote_tor_v3_onion" or
                client["service_run_id"] != service["service_run_id"] or
                client["tor_network"]["onion_hostname_sha256"] !=
                service["onion_hostname_sha256"] or
                client["target_http_requests"] != host["target_requests"] or
                client["tor_network"]["service_landing_requests"] >
                host["landing_requests"]):
            raise ValueError(f"Remote service/client evidence mismatch: {target_os}/{scenario}")
        if (scenario == "clicked") != (host["target_requests"] > 0):
            raise ValueError(f"Request truth disagrees with scenario: {target_os}/{scenario}")
        summary.append({
            "target_os": target_os,
            "scenario": scenario,
            "image_sha256": client["image_sha256"],
            "service_target_requests": host["target_requests"],
            "service_landing_requests": host["landing_requests"],
            "adapter_target_detected": client["target_detected_in_browser_memory"],
            "adapter_target_hits": client["target_hits"],
            "blind_yara_target_detected": client["blind_onion_yara_baseline"]["target_detected"],
            "blind_yara_target_hits": client["blind_onion_yara_baseline"]["target_string_hits"],
            "adapter_seconds": client["adapter_seconds_total"],
            "blind_yara_seconds": client["blind_onion_yara_baseline"]["seconds_total"],
        })
    return {
        "schema_version": 1,
        "transport": "remote_tor_v3_onion",
        "service_run_id": service["service_run_id"],
        "service_host": service["service_host"],
        "onion_hostname_sha256": service["onion_hostname_sha256"],
        "service_ready_requests": service["ready_requests"],
        "summary": summary,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", type=Path, required=True)
    parser.add_argument("--clients", nargs=4, type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = aggregate(args.service, args.clients)
    output = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    print(output, end="")


if __name__ == "__main__":
    main()
