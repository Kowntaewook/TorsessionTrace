"""Cross-check service request truth against primary and extra client RAM results."""

import argparse
import json
from pathlib import Path


EXPECTED = {(target_os, scenario)
            for target_os in ("linux", "windows")
            for scenario in ("link_only", "clicked")}


def aggregate(service_paths, client_paths, extra_paths=()):
    services = [json.loads(Path(path).read_text(encoding="utf-8"))
                for path in service_paths]
    clients = [json.loads(Path(path).read_text(encoding="utf-8")) for path in client_paths]
    extras = [json.loads(Path(path).read_text(encoding="utf-8")) for path in extra_paths]
    by_run = {service["service_run_id"]: service for service in services}
    client_cells = {(row["target_os"], row["scenario"]): row for row in clients}
    if len(by_run) != len(services):
        raise ValueError("Duplicate remote service run IDs")
    if set(client_cells) != EXPECTED or len(clients) != 4:
        raise ValueError("Remote client matrix incomplete or duplicated")
    for field in ("image_sha256", "target_sha256"):
        if len({row[field] for row in clients + extras}) != len(clients + extras):
            raise ValueError(f"Client {field} values are not independent")

    def summarize(client):
        target_os, scenario = client["target_os"], client["scenario"]
        if (target_os, scenario) not in EXPECTED:
            raise ValueError(f"Unexpected remote client cell: {target_os}/{scenario}")
        service = by_run.get(client["service_run_id"])
        if not service or not service["dispatch_succeeded"]:
            raise ValueError(f"Missing dispatched service for {target_os}/{scenario}")
        host = next((row for row in service["clients"]
                     if (row["target_os"], row["scenario"]) == (target_os, scenario)), None)
        if host is None:
            raise ValueError(f"Service cell missing for {target_os}/{scenario}")
        if (not client["protocol_pass"] or
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
        return {
            "target_os": target_os,
            "scenario": scenario,
            "service_run_id": service["service_run_id"],
            "onion_hostname_sha256": service["onion_hostname_sha256"],
            "image_sha256": client["image_sha256"],
            "service_target_requests": host["target_requests"],
            "service_landing_requests": host["landing_requests"],
            "service_finish_received": host["finish_received"],
            "adapter_target_detected": client["target_detected_in_browser_memory"],
            "adapter_target_hits": client["target_hits"],
            "blind_yara_target_detected": client["blind_onion_yara_baseline"]["target_detected"],
            "blind_yara_target_hits": client["blind_onion_yara_baseline"]["target_string_hits"],
            "adapter_seconds": client["adapter_seconds_total"],
            "blind_yara_seconds": client["blind_onion_yara_baseline"]["seconds_total"],
        }
    summary = [summarize(client_cells[cell]) for cell in sorted(EXPECTED)]
    additional = [summarize(client) for client in extras]
    return {
        "schema_version": 1,
        "transport": "remote_tor_v3_onion",
        "service_run_ids": sorted({row["service_run_id"] for row in summary + additional}),
        "service_host": "separate GitHub-hosted Ubuntu runner",
        "summary": summary,
        "additional_analyzable": additional,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--services", nargs="+", type=Path, required=True)
    parser.add_argument("--clients", nargs=4, type=Path, required=True)
    parser.add_argument("--extras", nargs="*", type=Path, default=[])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = aggregate(args.services, args.clients, args.extras)
    output = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    print(output, end="")


if __name__ == "__main__":
    main()
