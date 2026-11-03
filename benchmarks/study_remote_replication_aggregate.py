"""Summarize a preregistered remote-host matrix, including incomplete cells."""

import argparse
import json
import statistics
from pathlib import Path

from study_aggregate import wilson_interval


SCENARIOS = ("absent", "link_only", "clicked")
OPERATING_SYSTEMS = ("linux", "windows")


def load(paths):
    return [json.loads(Path(path).read_text(encoding="utf-8")) for path in paths]


def check_client(row, services):
    key = (row.get("target_os"), row.get("scenario"))
    if key[0] not in OPERATING_SYSTEMS or key[1] not in SCENARIOS:
        return "unexpected cell"
    service = services.get(str(row.get("service_run_id")))
    if service is None or not service.get("dispatch_succeeded"):
        return "missing dispatched service record"
    if row.get("replicate") != service.get("replicate"):
        return "replicate disagrees with service"
    host = next((item for item in service["clients"]
                 if (item["target_os"], item["scenario"]) == key), None)
    if host is None:
        return "service cell missing"
    if (not row.get("protocol_pass") or row.get("protocol_failures") or
            row.get("browser_pids_missing_from_image")):
        return "client protocol failure"
    if row.get("transport") != "remote_tor_v3_onion" or row.get("schema_version") != 2:
        return "wrong client protocol version"
    if (row["tor_network"]["onion_hostname_sha256"] !=
            service["onion_hostname_sha256"]):
        return "service hostname hash mismatch"
    if (row["target_http_requests"] != host["target_requests"] or
            row["tor_network"]["service_landing_requests"] > host["landing_requests"]):
        return "service request counter mismatch"
    if (key[1] == "clicked") != (host["target_requests"] > 0):
        return "request truth disagrees with condition"
    baseline = row.get("blind_onion_yara_baseline")
    if not baseline or baseline.get("target_in_rule") is not False:
        return "missing target-blind baseline"
    return None


def aggregate(service_paths, client_paths, attempt_paths, expected_replicates=10):
    if not 1 <= expected_replicates <= 10:
        raise ValueError("expected_replicates must be 1–10")
    service_rows = load(service_paths)
    services = {str(row["service_run_id"]): row for row in service_rows}
    if len(services) != len(service_rows):
        raise ValueError("Duplicate service run ID")
    attempts = load(attempt_paths)
    client_rows = load(client_paths)
    selected = {}
    excluded = []
    surplus = []
    for row in sorted(client_rows, key=lambda item: int(item["service_run_id"])):
        key = (row.get("target_os"), row.get("scenario"), row.get("replicate"))
        reason = check_client(row, services)
        if reason:
            excluded.append({"cell": key, "service_run_id": row.get("service_run_id"),
                             "reason": reason})
        elif key[2] not in range(1, expected_replicates + 1):
            excluded.append({"cell": key, "service_run_id": row["service_run_id"],
                             "reason": "replicate outside preregistered range"})
        elif key in selected:
            surplus.append({"cell": key, "service_run_id": row["service_run_id"],
                            "image_sha256": row["image_sha256"]})
        else:
            selected[key] = row
    for field in ("image_sha256", "target_sha256"):
        values = [row[field] for row in selected.values()]
        if len(set(values)) != len(values):
            raise ValueError(f"Duplicate selected {field}")
    expected = {(os_name, scenario, replicate)
                for os_name in OPERATING_SYSTEMS for scenario in SCENARIOS
                for replicate in range(1, expected_replicates + 1)}
    summary = []
    for os_name in OPERATING_SYSTEMS:
        for scenario in SCENARIOS:
            group = [selected[(os_name, scenario, replicate)]
                     for replicate in range(1, expected_replicates + 1)
                     if (os_name, scenario, replicate) in selected]
            adapter = sum(bool(row["target_detected_in_browser_memory"]) for row in group)
            yara = sum(bool(row["blind_onion_yara_baseline"]["target_detected"])
                       for row in group)
            n = len(group)
            summary.append({
                "target_os": os_name, "scenario": scenario, "selected_images": n,
                "adapter_detected": adapter,
                "adapter_wilson_95": wilson_interval(adapter, n) if n else None,
                "blind_yara_detected": yara,
                "blind_yara_wilson_95": wilson_interval(yara, n) if n else None,
                "image_level_agreement": sum(
                    bool(row["target_detected_in_browser_memory"]) ==
                    bool(row["blind_onion_yara_baseline"]["target_detected"])
                    for row in group),
                "median_adapter_seconds": (round(statistics.median(
                    row["adapter_seconds_total"] for row in group), 3) if n else None),
                "median_blind_yara_seconds": (round(statistics.median(
                    row["blind_onion_yara_baseline"]["seconds_total"]
                    for row in group), 3) if n else None),
                "service_run_ids": [row["service_run_id"] for row in group],
                "image_sha256": [row["image_sha256"] for row in group],
            })
    return {
        "schema_version": 1, "expected_replicates": expected_replicates,
        "expected_images": len(expected), "selected_images": len(selected),
        "complete": set(selected) == expected,
        "missing_cells": [list(key) for key in sorted(expected - set(selected))],
        "attempts": attempts, "excluded_results": excluded,
        "surplus_analyzable": surplus, "summary": summary,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--services", nargs="+", type=Path, required=True)
    parser.add_argument("--clients", nargs="*", type=Path, default=[])
    parser.add_argument("--attempts", nargs="*", type=Path, default=[])
    parser.add_argument("--expected-replicates", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = aggregate(args.services, args.clients, args.attempts, args.expected_replicates)
    output = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    print(output, end="")


if __name__ == "__main__":
    main()
