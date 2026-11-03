"""Aggregate independent extended-onion captures and the blind comparison."""

import argparse
import json
import statistics
from pathlib import Path

from study_aggregate import wilson_interval


SCENARIOS = ("absent", "text_only", "input_field", "background_link", "clicked")
OPERATING_SYSTEMS = ("linux", "windows")


def aggregate(paths, expected_replicates):
    rows = [json.loads(Path(path).read_text(encoding="utf-8")) for path in paths]
    keyed = {}
    for row in rows:
        key = (row["target_os"], row["scenario"], int(row["replicate"]))
        if key in keyed:
            raise ValueError(f"Duplicate capture cell: {key}")
        if row.get("transport") != "real_tor_v3_onion" or row.get("schema_version") != 2:
            raise ValueError(f"Unexpected result protocol: {key}")
        if not row.get("protocol_pass") or row.get("browser_pids_missing_from_image"):
            raise ValueError(f"Unanalyzable result: {key}")
        baseline = row.get("blind_onion_yara_baseline")
        if not baseline or baseline.get("target_in_rule") is not False:
            raise ValueError(f"Missing target-blind baseline: {key}")
        keyed[key] = row
    expected = {(os_name, scenario, replicate)
                for os_name in OPERATING_SYSTEMS for scenario in SCENARIOS
                for replicate in range(1, expected_replicates + 1)}
    if set(keyed) != expected:
        raise ValueError(f"Incomplete matrix: missing={sorted(expected-set(keyed))}, "
                         f"unexpected={sorted(set(keyed)-expected)}")
    for field in ("image_sha256", "target_sha256"):
        values = [row[field] for row in rows]
        if len(set(values)) != len(values):
            raise ValueError(f"Duplicate {field} across independent captures")
    host_hashes = [row["tor_network"]["onion_hostname_sha256"] for row in rows]
    if len(set(host_hashes)) != len(host_hashes):
        raise ValueError("Duplicate onion hostname across independent captures")
    summary = []
    for os_name in OPERATING_SYSTEMS:
        for scenario in SCENARIOS:
            group = [keyed[(os_name, scenario, replicate)]
                     for replicate in range(1, expected_replicates + 1)]
            adapter = sum(row["target_detected_in_browser_memory"] for row in group)
            blind = sum(row["blind_onion_yara_baseline"]["target_detected"]
                        for row in group)
            summary.append({
                "target_os": os_name,
                "scenario": scenario,
                "independent_captures": len(group),
                "target_requested_captures": sum(row["target_http_requests"] > 0 for row in group),
                "adapter_detected_captures": adapter,
                "adapter_wilson_95": wilson_interval(adapter, len(group)),
                "blind_yara_detected_captures": blind,
                "blind_yara_wilson_95": wilson_interval(blind, len(group)),
                "adapter_target_hits": [row["target_hits"] for row in group],
                "blind_yara_target_hits": [row["blind_onion_yara_baseline"]["target_string_hits"]
                                           for row in group],
                "median_adapter_seconds": round(statistics.median(
                    row["adapter_seconds_total"] for row in group), 3),
                "median_blind_yara_seconds": round(statistics.median(
                    row["blind_onion_yara_baseline"]["seconds_total"] for row in group), 3),
                "image_sha256": [row["image_sha256"] for row in group],
            })
    return {"schema_version": 1, "transport": "real_tor_v3_onion",
            "expected_replicates": expected_replicates, "summary": summary}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("results", nargs="+", type=Path)
    parser.add_argument("--expected-replicates", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.expected_replicates < 1:
        parser.error("expected-replicates must be positive")
    result = aggregate(args.results, args.expected_replicates)
    output = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    print(output, end="")


if __name__ == "__main__":
    main()
