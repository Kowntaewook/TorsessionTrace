"""Summarize independent study captures, rejecting incomplete matrices."""

import argparse
import json
import math
import statistics
from pathlib import Path


SCENARIOS = ("absent", "link_only", "clicked")


def wilson_interval(positive, total, z=1.959963984540054):
    if total <= 0 or not 0 <= positive <= total:
        raise ValueError("Invalid binomial counts")
    p = positive / total
    d = 1 + z * z / total
    center = (p + z * z / (2 * total)) / d
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / d
    return [round(center - margin, 4), round(center + margin, 4)]


def aggregate(paths, expected_os, expected_replicates):
    rows = [json.loads(Path(path).read_text(encoding="utf-8")) for path in paths]
    keyed = {}
    for row in rows:
        key = (row["target_os"], row["scenario"], int(row["replicate"]))
        if key in keyed:
            raise ValueError(f"Duplicate fixture: {key}")
        keyed[key] = row
    expected = {(os_name, scenario, replicate)
                for os_name in expected_os for scenario in SCENARIOS
                for replicate in range(1, expected_replicates + 1)}
    missing = sorted(expected - keyed.keys())
    unexpected = sorted(keyed.keys() - expected)
    if missing or unexpected:
        raise ValueError(f"Incomplete matrix: missing={missing}, unexpected={unexpected}")
    summary = []
    for os_name in expected_os:
        for scenario in SCENARIOS:
            group = [keyed[(os_name, scenario, i)]
                     for i in range(1, expected_replicates + 1)]
            detected = sum(bool(row["target_detected_in_browser_memory"]) for row in group)
            requested = sum(row["target_http_requests"] > 0 for row in group)
            passed = sum(bool(row["protocol_pass"]) for row in group)
            durations = [row.get("adapter_seconds_total", sum(scan.get("seconds", 0)
                         for scan in row["scans"])) for row in group]
            baseline_available = [row["exact_target_yara_baseline"] for row in group
                                  if row.get("exact_target_yara_baseline") and
                                  "error_type" not in row["exact_target_yara_baseline"]]
            summary.append({
                "target_os": os_name,
                "scenario": scenario,
                "independent_captures": len(group),
                "target_detected_captures": detected,
                "detection_fraction": round(detected / len(group), 4),
                "detection_wilson_95": wilson_interval(detected, len(group)),
                "http_requested_captures": requested,
                "protocol_pass_captures": passed,
                "median_all_browser_pid_scan_seconds": round(statistics.median(durations), 3),
                "exact_target_yara_available_captures": len(baseline_available),
                "exact_target_yara_detected_captures": sum(
                    bool(row["target_detected"]) for row in baseline_available
                ),
                "exact_target_yara_median_seconds": (
                    round(statistics.median(row["seconds_total"] for row in baseline_available), 3)
                    if baseline_available else None
                ),
                "image_sha256": [row["image_sha256"] for row in group],
            })
    return {"schema_version": 1, "summary": summary}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("results", nargs="+", type=Path)
    parser.add_argument("--expected-os", nargs="+", choices=("linux", "windows"),
                        default=["linux", "windows"])
    parser.add_argument("--expected-replicates", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.expected_replicates < 1:
        parser.error("expected-replicates must be positive")
    result = aggregate(args.results, args.expected_os, args.expected_replicates)
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
