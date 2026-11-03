"""Record every remote client job, including jobs that fail before analysis."""

import argparse
import json
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-os", choices=("linux", "windows"), required=True)
    parser.add_argument("--scenario", choices=("absent", "link_only", "clicked"), required=True)
    parser.add_argument("--replicate", type=int, required=True)
    parser.add_argument("--capture-outcome", required=True)
    parser.add_argument("--analysis-outcome", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = {
        "schema_version": 1,
        "target_os": args.target_os,
        "scenario": args.scenario,
        "replicate": args.replicate,
        "service_run_id": os.environ.get("SERVICE_RUN_ID"),
        "client_run_id": os.environ.get("GITHUB_RUN_ID"),
        "client_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "source_sha": os.environ.get("GITHUB_SHA"),
        "capture_outcome": args.capture_outcome,
        "analysis_outcome": args.analysis_outcome,
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
