"""Check that the study summary counts independent fixtures and missing cells."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "benchmarks" / "study_aggregate.py"
SPEC = importlib.util.spec_from_file_location("study_aggregate", SCRIPT)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class StudyAggregateTest(unittest.TestCase):
    def test_complete_matrix_and_interval(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            for scenario in module.SCENARIOS:
                for replicate in (1, 2):
                    row = {
                        "target_os": "linux", "scenario": scenario,
                        "replicate": replicate,
                        "target_detected_in_browser_memory": scenario != "absent",
                        "target_http_requests": int(scenario == "clicked"),
                        "protocol_pass": True,
                        "scans": [{"seconds": 1.0}],
                        "image_sha256": f"{scenario}-{replicate}",
                    }
                    path = Path(directory) / f"{scenario}-{replicate}.json"
                    path.write_text(json.dumps(row), encoding="utf-8")
                    paths.append(path)
            result = module.aggregate(paths, ["linux"], 2)
            self.assertEqual(len(result["summary"]), 3)
            self.assertEqual(result["summary"][0]["target_detected_captures"], 0)
            self.assertEqual(result["summary"][1]["target_detected_captures"], 2)
            self.assertEqual(result["summary"][2]["http_requested_captures"], 2)
            with self.assertRaisesRegex(ValueError, "Incomplete matrix"):
                module.aggregate(paths[:-1], ["linux"], 2)


if __name__ == "__main__":
    unittest.main()
