"""Check the preregistered remote control page and branch dispatch payload."""

import io
import json
import os
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))
import study_remote_service as service  # noqa: E402


class RemoteReplicationTest(unittest.TestCase):
    def test_absent_page_does_not_expose_target(self):
        state = {
            "hostname": "a" * 56 + ".onion",
            "token": "b" * 32,
            "lock": threading.Lock(),
            "landing_requests": {key: 0 for key in service.CLIENTS},
            "target_requests": {key: 0 for key in service.CLIENTS},
            "finished": set(),
            "ready_requests": 0,
        }
        handler = service.handler_for(state)
        for scenario in ("absent", "link_only", "clicked"):
            request = object.__new__(handler)
            request.path = f"/landing/linux/{scenario}"
            request.wfile = io.BytesIO()
            request.send_response = lambda *_: None
            request.send_header = lambda *_: None
            request.end_headers = lambda: None
            request.do_GET()
            page = request.wfile.getvalue().decode()
            self.assertEqual("/target/" in page, scenario != "absent")
            self.assertEqual(state["landing_requests"][("linux", scenario)], 1)

    def test_client_dispatch_uses_current_branch_and_replicate(self):
        class Response:
            status = 204

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        requests = []

        def receive(request, timeout):
            requests.append(request)
            return Response()

        environ = {
            "GITHUB_REPOSITORY": "owner/repo", "GITHUB_TOKEN": "test-token",
            "GITHUB_RUN_ID": "123", "GITHUB_REF_NAME": "research/remote-replication",
            "STUDY_REPLICATE": "7",
        }
        with patch.dict(os.environ, environ), patch.object(service, "urlopen", receive):
            service.dispatch_client("a" * 56 + ".onion", "b" * 32)
        payload = json.loads(requests[0].data)
        self.assertEqual(payload["ref"], "research/remote-replication")
        self.assertEqual(payload["inputs"]["replicate"], "7")
        self.assertEqual(payload["inputs"]["service_run_id"], "123")


if __name__ == "__main__":
    unittest.main()
