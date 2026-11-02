"""Synthetic process-layer tests; no memory image or browsing claim."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
from tor_session_trace import core  # noqa: E402


class MemoryLayer:
    def __init__(self, data):
        self.data = data

    def scan(self, context, scanner, sections, progress_callback=None):
        for start, size in sections:
            yield from scanner(self.data[start:start + size], start)

    def read(self, offset, length, pad=False):
        data = self.data[offset:offset + length]
        return data.ljust(length, b"\0") if pad else data


def hits(data, max_hits=1000):
    return list(core.scan_layer(MemoryLayer(data), None, [(0, len(data))], max_hits=max_hits))


class CoreTests(unittest.TestCase):
    def test_ascii_and_utf16_urls(self):
        data = b"\0https://example.org/a?x=1\0" + "http://example.net/b".encode("utf-16le")
        found = hits(data)
        self.assertEqual(
            {(hit.encoding, hit.artifact) for hit in found},
            {("ascii", "https://example.org/a?x=1"), ("utf-16le", "http://example.net/b")},
        )

    def test_onion_candidate_and_no_duplicate_host_from_url(self):
        onion = "a" * 56 + ".onion"
        found = hits(("http://" + onion + " " + onion).encode("ascii"))
        self.assertEqual([hit.kind for hit in found], ["url", "onion_candidate"])
        self.assertEqual([hit.artifact for hit in found], ["http://" + onion, onion])

    def test_utf16_onion_candidate(self):
        onion = "b" * 56 + ".onion"
        found = hits(onion.encode("utf-16le"))
        self.assertEqual([(hit.encoding, hit.kind, hit.artifact) for hit in found],
                         [("utf-16le", "onion_candidate", onion)])

    def test_malformed_port_and_trailing_punctuation(self):
        found = hits(b"http://example.org:abc test https://example.net/path).")
        self.assertEqual([hit.artifact for hit in found], ["https://example.net/path"])

    def test_hit_limit(self):
        found = hits(b"http://one.test\0http://two.test\0", max_hits=1)
        self.assertEqual(len(found), 1)


if __name__ == "__main__":
    unittest.main()
