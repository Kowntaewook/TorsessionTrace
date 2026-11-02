"""Exercise the real SOCKS handshake and loopback-only relay."""

import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks"))
from local_socks import LocalSocksHandler, LocalSocksServer, recv_exact  # noqa: E402


class HttpHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"fixture-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class LocalSocksTest(unittest.TestCase):
    def test_authenticated_loopback_and_blocked_destination(self):
        http = ThreadingHTTPServer(("127.0.0.1", 0), HttpHandler)
        socks = LocalSocksServer(("127.0.0.1", 0), LocalSocksHandler)
        socks.target_port = http.server_port
        for server in (http, socks):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with socket.create_connection(("127.0.0.1", socks.server_address[1])) as client:
                client.settimeout(3)
                client.sendall(b"\x05\x02\x00\x02")
                self.assertEqual(recv_exact(client, 2), b"\x05\x02")
                client.sendall(b"\x01\x01u\x01p")
                self.assertEqual(recv_exact(client, 2), b"\x01\x00")
                client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" +
                               http.server_port.to_bytes(2, "big"))
                self.assertEqual(recv_exact(client, 2), b"\x05\x00")
                recv_exact(client, 8)
                client.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                response = bytearray()
                while b"fixture-ok" not in response:
                    block = client.recv(4096)
                    if not block:
                        break
                    response.extend(block)
                self.assertIn(b"fixture-ok", response)
            with socket.create_connection(("127.0.0.1", socks.server_address[1])) as client:
                client.sendall(b"\x05\x01\x00")
                self.assertEqual(recv_exact(client, 2), b"\x05\x00")
                client.sendall(b"\x05\x01\x00\x01\x08\x08\x08\x08\x00\x50")
                self.assertEqual(recv_exact(client, 2), b"\x05\x02")
        finally:
            socks.shutdown()
            socks.server_close()
            http.shutdown()
            http.server_close()


if __name__ == "__main__":
    unittest.main()
