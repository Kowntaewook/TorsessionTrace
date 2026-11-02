"""SOCKS5 relay restricted to a single loopback HTTP port for controlled tests."""

import select
import socket
import socketserver


def recv_exact(connection, count):
    data = bytearray()
    while len(data) < count:
        block = connection.recv(count - len(data))
        if not block:
            raise ConnectionError("SOCKS connection closed")
        data.extend(block)
    return bytes(data)


class LocalSocksHandler(socketserver.BaseRequestHandler):
    """Forward only this experiment's loopback HTTP endpoint, never the Internet."""

    def handle(self):
        client = self.request
        client.settimeout(10)
        try:
            version, count = recv_exact(client, 2)
            methods = recv_exact(client, count)
            if version != 5:
                return
            method = 2 if 2 in methods else (0 if 0 in methods else 255)
            client.sendall(bytes((5, method)))
            if method == 255:
                return
            if method == 2:
                auth_version, username_length = recv_exact(client, 2)
                recv_exact(client, username_length)
                password_length = recv_exact(client, 1)[0]
                recv_exact(client, password_length)
                if auth_version != 1:
                    return
                client.sendall(b"\x01\x00")
            version, command, _reserved, address_type = recv_exact(client, 4)
            if address_type == 1:
                host = socket.inet_ntop(socket.AF_INET, recv_exact(client, 4))
            elif address_type == 3:
                host = recv_exact(client, recv_exact(client, 1)[0]).decode("ascii")
            elif address_type == 4:
                host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
            else:
                return
            port = int.from_bytes(recv_exact(client, 2), "big")
            if (version, command) != (5, 1) or host not in ("127.0.0.1", "localhost", "::1") or port != self.server.target_port:
                client.sendall(b"\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x00")
                return
            with socket.create_connection(("127.0.0.1", port), timeout=10) as upstream:
                client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                client.settimeout(None)
                upstream.settimeout(None)
                while True:
                    readable, _, _ = select.select((client, upstream), (), (), 10)
                    if not readable:
                        break
                    for source in readable:
                        block = source.recv(65536)
                        if not block:
                            return
                        (upstream if source is client else client).sendall(block)
        except (ConnectionError, OSError, ValueError):
            return


class LocalSocksServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


