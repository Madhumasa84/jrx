"""Small CONNECT-only egress proxy used inside a per-execution Docker sidecar."""

from __future__ import annotations

import argparse
import ipaddress
import select
import socket
import socketserver
import threading
from collections.abc import Sequence


def _canonical_host(value: str) -> str:
    return value.rstrip(".").encode("idna").decode("ascii").lower()


def _destination_allowed(address: str, networks: Sequence[ipaddress._BaseNetwork]) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return False
    if ip.is_global:
        return True
    if ip.is_private and not (ip.is_loopback or ip.is_link_local or ip.is_reserved):
        return any(ip in network for network in networks)
    return False


def _connect_allowed(
    host: str,
    port: int,
    allowed_networks: Sequence[ipaddress._BaseNetwork],
) -> socket.socket:
    records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    denied_destination = False
    last_error: OSError | None = None
    for family, socktype, protocol, _, address in records:
        if not isinstance(address[0], str) or not _destination_allowed(
            address[0], allowed_networks
        ):
            denied_destination = True
            continue
        upstream = socket.socket(family, socktype, protocol)
        upstream.settimeout(15)
        try:
            upstream.connect(address)
        except OSError as exc:
            upstream.close()
            last_error = exc
            continue
        return upstream
    if denied_destination and last_error is None:
        raise PermissionError("destination address is not allowed")
    if last_error is not None:
        raise last_error
    raise OSError("destination has no usable address")


class _Handler(socketserver.StreamRequestHandler):
    # Prevent the buffered file reader from consuming bytes sent optimistically with
    # the CONNECT request before the tunnel relay begins.
    rbufsize = 0

    def handle(self) -> None:
        self.connection.settimeout(10)
        request_line = self.rfile.readline(8193)
        if not request_line or len(request_line) > 8192 or not request_line.endswith(b"\r\n"):
            self._respond(400, "Bad Request")
            return
        try:
            method, authority, version = request_line.decode("ascii").strip().split(" ", 2)
        except (UnicodeDecodeError, ValueError):
            self._respond(400, "Bad Request")
            return
        header_bytes = len(request_line)
        while True:
            line = self.rfile.readline(8193)
            header_bytes += len(line)
            if not line or header_bytes > 16_384 or not line.endswith(b"\r\n"):
                self._respond(431, "Request Header Fields Too Large")
                return
            if line == b"\r\n":
                break
        if method != "CONNECT" or version not in {"HTTP/1.0", "HTTP/1.1"}:
            self._respond(405, "Method Not Allowed")
            return
        try:
            host, separator, port_text = authority.rpartition(":")
            if not separator or not host or not port_text.isdecimal():
                raise ValueError
            host = _canonical_host(host.strip("[]"))
            port = int(port_text)
        except (UnicodeError, ValueError):
            self._respond(400, "Bad Request")
            return
        server: _ProxyServer = self.server  # type: ignore[assignment]
        if host not in server.allowed_hosts or port not in server.allowed_ports:
            self._respond(403, "Forbidden")
            return
        try:
            upstream = _connect_allowed(host, port, server.allowed_networks)
        except PermissionError:
            self._respond(403, "Forbidden")
            return
        except OSError:
            self._respond(502, "Bad Gateway")
            return
        self._respond(200, "Connection Established")
        try:
            self._relay(upstream)
        finally:
            upstream.close()

    def _respond(self, code: int, message: str) -> None:
        payload = f"HTTP/1.1 {code} {message}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        try:
            self.wfile.write(payload.encode("ascii"))
            self.wfile.flush()
        except OSError:
            pass

    def _relay(self, upstream: socket.socket) -> None:
        self.connection.settimeout(15)
        peers = (self.connection, upstream)
        while True:
            try:
                readable, _, _ = select.select(peers, [], [], 180)
            except (OSError, ValueError):
                return
            if not readable:
                return
            for source in readable:
                target = upstream if source is self.connection else self.connection
                try:
                    data = source.recv(65_536)
                    if not data:
                        return
                    target.sendall(data)
                except OSError:
                    return


class _ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64
    max_workers = 32

    def __init__(
        self,
        address: tuple[str, int],
        allowed_hosts: set[str],
        allowed_ports: set[int],
        allowed_networks: Sequence[ipaddress._BaseNetwork],
    ) -> None:
        self.allowed_hosts = allowed_hosts
        self.allowed_ports = allowed_ports
        self.allowed_networks = allowed_networks
        self._workers = threading.BoundedSemaphore(self.max_workers)
        super().__init__(address, _Handler)

    def process_request(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: tuple[str, int]
    ) -> None:
        if not isinstance(request, socket.socket):
            raise TypeError("TCP proxy requires a socket request")
        if not self._workers.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._workers.release()
            raise

    def process_request_thread(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: tuple[str, int],
    ) -> None:
        if not isinstance(request, socket.socket):
            raise TypeError("TCP proxy requires a socket request")
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._workers.release()

    def handle_error(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: tuple[str, int]
    ) -> None:
        del request, client_address


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=3128)
    parser.add_argument("--allow-host", action="append", required=True)
    parser.add_argument("--allow-port", action="append", type=int)
    parser.add_argument("--allow-network", action="append", default=[])
    args = parser.parse_args()
    allowed_hosts = {_canonical_host(host) for host in args.allow_host}
    allowed_networks = [ipaddress.ip_network(value, strict=True) for value in args.allow_network]
    with _ProxyServer(
        (args.listen, args.port), allowed_hosts, set(args.allow_port or [443]), allowed_networks
    ) as server:
        server.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    main()
