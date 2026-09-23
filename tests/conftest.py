# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import contextlib
import os
import shutil
import socket
import struct
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from cuantario.net import ProbeConfig
from cuantario.tls import HRR_RANDOM

Handler = Callable[[socket.socket], None]
ALERT = b"\x15\x03\x03\x00\x02\x02\x28"
PQ = {0x11EC, 0x11EB, 0x11ED, 0x0201, 0x0202}


def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError
        buf += chunk
    return buf


@dataclass
class ClientHello:
    groups: list[int] = field(default_factory=list)
    tls13: bool = False


def parse_client_hello(record_body: bytes) -> ClientHello:
    body = record_body[4:]
    offset = 2 + 32
    offset += 1 + body[offset]
    offset += 2 + struct.unpack(">H", body[offset:offset + 2])[0]
    offset += 1 + body[offset]
    end = offset + 2 + struct.unpack(">H", body[offset:offset + 2])[0]
    offset += 2
    hello = ClientHello()
    while offset + 4 <= end:
        ext_type, size = struct.unpack(">HH", body[offset:offset + 4])
        data = body[offset + 4:offset + 4 + size]
        if ext_type == 10:
            hello.groups = [struct.unpack(">H", data[i:i + 2])[0] for i in range(2, len(data), 2)]
        elif ext_type == 43:
            hello.tls13 = b"\x03\x04" in data
        offset += 4 + size
    return hello


def read_client_hello(conn: socket.socket) -> ClientHello:
    header = recv_exact(conn, 5)
    return parse_client_hello(recv_exact(conn, struct.unpack(">H", header[3:5])[0]))


def hrr(group: int, suite: int = 0x1302) -> bytes:
    exts = struct.pack(">HHH", 43, 2, 0x0304) + struct.pack(">HHH", 51, 2, group)
    body = (b"\x03\x03" + HRR_RANDOM + b"\x20" + os.urandom(32) + struct.pack(">HB", suite, 0)
            + struct.pack(">H", len(exts)) + exts)
    handshake = b"\x02" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake


def send_rst(conn: socket.socket) -> None:
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    conn.close()


@pytest.fixture
def serve() -> Iterator[Callable[[Handler], int]]:
    servers: list[socket.socket] = []

    def start(handler: Handler) -> int:
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(32)
        servers.append(srv)

        def worker(conn: socket.socket) -> None:
            with conn, contextlib.suppress(OSError):
                handler(conn)

        def loop() -> None:
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                threading.Thread(target=worker, args=(conn,), daemon=True).start()

        threading.Thread(target=loop, daemon=True).start()
        return int(srv.getsockname()[1])

    yield start
    for srv in servers:
        srv.close()


@pytest.fixture
def tls_server(serve: Callable[[Handler], int]) -> Callable[..., int]:
    def start(supported: set[int], mode: str = "cliente") -> int:
        def handler(conn: socket.socket) -> None:
            hello = read_client_hello(conn)
            offered = [g for g in hello.groups if g in supported] if hello.tls13 else []
            if not offered:
                conn.sendall(ALERT)
                return
            if mode == "pq":
                offered.sort(key=lambda g: g not in PQ)
            elif mode == "clasico":
                offered.sort(key=lambda g: g in PQ)
            conn.sendall(hrr(offered[0]))
        return serve(handler)
    return start


def namelist(value: str) -> bytes:
    return struct.pack(">I", len(value)) + value.encode()


def kexinit_packet(kex: str, host_keys: str, ciphers: str, macs: str = "hmac-sha2-256") -> bytes:
    payload = (b"\x14" + os.urandom(16) + namelist(kex) + namelist(host_keys) + namelist(ciphers) * 2
               + namelist(macs) * 2 + namelist("none") * 2 + namelist("") * 2 + b"\x00" + b"\x00" * 4)
    pad = 8 - (len(payload) + 5) % 8 + 4
    return struct.pack(">IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad


@pytest.fixture
def ssh_server(serve: Callable[[Handler], int]) -> Callable[[bytes], int]:
    def start(raw: bytes) -> int:
        def handler(conn: socket.socket) -> None:
            conn.sendall(b"SSH-2.0-OpenSSH_9.9\r\n" + raw)
            conn.recv(100)
        return serve(handler)
    return start


@pytest.fixture
def fast() -> ProbeConfig:
    return ProbeConfig(timeout=0.5, retries=2, backoff=0.01, workers=3, min_interval=0.0)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_for_port(port: int, attempts: int = 50) -> None:
    for _ in range(attempts):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.1)


@pytest.fixture
def pki(tmp_path: Path) -> Path:
    if not shutil.which("openssl"):
        pytest.skip("openssl no disponible")

    def run(*args: str) -> None:
        subprocess.run(["openssl", *args], check=True, capture_output=True, cwd=tmp_path)

    for name in ("ca", "otra_ca"):
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.pem",
            "-days", "30", "-subj", f"/CN={name}")
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=localhost")
    run("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", "leaf.pem", "-days", "30")
    return tmp_path


@pytest.fixture
def openssl_server(pki: Path) -> Iterator[Callable[..., int]]:
    processes: list[subprocess.Popen[bytes]] = []

    def start(*extra: str, chain: str = "ca.pem") -> int:
        port = free_port()
        processes.append(subprocess.Popen(
            ["openssl", "s_server", "-accept", str(port), "-cert", "leaf.pem", "-key", "leaf.key",
             "-cert_chain", chain, "-www", "-quiet", *extra],
            cwd=pki, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        wait_for_port(port)
        return port

    yield start
    for p in processes:
        p.kill()
