# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
import contextlib
import os
import socket
import struct
import threading

import pytest

from cuantario.model import Context, assess
from cuantario.probes import (
    HRR_RANDOM,
    Reply,
    ServerReply,
    build_client_hello,
    parse_server_response,
    parse_target,
    scan_ssh,
    scan_tls,
)

PQ = {0x11EC, 0x11EB, 0x11ED, 0x0201, 0x0202}


def _serve(handler):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    srv.settimeout(10)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn, contextlib.suppress(OSError):
                handler(conn)

    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1]


def _recv(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError
        buf += chunk
    return buf


def _client_groups(hello: bytes) -> list[int]:
    body = hello[4:]
    p = 2 + 32
    p += 1 + body[p]
    p += 2 + struct.unpack(">H", body[p:p + 2])[0]
    p += 1 + body[p]
    end = p + 2 + struct.unpack(">H", body[p:p + 2])[0]
    p += 2
    while p + 4 <= end:
        t, n = struct.unpack(">HH", body[p:p + 4])
        if t == 10:
            data = body[p + 6:p + 4 + n]
            return [struct.unpack(">H", data[i:i + 2])[0] for i in range(0, len(data), 2)]
        p += 4 + n
    return []


def _hrr(group: int) -> bytes:
    exts = struct.pack(">HHH", 43, 2, 0x0304) + struct.pack(">HHH", 51, 2, group)
    body = b"\x03\x03" + HRR_RANDOM + b"\x20" + os.urandom(32) + b"\x13\x01\x00" + struct.pack(">H", len(exts)) + exts
    hs = b"\x02" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs


ALERT = b"\x15\x03\x03\x00\x02\x02\x28"


def tls_server(supported: set[int], mode: str):
    """mode: 'pq' (el servidor prefiere PQC), 'cliente' (sigue al cliente), 'clasico' (prefiere clásico)."""
    def handler(conn):
        header = _recv(conn, 5)
        hello = _recv(conn, struct.unpack(">H", header[3:5])[0])
        offered = [g for g in _client_groups(hello) if g in supported]
        if not offered:
            conn.sendall(ALERT)
            return
        if mode == "pq":
            offered.sort(key=lambda g: g not in PQ)
        elif mode == "clasico":
            offered.sort(key=lambda g: g in PQ)
        conn.sendall(_hrr(offered[0]))
    return _serve(handler)


def _namelist(s: str) -> bytes:
    return struct.pack(">I", len(s)) + s.encode()


def ssh_server(kex: str, hostkeys: str, ciphers: str):
    def handler(conn):
        conn.sendall(b"SSH-2.0-OpenSSH_9.9\r\n")
        payload = (b"\x14" + os.urandom(16) + _namelist(kex) + _namelist(hostkeys) + _namelist(ciphers)
                   + _namelist(ciphers) + _namelist("hmac-sha2-256") * 2 + _namelist("none") * 2
                   + _namelist("") * 2 + b"\x00" + b"\x00\x00\x00\x00")
        pad = 8 - (len(payload) + 5) % 8 + 4
        conn.sendall(struct.pack(">IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad)
        conn.recv(100)
    return _serve(handler)


def by_rule(findings):
    return {f.rule_id: f for f in findings}


@pytest.mark.parametrize("text,expected", [
    ("ejemplo.es", ("ejemplo.es", 443)),
    ("ejemplo.es:8443", ("ejemplo.es", 8443)),
    ("[2001:db8::1]:444", ("2001:db8::1", 444)),
    ("[2001:db8::1]", ("2001:db8::1", 443)),
])
def test_parse_target(text, expected):
    assert parse_target(text, 443) == expected


def test_client_hello_offers_requested_groups_and_empty_key_share():
    hello = build_client_hello("ejemplo.es", [0x11EC, 0x001D])
    assert hello[:3] == b"\x16\x03\x01"
    assert _client_groups(hello[5:]) == [0x11EC, 0x001D]
    assert b"ejemplo.es" in hello
    assert struct.pack(">HHH", 51, 2, 0) in hello  # key_share vacío


def test_parse_hrr_and_alert():
    data = _hrr(0x11EC)
    pos = [0]

    def read(n):
        chunk = data[pos[0]:pos[0] + n]
        pos[0] += n
        return chunk
    assert parse_server_response(read) == ServerReply(Reply.HRR, 0x11EC)
    pos[0], data = 0, ALERT
    assert parse_server_response(read).kind is Reply.REJECTED


def test_tls_server_preferring_pq_is_ok():
    srv, port = tls_server({0x11EC, 0x001D}, "pq")
    with srv:
        f = by_rule(assess(scan_tls("127.0.0.1", port, timeout=3), Context()))
    assert f["hybrid-kem"].priority == "OK"
    assert f["ecdh"].priority == "MEDIO"  # X25519 queda como respaldo
    assert "prefiere el grupo post-cuántico" in f["ecdh"].evidence


def test_tls_server_following_client_is_ok():
    srv, port = tls_server({0x11EC, 0x001D}, "cliente")
    with srv:
        f = by_rule(assess(scan_tls("127.0.0.1", port, timeout=3), Context()))
    assert f["ecdh"].priority == "MEDIO"
    assert "preferencia del cliente" in f["ecdh"].evidence


def test_tls_server_forcing_classical_is_critical():
    srv, port = tls_server({0x11EC, 0x001D}, "clasico")
    with srv:
        f = by_rule(assess(scan_tls("127.0.0.1", port, timeout=3), Context()))
    assert f["ecdh"].priority == "CRITICO"  # soporta PQC, pero nunca la usa
    assert "elige el grupo clásico" in f["ecdh"].evidence


def test_tls_server_without_pq():
    srv, port = tls_server({0x001D, 0x0017}, "cliente")
    with srv:
        f = by_rule(assess(scan_tls("127.0.0.1", port, timeout=3), Context()))
    assert "hybrid-kem" not in f
    assert f["ecdh"].priority == "CRITICO"
    assert f["ecdh"].location == f"tls://127.0.0.1:{port}"


def test_ssh_server_with_hybrid_kex():
    srv, port = ssh_server("mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,ext-info-s",
                           "rsa-sha2-512,ssh-ed25519", "chacha20-poly1305@openssh.com,aes128-ctr")
    with srv:
        f = by_rule(assess(scan_ssh("127.0.0.1", port, timeout=3), Context()))
    assert f["hybrid-kem"].priority == "OK"
    assert f["hybrid-sntrup"].priority == "OK"
    assert f["ecdh"].priority == "MEDIO"
    assert f["rsa"].priority == "ALTO" and not f["rsa"].harvest_risk   # clave de host: solo firma
    assert f["eddsa"].priority == "ALTO"
    assert f["aes-128"].priority == "BAJO"
    assert f["chacha20"].priority == "OK"
    assert f["ecdh"].evidence.startswith("SSH-2.0-OpenSSH_9.9")


def test_ssh_server_classical_only():
    srv, port = ssh_server("curve25519-sha256,diffie-hellman-group14-sha256", "ssh-rsa", "aes256-ctr")
    with srv:
        f = by_rule(assess(scan_ssh("127.0.0.1", port, timeout=3), Context()))
    assert f["ecdh"].priority == "CRITICO" and f["dh"].priority == "CRITICO"


@pytest.mark.skipif(not __import__("shutil").which("openssl"), reason="openssl no disponible")
def test_real_openssl_server(tmp_path):
    import subprocess
    import time
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(tmp_path / "k.pem"),
                    "-out", str(tmp_path / "c.pem"), "-days", "30", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(["openssl", "s_server", "-accept", str(port), "-cert", str(tmp_path / "c.pem"),
                             "-key", str(tmp_path / "k.pem"), "-www", "-quiet"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        findings = assess(scan_tls("127.0.0.1", port, timeout=3), Context())
    finally:
        proc.kill()
    names = {f.name for f in findings}
    assert "Certificado RSA-2048" in names
    assert any(f.rule_id == "ecdh" and "grupos aceptados" in f.evidence for f in findings)
