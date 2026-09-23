# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
import contextlib
import socket
import ssl
import struct
import time

import pytest
from conftest import ALERT, hrr, parse_client_hello, read_client_hello, send_rst
from hypothesis import given, settings
from hypothesis import strategies as st

from cuantario.model import Assessment, Context, assess
from cuantario.net import NetworkError, ProtocolError, RateLimiter, parse_target
from cuantario.rules import Confidence, Priority, ServerPreference
from cuantario.tls import (
    Reply,
    ServerReply,
    TlsVersion,
    build_client_hello,
    build_legacy_hello,
    parse_server_response,
    probe,
    scan_tls,
)


def reader(data: bytes):
    pos = 0

    def read(n: int) -> bytes:
        nonlocal pos
        chunk = data[pos:pos + n]
        pos += n
        return chunk
    return read


def by_rule(items):
    result = {}
    for item in items:
        detection = item.detection if isinstance(item, Assessment) else item
        result.setdefault(detection.rule.id, []).append(item)
    return result


@pytest.mark.parametrize("text,expected", [
    ("ejemplo.es", ("ejemplo.es", 443)), ("ejemplo.es:8443", ("ejemplo.es", 8443)),
    ("[2001:db8::1]:444", ("2001:db8::1", 444)), ("[2001:db8::1]", ("2001:db8::1", 443)),
])
def test_parse_target(text, expected):
    assert parse_target(text, 443) == expected


@pytest.mark.parametrize("text", ["ejemplo.es:abc", "ejemplo.es:0", "ejemplo.es:70000", ":443", "[::1", "a b"])
def test_parse_target_rejects_garbage(text):
    with pytest.raises(ValueError):
        parse_target(text, 443)


def test_client_hello_offers_requested_groups():
    hello = build_client_hello("ejemplo.es", [0x11EC, 0x001D])
    parsed = parse_client_hello(hello[5:])
    assert parsed.groups == [0x11EC, 0x001D] and parsed.tls13 and b"ejemplo.es" in hello


def test_legacy_hello_does_not_offer_tls13():
    hello = build_legacy_hello("ejemplo.es", TlsVersion.TLS10)
    assert not parse_client_hello(hello[5:]).tls13 and hello[9:11] == b"\x03\x01"


def test_parse_hrr_and_alert():
    assert parse_server_response(reader(hrr(0x11EC))) == ServerReply(Reply.HELLO_RETRY, TlsVersion.TLS13,
                                                                        0x11EC, 0x1302)
    assert parse_server_response(reader(ALERT)).kind is Reply.REJECTED


@settings(max_examples=500, deadline=None)
@given(st.binary(max_size=300))
def test_parser_never_crashes_on_random_bytes(data):
    with contextlib.suppress(ProtocolError):
        assert isinstance(parse_server_response(reader(data)), ServerReply)


@settings(max_examples=200, deadline=None)
@given(st.integers(min_value=0, max_value=len(hrr(0x11EC)) - 1))
def test_parser_handles_every_truncation(cut):
    with contextlib.suppress(ProtocolError):
        parse_server_response(reader(hrr(0x11EC)[:cut]))


def test_rate_limiter_spaces_calls():
    limiter = RateLimiter(0.05)
    start = time.monotonic()
    for _ in range(5):
        limiter.wait()
    assert time.monotonic() - start >= 0.19


@pytest.mark.parametrize("mode,preference,ecdh_priority", [
    ("pq", ServerPreference.PREFERS_PQ, Priority.MEDIUM),
    ("cliente", ServerPreference.FOLLOWS_CLIENT, Priority.MEDIUM),
    ("clasico", ServerPreference.PREFERS_CLASSICAL, Priority.CRITICAL),
])
def test_server_preference(tls_server, fast, mode, preference, ecdh_priority):
    port = tls_server({0x11EC, 0x001D}, mode)
    found = by_rule(assess(scan_tls("127.0.0.1", port, fast), Context()))
    assert found["hybrid-kem"][0].priority is Priority.OK
    assert found["ecdh"][0].priority is ecdh_priority
    assert found["ecdh"][0].detection.evidence.server_preference is preference


def test_server_without_pq(tls_server, fast):
    port = tls_server({0x001D, 0x0017})
    found = by_rule(assess(scan_tls("127.0.0.1", port, fast), Context()))
    assert "hybrid-kem" not in found
    assert {a.detection.evidence.snippet for a in found["ecdh"]} == {"ECDHE-P256", "X25519"}
    assert {a.priority for a in found["ecdh"]} == {Priority.CRITICAL}


def test_suite_from_hello_retry_is_reported(tls_server, fast):
    found = by_rule(scan_tls("127.0.0.1", tls_server({0x001D}), fast))
    assert found["aes-256"][0].evidence.snippet == "TLS 1.3 · TLS_AES_256_GCM_SHA384"


def test_reset_is_retried_not_treated_as_rejection(serve, fast):
    attempts = {"n": 0}

    def handler(conn: socket.socket) -> None:
        read_client_hello(conn)
        attempts["n"] += 1
        if attempts["n"] == 1:
            send_rst(conn)
        else:
            conn.sendall(hrr(0x11EC))

    reply = probe("127.0.0.1", serve(handler), build_client_hello("x", [0x11EC]), fast, RateLimiter(0))
    assert reply.kind is Reply.HELLO_RETRY and attempts["n"] == 2


def test_persistent_reset_is_a_network_error(serve, fast):
    def handler(conn: socket.socket) -> None:
        read_client_hello(conn)
        send_rst(conn)

    port = serve(handler)
    reply = probe("127.0.0.1", port, build_client_hello("x", [0x11EC]), fast, RateLimiter(0))
    assert reply.kind is Reply.NETWORK_ERROR and "reseteada" in reply.detail
    with pytest.raises(NetworkError):
        scan_tls("127.0.0.1", port, fast)


def test_clean_close_counts_as_rejection(serve, fast):
    port = serve(lambda conn: read_client_hello(conn))
    assert probe("127.0.0.1", port, build_client_hello("x", [1]), fast, RateLimiter(0)).kind is Reply.REJECTED


def test_one_hanging_probe_does_not_discard_the_rest(serve, fast):
    def handler(conn: socket.socket) -> None:
        hello = read_client_hello(conn)
        if not hello.tls13:
            conn.sendall(ALERT)
        elif hello.groups == [0x0017]:
            time.sleep(1.5)
        elif set(hello.groups) & {0x11EC, 0x001D}:
            conn.sendall(hrr(0x11EC if 0x11EC in hello.groups else 0x001D))
        else:
            conn.sendall(ALERT)

    found = by_rule(scan_tls("127.0.0.1", serve(handler), fast))
    ecdh = found["ecdh"][0]
    assert "hybrid-kem" in found
    assert any("ECDHE-P256" in n for n in ecdh.evidence.notes) and ecdh.confidence is Confidence.MEDIUM


def test_closed_port_is_unreachable(fast):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with pytest.raises(NetworkError):
        scan_tls("127.0.0.1", port, fast)


def test_real_tls10_only_server(openssl_server, fast):
    port = openssl_server("-tls1", "-cipher", "ALL:@SECLEVEL=0")
    found = by_rule(assess(scan_tls("127.0.0.1", port, fast), Context()))
    assert found["tls-legacy"][0].detection.evidence.snippet == "TLS 1.0 aceptado"
    assert found["tls-legacy"][0].priority is Priority.CRITICAL
    assert len(found["certificate"]) == 2


def test_real_tls13_server_with_chain(openssl_server, fast):
    port = openssl_server()
    found = by_rule(scan_tls("127.0.0.1", port, fast))
    assert "tls-legacy" not in found
    assert {d.evidence.snippet for d in found["ecdh"]} >= {"X25519", "ECDHE-P256"}
    leaf, intermediate = sorted(found["certificate"], key=lambda d: d.cert.position)
    assert intermediate.cert.subject == "CN=ca"
    assert not any("Cadena rota" in n for n in leaf.evidence.notes)
    assert any("almacén del sistema" in n for n in leaf.evidence.notes)


def test_real_server_with_broken_chain(openssl_server, fast):
    port = openssl_server("-tls1_2", chain="otra_ca.pem")
    leaf = next(d for d in scan_tls("127.0.0.1", port, fast) if d.cert and d.cert.position == 0)
    assert any("Cadena rota" in n for n in leaf.evidence.notes)


def test_real_tls12_only_server_notes_missing_tls13(openssl_server, fast):
    found = by_rule(scan_tls("127.0.0.1", openssl_server("-tls1_2"), fast))
    assert any("sin TLS 1.3" in n for n in found["ecdh"][0].evidence.notes)


def test_legacy_record_with_several_messages_is_parsed():
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack(">HB", 0xC02F, 0)
    server_hello = b"\x02" + struct.pack(">I", len(body))[1:] + body
    done = b"\x0e\x00\x00\x00"
    record = b"\x16\x03\x03" + struct.pack(">H", len(server_hello + done)) + server_hello + done
    assert parse_server_response(reader(record)) == ServerReply(Reply.SERVER_HELLO, TlsVersion.TLS12, None, 0xC02F)


def test_real_tls13_only_server_chain_depends_on_python(openssl_server, fast):
    port = openssl_server("-tls1_3")
    certs = [d for d in scan_tls("127.0.0.1", port, fast) if d.cert]
    if hasattr(ssl.SSLSocket, "get_unverified_chain"):
        assert len(certs) == 2
    else:
        assert len(certs) == 1 and any("solo se ha podido obtener" in n for n in certs[0].evidence.notes)
