# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
import contextlib
import dataclasses
import os
import socket
import struct
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from test_probes import _client_groups, _hrr, _recv, _serve

from cuantario import cli
from cuantario.model import Context, Finding, assess
from cuantario.probes import (
    ProtocolError,
    ServerReply,
    parse_server_response,
    parse_target,
    scan_ssh,
    scan_tls,
)
from cuantario.python_ast import scan_python
from cuantario.rules import Confidence, Primitive, Priority, Source, Status
from cuantario.scanner import scan_text


def reader(data: bytes):
    pos = 0

    def read(n: int) -> bytes:
        nonlocal pos
        chunk = data[pos:pos + n]
        pos += n
        return chunk
    return read


def by_rule(findings):
    return {f.rule_id: f for f in findings}


# Tipos

def test_finding_rejects_positional_arguments():
    with pytest.raises(TypeError):
        Finding("rsa", "RSA", Status.VULNERABLE, Primitive.PKE, Source.CODE, "a.py")  # type: ignore[misc]


def test_finding_is_immutable():
    f = Finding(rule_id="rsa", name="RSA", status=Status.VULNERABLE, primitive=Primitive.PKE,
                source=Source.CODE, location="a.py")
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.priority = Priority.OK  # type: ignore[misc]


def test_enums_format_as_their_value():
    assert f"{Priority.CRITICAL}" == "CRITICO" and str(Confidence.HIGH) == "alta"


def test_priority_does_not_depend_on_call_order():
    raw = scan_text("grupos aceptados: X25519MLKEM768, X25519", "t", Source.TLS, Confidence.HIGH)
    assert assess(raw, Context()) == assess(reversed(raw), Context())
    assert all(f.priority is None for f in raw)  # evaluar no toca los originales


# Entrada de la CLI

@pytest.mark.parametrize("text", ["ejemplo.es:abc", "ejemplo.es:0", "ejemplo.es:70000", ":443", "[::1",
                                  "[::1]x", "con espacio.es"])
def test_parse_target_rejects_garbage(text):
    with pytest.raises(ValueError):
        parse_target(text, 443)


@pytest.mark.parametrize("args", [["--tls", "ejemplo.es:abc"], ["--ssh", "[::1"], ["--timeout", "0"],
                                  ["--ano-crqc", "35"], ["--vida-datos", "-1"]])
def test_cli_reports_bad_input_without_traceback(args, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    assert exc.value.code == 2
    assert "Traceback" not in capsys.readouterr().err


def test_demo_code_lives_outside_the_cli():
    assert not hasattr(cli, "DEMO_FILES")


# Parsers binarios

@settings(max_examples=500, deadline=None)
@given(st.binary(max_size=300))
def test_tls_parser_never_crashes_on_random_bytes(data):
    with contextlib.suppress(ProtocolError):
        assert isinstance(parse_server_response(reader(data)), ServerReply)


@settings(max_examples=300, deadline=None)
@given(st.integers(min_value=0, max_value=len(_hrr(0x11EC)) - 1))
def test_tls_parser_handles_every_truncation(cut):
    with contextlib.suppress(ProtocolError):
        parse_server_response(reader(_hrr(0x11EC)[:cut]))


def _ssh_server(raw: bytes):
    def handler(conn):
        conn.sendall(b"SSH-2.0-Raro\r\n" + raw)
        conn.recv(100)
    return _serve(handler)


@pytest.mark.parametrize("raw", [
    b"",                                                  # corta tras el banner
    struct.pack(">IB", 20, 4) + b"\x14" + b"x" * 5,       # paquete más corto de lo anunciado
    struct.pack(">IB", 10**6, 4),                         # longitud absurda
    struct.pack(">IB", 20, 200) + b"\x14" + b"x" * 18,    # relleno mayor que el paquete
    struct.pack(">IB", 24, 4) + b"\x14" + os.urandom(16) + struct.pack(">I", 999) + b"ab",  # name-list truncada
])
def test_ssh_parser_raises_protocol_error(raw):
    srv, port = _ssh_server(raw)
    with srv, pytest.raises((ProtocolError, ConnectionError)):
        scan_ssh("127.0.0.1", port, timeout=2)


# Una sonda que no responde no tumba el host

def test_one_hanging_probe_does_not_discard_the_rest():
    def handler(conn):
        header = _recv(conn, 5)
        offered = _client_groups(_recv(conn, struct.unpack(">H", header[3:5])[0]))
        if offered == [0x0017]:        # la sonda de P-256 se queda colgada
            time.sleep(1.5)
            return
        for group in offered:
            if group in (0x11EC, 0x001D, 0x0017):
                conn.sendall(_hrr(group))
                return
        conn.sendall(b"\x15\x03\x03\x00\x02\x02\x28")

    srv, port = _serve(handler)
    with srv:
        findings = by_rule(scan_tls("127.0.0.1", port, timeout=0.5))
    assert "hybrid-kem" in findings and "ecdh" in findings
    assert "sin respuesta al sondear ECDHE-P256" in findings["ecdh"].evidence
    assert findings["ecdh"].confidence is Confidence.MEDIUM


def test_dead_server_is_reported_as_unreachable():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with pytest.raises(ConnectionError):
        scan_tls("127.0.0.1", port, timeout=0.5)


# Detección

@pytest.mark.parametrize("src", [
    "import hashlib as h\nh.md5(b'x')\n",
    "from hashlib import md5\nmd5(b'x')\n",
    "from hashlib import md5 as digest\ndigest(b'x')\n",
])
def test_ast_follows_import_aliases_for_hashes(src):
    assert [f.rule_id for f in scan_python(src, "a.py")] == ["md5"]


def test_ast_follows_from_imports():
    src = ("from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key\n"
           "k = generate_private_key(public_exponent=65537, key_size=2048)\n")
    [f] = scan_python(src, "a.py")
    assert f.rule_id == "rsa" and f.line == 2


def test_ast_ignores_unrelated_functions_with_crypto_names():
    assert scan_python("def md5(x):\n    return x\nmd5(1)\n", "a.py") == []


def test_md5_priority_depends_on_declared_use():
    src = "import hashlib\nhashlib.md5(b'x', usedforsecurity=False)\nhashlib.md5(b'y')\n"
    first, second = assess(scan_python(src, "a.py"), Context())
    assert {first.priority, second.priority} == {Priority.LOW, Priority.MEDIUM}


def test_md5_in_config_is_still_critical():
    [f] = assess(scan_text("password_encryption = md5", "pg.conf", Source.CONFIG, Confidence.MEDIUM), Context())
    assert f.priority is Priority.CRITICAL


@pytest.mark.parametrize("line", ["MACs hmac-sha1,hmac-sha2-256", "Mac.getInstance(\"HmacSHA1\")",
                                  "MACs hmac-md5-etm@openssh.com"])
def test_hmac_with_legacy_hash_is_low_not_critical(line):
    findings = by_rule(assess(scan_text(line, "f", Source.CONFIG, Confidence.MEDIUM), Context()))
    assert "sha1" not in findings and "md5" not in findings
    assert findings["hmac-legacy"].priority is Priority.LOW


def test_cbc_mode_is_reported():
    findings = by_rule(assess(scan_text("cipher AES-256-CBC", "f", Source.CONFIG, Confidence.MEDIUM), Context()))
    assert findings["aes-256"].priority is Priority.OK
    assert findings["aes-cbc"].priority is Priority.LOW and "no autentica" in findings["aes-cbc"].reason


def test_excluded_ciphers_are_not_findings():
    assert scan_text("ssl_ciphers HIGH:!aNULL:!MD5:!RC4:!3DES;", "f", Source.CONFIG, Confidence.MEDIUM) == []
