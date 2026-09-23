# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cuantario.model import Context, assess
from cuantario.rules import Confidence, Priority, Status
from cuantario.scanner import MAX_BYTES, scan


def write_cert(path, bits: int, years: int) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    start = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(start)
            .not_valid_after(start + dt.timedelta(days=365 * years)).sign(key, hashes.SHA256()))
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def test_invalid_python_falls_back_to_text(tmp_path):
    (tmp_path / "broken.py").write_text("def x(:\n  RSA\n")
    [d] = scan(tmp_path).detections
    assert d.rule.id == "rsa" and d.confidence is Confidence.LOW


def test_weak_certificate_is_critical(tmp_path):
    write_cert(tmp_path / "weak.pem", 1024, 1)
    [a] = assess(scan(tmp_path).detections, Context(high_risk=False))
    assert a.priority is Priority.CRITICAL and a.detection.status is Status.BROKEN


def test_long_lived_certificate_depends_on_risk(tmp_path):
    write_cert(tmp_path / "c.pem", 2048, 8)
    detections = scan(tmp_path).detections
    assert assess(detections, Context(high_risk=True))[0].priority is Priority.CRITICAL
    assert assess(detections, Context(high_risk=False))[0].priority is Priority.MEDIUM


def test_private_key_is_reported_and_redacted(tmp_path):
    (tmp_path / "k.pem").write_text("-----BEGIN PRIVATE KEY-----\nSECRETO123\n-----END PRIVATE KEY-----\n")
    [d] = scan(tmp_path).detections
    assert d.status is Status.EXPOSED_SECRET and d.evidence.snippet == "[REDACTADO]"


def test_utf16_with_bom_is_read(tmp_path):
    (tmp_path / "app.conf").write_bytes("cipher RC4\n".encode("utf-16"))
    result = scan(tmp_path)
    assert [d.rule.id for d in result.detections] == ["rc4"] and result.skipped == []


def test_undecodable_and_large_files_are_reported(tmp_path):
    (tmp_path / "latin1.conf").write_bytes("contraseña RSA\n".encode("latin-1"))
    (tmp_path / "big.js").write_bytes(b"// RSA\n" * (MAX_BYTES // 7 + 1))
    (tmp_path / "ok.conf").write_text("cipher RC4\n")
    result = scan(tmp_path)
    assert [d.rule.id for d in result.detections] == ["rc4"]
    assert {s.path for s in result.skipped} == {"latin1.conf", "big.js"}
    assert any("codificación" in s.reason for s in result.skipped)


def test_unrelated_binary_files_are_ignored_silently(tmp_path):
    (tmp_path / "foto.png").write_bytes(b"\x89PNG\x00\xff")
    assert scan(tmp_path).skipped == []
