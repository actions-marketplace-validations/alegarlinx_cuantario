# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

from .model import CertInfo, Finding
from .rules import PQC_SIG, Confidence, Primitive, Source, Status


def load_certs(data: bytes) -> list[x509.Certificate]:
    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            return x509.load_pem_x509_certificates(data)
        return [x509.load_der_x509_certificate(data)]
    except ValueError:
        return []


def key_info(pk: CertificatePublicKeyTypes) -> tuple[str, int]:
    if isinstance(pk, rsa.RSAPublicKey):
        return "RSA", pk.key_size
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return f"ECDSA-{pk.curve.name}", pk.curve.key_size
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pk, ed448.Ed448PublicKey):
        return "Ed448", 456
    if isinstance(pk, dsa.DSAPublicKey):
        return "DSA", pk.key_size
    return type(pk).__name__, 0


def analyze_certificate(cert: x509.Certificate, location: str) -> Finding:
    alg, size = key_info(cert.public_key())
    try:
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "n/a"
    except UnsupportedAlgorithm:
        sig_hash = "desconocido"
    info = CertInfo(algorithm=alg, key_size=size, signature_hash=sig_hash,
                    subject=cert.subject.rfc4514_string(), issuer=cert.issuer.rfc4514_string(),
                    not_before=cert.not_valid_before_utc, not_after=cert.not_valid_after_utc)
    weak = sig_hash in ("md5", "sha1") or (alg == "RSA" and size < 2048) or alg == "DSA"
    return Finding(
        rule_id=f"cert-{cert.serial_number:x}"[:40],
        name=f"Certificado {alg}-{size}",
        status=Status.BROKEN if weak else Status.VULNERABLE,
        primitive=Primitive.SIGNATURE,
        source=Source.CERTIFICATE,
        location=location,
        evidence=f"{alg} {size} bits · hash {sig_hash} · caduca {info.not_after:%d/%m/%Y} · {info.subject[:80]}",
        replacement=PQC_SIG,
        confidence=Confidence.HIGH,
        key_size=size,
        cert=info,
    )


def scan_cert(path: Path, rel: str) -> list[Finding]:
    return [analyze_certificate(c, rel) for c in load_certs(path.read_bytes())]
