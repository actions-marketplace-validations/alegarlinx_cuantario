# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from .model import Context, Finding, now, prioritize
from .rules import BROKEN, PQC_SIG, VULN


def load_certs(data: bytes) -> list[x509.Certificate]:
    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            return x509.load_pem_x509_certificates(data)
        return [x509.load_der_x509_certificate(data)]
    except ValueError:
        return []


def key_info(pk) -> tuple[str, int]:
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


def analyze_certificate(cert: x509.Certificate, location: str, ctx: Context) -> Finding:
    alg, size = key_info(cert.public_key())
    try:
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "n/a"
    except UnsupportedAlgorithm:
        sig_hash = "desconocido"
    not_after = cert.not_valid_after_utc
    subject = cert.subject.rfc4514_string()

    f = Finding(f"cert-{cert.serial_number:x}"[:40], f"Certificado {alg}-{size}", VULN, "signature", location, 0,
                f"{alg} {size} bits · hash {sig_hash} · caduca {not_after:%d/%m/%Y} · {subject[:80]}",
                PQC_SIG, "certificado", confidence="alta",
                extra={"subject": subject, "issuer": cert.issuer.rfc4514_string(),
                       "not_before": cert.not_valid_before_utc.isoformat(), "not_after": not_after.isoformat()})
    prioritize(f, ctx)

    notes = []
    if sig_hash in ("md5", "sha1") or (alg == "RSA" and size < 2048) or alg == "DSA":
        f.priority, f.status = "CRITICO", BROKEN
        notes.append("Parámetros inseguros ya hoy.")
    elif not_after.year > 2030 and ctx.high_risk:
        f.priority = "CRITICO"
        notes.append("Caduca después de 2030 con firma vulnerable: incumple el hito UE de alto riesgo.")
    if not_after < now():
        notes.append("Certificado ya caducado.")
    # CCN-STIC 807, anexo 1. Comprobar en cada versión de la guía si la fecha sigue vigente.
    if ctx.profile == "ccn" and alg == "RSA" and 1900 <= size < 3000:
        notes.append("CCN: RSA de 1900–3000 bits solo autorizado a prestadores de confianza hasta 31/12/2026.")
    if notes:
        f.reason = " ".join(notes + [f.reason])
    return f


def scan_cert(path: Path, rel: str, ctx: Context) -> list[Finding]:
    return [analyze_certificate(c, rel, ctx) for c in load_certs(path.read_bytes())]
