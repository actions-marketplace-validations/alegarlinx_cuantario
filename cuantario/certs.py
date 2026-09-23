# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

from .model import CertInfo, Detection, Evidence, Location, detect
from .rules import Confidence, Source, Status


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


def cert_info(cert: x509.Certificate, position: int = 0) -> CertInfo:
    alg, size = key_info(cert.public_key())
    try:
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "n/a"
    except UnsupportedAlgorithm:
        sig_hash = "desconocido"
    return CertInfo(algorithm=alg, key_size=size, signature_hash=sig_hash,
                    subject=cert.subject.rfc4514_string(), issuer=cert.issuer.rfc4514_string(),
                    not_before=cert.not_valid_before_utc, not_after=cert.not_valid_after_utc, position=position)


def _is_weak(info: CertInfo) -> bool:
    return info.signature_hash in ("md5", "sha1") or (info.algorithm == "RSA" and info.key_size < 2048) \
        or info.algorithm == "DSA"


def link_problem(cert: x509.Certificate, issuer: x509.Certificate) -> str | None:
    try:
        cert.verify_directly_issued_by(issuer)
    except ValueError:
        return "el emisor no coincide con el siguiente certificado de la cadena"
    except InvalidSignature:
        return "la firma no la valida el siguiente certificado de la cadena"
    except (TypeError, UnsupportedAlgorithm):
        return "no se pudo comprobar la firma con el siguiente certificado"
    return None


def certificate_detection(cert: x509.Certificate, location: Location, position: int = 0,
                          notes: tuple[str, ...] = ()) -> Detection:
    info = cert_info(cert, position)
    return detect(
        "certificate", location=location, source=Source.CERTIFICATE, confidence=Confidence.HIGH,
        status=Status.BROKEN if _is_weak(info) else Status.VULNERABLE, key_size=info.key_size, cert=info,
        evidence=Evidence(
            snippet=f"{info.algorithm} {info.key_size} bits · hash {info.signature_hash} · "
                    f"caduca {info.not_after:%d/%m/%Y} · {info.subject[:80]}",
            notes=notes),
    )


def chain_detections(chain: list[x509.Certificate], location: Location,
                     leaf_notes: tuple[str, ...] = ()) -> list[Detection]:
    detections = []
    for position, cert in enumerate(chain):
        notes = list(leaf_notes) if position == 0 else []
        if position + 1 < len(chain):
            problem = link_problem(cert, chain[position + 1])
            if problem:
                notes.append(f"Cadena rota: {problem}.")
        detections.append(certificate_detection(cert, location, position, tuple(notes)))
    return detections


def scan_cert_file(data: bytes, rel: str) -> list[Detection]:
    return [certificate_detection(c, Location(rel)) for c in load_certs(data)]
