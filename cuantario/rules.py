# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import functools
import re
from dataclasses import dataclass

VULN = "vulnerable"   # Shor
WEAK = "debilitado"   # Grover
SAFE = "resistente"
HYBRID = "hibrido"
BROKEN = "roto_hoy"
SECRET = "secreto_expuesto"

PRIORITIES = ["CRITICO", "ALTO", "MEDIO", "BAJO", "OK"]
CONFIDENCE = ["alta", "media", "baja"]

EU_MILESTONES = [
    ("31/12/2026", "Estrategias nacionales PQC, inventarios criptográficos y mapas de dependencias."),
    ("31/12/2030", "Casos de alto riesgo e infraestructuras críticas migrados; "
                   "sin mecanismos de clave pública vulnerables usados en solitario."),
    ("31/12/2035", "Transición completada en el mayor número posible de sistemas."),
]

PQC_KEM = "ML-KEM-768 (FIPS 203), preferiblemente híbrido X25519MLKEM768"
PQC_SIG = "ML-DSA-65 (FIPS 204) o SLH-DSA (FIPS 205), en modo híbrido durante la transición"


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    pattern: str
    primitive: str  # vocabulario de CycloneDX 1.6
    status: str
    hndl: bool
    replacement: str
    nist_level: int = 0
    consumes: bool = False

    @property
    def rx(self) -> re.Pattern:
        return _compile(self.pattern)


@functools.cache
def _compile(pattern: str) -> re.Pattern:
    return re.compile(pattern)


RULES: list[Rule] = [
    Rule("hybrid-kem", "Intercambio híbrido clásico + ML-KEM",
         r"(?i)X25519[-_]?MLKEM768|SecP(?:256|384)r1[-_]?MLKEM\d+|mlkem768x25519|X25519Kyber768",
         "kem", HYBRID, True, "Correcto: mantener", 3, consumes=True),
    Rule("hybrid-sntrup", "Híbrido sntrup761 + X25519 (SSH, no estandarizado por NIST)",
         r"sntrup761x25519-sha512(?:@openssh\.com)?",
         "kem", HYBRID, True, "Aceptable; preferible mlkem768x25519-sha256 (ML-KEM, FIPS 203)", 0, consumes=True),
    Rule("ml-kem", "ML-KEM / Kyber", r"(?i)\bML-?KEM(?:-?(?:512|768|1024))?\b|\bKyber(?:512|768|1024)?\b",
         "kem", SAFE, True, "Correcto: valorar modo híbrido", 3),
    Rule("ml-dsa", "ML-DSA / Dilithium", r"(?i)\bML-?DSA(?:-?(?:44|65|87))?\b|\bDilithium[235]?\b",
         "signature", SAFE, False, "Correcto", 3),
    Rule("slh-dsa", "SLH-DSA / SPHINCS+", r"(?i)\bSLH-?DSA\b|\bSPHINCS\+?",
         "signature", SAFE, False, "Correcto", 1),
    Rule("rsa", "RSA", r"\bRSA\b|\brsa\.generate|\bimport rsa\b|RSA_generate_key|ssh-rsa|rsa-sha2-(?:256|512)"
         r"|\b[RP]S(?:256|384|512)\b",
         "pke", VULN, True, PQC_KEM + " / " + PQC_SIG),
    Rule("ecdsa", "ECDSA / curvas NIST", r"(?i)\bECDSA\b|\bES(?:256|384|512)\b|ecdsa-sha2-nistp\d+"
         r"|\bsecp(?:256|384|521)r1\b|\bprime256v1\b",
         "signature", VULN, False, PQC_SIG),
    Rule("ecdh", "ECDH / X25519 / X448", r"(?i)\bECDHE?\b|ecdh-sha2-nistp\d+|\bX25519\b|curve25519-sha256|\bX448\b",
         "key-agree", VULN, True, PQC_KEM),
    Rule("dh", "Diffie-Hellman finito", r"\bDHE?-|(?i:diffie-hellman-group[\w-]*|\bffdhe\d+\b)",
         "key-agree", VULN, True, PQC_KEM),
    Rule("dsa", "DSA", r"(?<![\w-])DSA\b|ssh-dss", "signature", VULN, False, PQC_SIG),
    Rule("eddsa", "EdDSA (Ed25519/Ed448)", r"(?i)\bEd(?:25519|448)\b|ssh-ed25519|\bEdDSA\b",
         "signature", VULN, False, PQC_SIG),
    Rule("aes-128", "AES-128", r"(?i)\bAES[-_]?128\b|aes128-(?:gcm|ctr|cbc)", "ae", WEAK, True, "AES-256-GCM", 1),
    Rule("aes-256", "AES-256", r"(?i)\bAES[-_]?256\b|aes256-(?:gcm|ctr)", "ae", SAFE, True, "Correcto", 5),
    Rule("chacha20", "ChaCha20-Poly1305", r"(?i)ChaCha20[-_]?Poly1305", "ae", SAFE, True, "Correcto", 5),
    Rule("3des", "3DES", r"(?i)\b3DES\b|DES-EDE3|TripleDES|\bDESede\b", "block-cipher", BROKEN, True, "AES-256-GCM"),
    Rule("des", "DES", r"(?<![\w-])DES(?:-CBC|-ECB)?(?![\w-])", "block-cipher", BROKEN, True, "AES-256-GCM"),
    Rule("rc4", "RC4", r"(?i)\bRC4\b|\bARCFOUR\b", "stream-cipher", BROKEN, True, "ChaCha20-Poly1305 o AES-GCM"),
    Rule("md5", "MD5", r"(?i)\bMD5\b|hashlib\.md5", "hash", BROKEN, False, "SHA-256 / SHA3-256"),
    Rule("sha1", "SHA-1", r"(?i)\bSHA-?1\b|hashlib\.sha1", "hash", BROKEN, False, "SHA-256 / SHA3-256"),
]
RULES_BY_ID = {r.id: r for r in RULES}

PRIVKEY_RX = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
