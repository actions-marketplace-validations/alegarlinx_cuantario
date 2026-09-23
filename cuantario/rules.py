# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import functools
import re
from dataclasses import dataclass
from enum import Enum


class Status(Enum):
    VULNERABLE = "vulnerable"  # Shor
    WEAKENED = "weakened"
    RESISTANT = "resistant"
    HYBRID = "hybrid"
    BROKEN = "broken"
    EXPOSED_SECRET = "exposed_secret"

    @property
    def label(self) -> str:
        return _STATUS_LABELS[self]


class Priority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    OK = "ok"

    @property
    def label(self) -> str:
        return _PRIORITY_LABELS[self]

    @property
    def rank(self) -> int:
        return list(Priority).index(self)

    @classmethod
    def from_label(cls, label: str) -> Priority:
        return next(p for p in cls if p.label == label)


class Confidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def label(self) -> str:
        return _CONFIDENCE_LABELS[self]

    @property
    def rank(self) -> int:
        return list(Confidence).index(self)

    @classmethod
    def from_label(cls, label: str) -> Confidence:
        return next(c for c in cls if c.label == label)


class Primitive(Enum):
    PKE = "pke"
    KEM = "kem"
    KEY_AGREE = "key-agree"
    SIGNATURE = "signature"
    AE = "ae"
    BLOCK_CIPHER = "block-cipher"
    STREAM_CIPHER = "stream-cipher"
    HASH = "hash"
    MAC = "mac"
    OTHER = "other"


class Source(Enum):
    CODE = "code"
    CONFIG = "config"
    CERTIFICATE = "certificate"
    SECRET = "secret"
    TLS = "tls"
    SSH = "ssh"


class SecurityUse(Enum):
    SECURITY = "security"
    NON_SECURITY = "non_security"
    UNKNOWN = "unknown"


class Profile(Enum):
    EU = "eu"
    CCN = "ccn"


class ServerPreference(Enum):
    PREFERS_PQ = "prefers_pq"
    FOLLOWS_CLIENT = "follows_client"
    PREFERS_CLASSICAL = "prefers_classical"

    @property
    def label(self) -> str:
        return _PREFERENCE_LABELS[self]


_STATUS_LABELS = {
    Status.VULNERABLE: "vulnerable", Status.WEAKENED: "debilitado", Status.RESISTANT: "resistente",
    Status.HYBRID: "híbrido", Status.BROKEN: "roto hoy", Status.EXPOSED_SECRET: "secreto expuesto",
}
_PRIORITY_LABELS = {
    Priority.CRITICAL: "CRITICO", Priority.HIGH: "ALTO", Priority.MEDIUM: "MEDIO", Priority.LOW: "BAJO",
    Priority.OK: "OK",
}
_CONFIDENCE_LABELS = {Confidence.HIGH: "alta", Confidence.MEDIUM: "media", Confidence.LOW: "baja"}
_PREFERENCE_LABELS = {
    ServerPreference.PREFERS_PQ: "el servidor prefiere el grupo post-cuántico",
    ServerPreference.FOLLOWS_CLIENT: ("el servidor respeta la preferencia del cliente: "
                                      "los clientes modernos obtienen PQC"),
    ServerPreference.PREFERS_CLASSICAL: "el servidor elige el grupo clásico aunque el cliente ofrezca PQC",
}

KEY_EXCHANGE = (Primitive.PKE, Primitive.KEM, Primitive.KEY_AGREE)

EU_MILESTONES = [
    ("31/12/2026", "Estrategias nacionales PQC, inventarios criptográficos y mapas de dependencias."),
    ("31/12/2030", "Casos de alto riesgo e infraestructuras críticas migrados; "
                   "sin mecanismos de clave pública vulnerables usados en solitario."),
    ("31/12/2035", "Transición completada en el mayor número posible de sistemas."),
]

PQC_KEM = "ML-KEM-768 (FIPS 203), preferiblemente híbrido X25519MLKEM768"
PQC_SIG = "ML-DSA-65 (FIPS 204) o SLH-DSA (FIPS 205), en modo híbrido durante la transición"


@dataclass(frozen=True, kw_only=True)
class Rule:
    id: str
    name: str
    primitive: Primitive
    status: Status
    harvest_risk: bool
    replacement: str
    pattern: str = ""
    nist_level: int = 0
    note: str = ""
    # Para que "X25519MLKEM768" no cuente también como X25519 ni "hmac-sha1" como SHA-1.
    consumes: bool = False

    @property
    def rx(self) -> re.Pattern[str]:
        return _compile(self.pattern)


@functools.cache
def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


TEXT_RULES: list[Rule] = [
    Rule(id="hybrid-kem", name="Intercambio híbrido clásico + ML-KEM",
         pattern=r"(?i)X25519[-_]?MLKEM768|SecP(?:256|384)r1[-_]?MLKEM\d+|mlkem768x25519|X25519Kyber768",
         primitive=Primitive.KEM, status=Status.HYBRID, harvest_risk=True,
         replacement="Correcto: mantener", nist_level=3, consumes=True),
    Rule(id="hybrid-sntrup", name="Híbrido sntrup761 + X25519 (SSH, no estandarizado por NIST)",
         pattern=r"sntrup761x25519-sha512(?:@openssh\.com)?",
         primitive=Primitive.KEM, status=Status.HYBRID, harvest_risk=True,
         replacement="Aceptable; preferible mlkem768x25519-sha256 (ML-KEM, FIPS 203)", consumes=True),
    Rule(id="ml-kem", name="ML-KEM / Kyber",
         pattern=r"(?i)\bML-?KEM(?:-?(?:512|768|1024))?\b|\bKyber(?:512|768|1024)?\b",
         primitive=Primitive.KEM, status=Status.RESISTANT, harvest_risk=True,
         replacement="Correcto: valorar modo híbrido", nist_level=3),
    Rule(id="ml-dsa", name="ML-DSA / Dilithium",
         pattern=r"(?i)\bML-?DSA(?:-?(?:44|65|87))?\b|\bDilithium[235]?\b",
         primitive=Primitive.SIGNATURE, status=Status.RESISTANT, harvest_risk=False,
         replacement="Correcto", nist_level=3),
    Rule(id="slh-dsa", name="SLH-DSA / SPHINCS+", pattern=r"(?i)\bSLH-?DSA\b|\bSPHINCS\+?",
         primitive=Primitive.SIGNATURE, status=Status.RESISTANT, harvest_risk=False,
         replacement="Correcto", nist_level=1),
    Rule(id="rsa", name="RSA",
         pattern=r"\bRSA\b|\brsa\.generate|\bimport rsa\b|RSA_generate_key|ssh-rsa|rsa-sha2-(?:256|512)"
                 r"|\b[RP]S(?:256|384|512)\b",
         primitive=Primitive.PKE, status=Status.VULNERABLE, harvest_risk=True,
         replacement=f"{PQC_KEM} / {PQC_SIG}"),
    Rule(id="ecdsa", name="ECDSA / curvas NIST",
         pattern=r"(?i)\bECDSA\b|\bES(?:256|384|512)\b|ecdsa-sha2-nistp\d+|\bsecp(?:256|384|521)r1\b|\bprime256v1\b",
         primitive=Primitive.SIGNATURE, status=Status.VULNERABLE, harvest_risk=False, replacement=PQC_SIG),
    Rule(id="ecdh", name="ECDH / X25519 / X448",
         pattern=r"(?i)\bECDHE?\b|ecdh-sha2-nistp\d+|\bX25519\b|curve25519-sha256|\bX448\b",
         primitive=Primitive.KEY_AGREE, status=Status.VULNERABLE, harvest_risk=True, replacement=PQC_KEM),
    Rule(id="dh", name="Diffie-Hellman finito",
         pattern=r"\bDHE?-|(?i:diffie-hellman-group[\w-]*|\bffdhe\d+\b)",
         primitive=Primitive.KEY_AGREE, status=Status.VULNERABLE, harvest_risk=True, replacement=PQC_KEM),
    Rule(id="dsa", name="DSA", pattern=r"(?<![\w-])DSA\b|ssh-dss",
         primitive=Primitive.SIGNATURE, status=Status.VULNERABLE, harvest_risk=False, replacement=PQC_SIG),
    Rule(id="eddsa", name="EdDSA (Ed25519/Ed448)", pattern=r"(?i)\bEd(?:25519|448)\b|ssh-ed25519|\bEdDSA\b",
         primitive=Primitive.SIGNATURE, status=Status.VULNERABLE, harvest_risk=False, replacement=PQC_SIG),
    Rule(id="aes-cbc", name="Modo CBC sin autenticación",
         pattern=r"(?i)\bAES[-_]?(?:128|192|256)?[-_/]?CBC\b|\baes(?:128|192|256)-cbc\b",
         primitive=Primitive.BLOCK_CIPHER, status=Status.WEAKENED, harvest_risk=False,
         replacement="AES-256-GCM o ChaCha20-Poly1305",
         note="CBC no autentica: sin un MAC aparte admite manipulación del mensaje y ataques de padding oracle."),
    Rule(id="aes-128", name="AES-128", pattern=r"(?i)\bAES[-_]?128\b|aes128-(?:gcm|ctr|cbc)",
         primitive=Primitive.AE, status=Status.WEAKENED, harvest_risk=True, replacement="AES-256-GCM", nist_level=1),
    Rule(id="aes-256", name="AES-256", pattern=r"(?i)\bAES[-_]?256\b|aes256-(?:gcm|ctr)",
         primitive=Primitive.AE, status=Status.RESISTANT, harvest_risk=True, replacement="Correcto", nist_level=5),
    Rule(id="chacha20", name="ChaCha20-Poly1305", pattern=r"(?i)ChaCha20[-_]?Poly1305",
         primitive=Primitive.AE, status=Status.RESISTANT, harvest_risk=True, replacement="Correcto", nist_level=5),
    Rule(id="3des", name="3DES", pattern=r"(?i)\b3DES\b|DES-EDE3|TripleDES|\bDESede\b",
         primitive=Primitive.BLOCK_CIPHER, status=Status.BROKEN, harvest_risk=True, replacement="AES-256-GCM"),
    Rule(id="des", name="DES", pattern=r"(?<![\w-])DES(?:-CBC|-ECB)?(?![\w-])",
         primitive=Primitive.BLOCK_CIPHER, status=Status.BROKEN, harvest_risk=True, replacement="AES-256-GCM"),
    Rule(id="rc4", name="RC4", pattern=r"(?i)\bRC4\b|\bARCFOUR\b",
         primitive=Primitive.STREAM_CIPHER, status=Status.BROKEN, harvest_risk=True,
         replacement="ChaCha20-Poly1305 o AES-GCM"),
    Rule(id="hmac-legacy", name="HMAC con MD5 o SHA-1",
         pattern=r"(?i)\bhmac[-_](?:sha1|md5)\b(?:[\w@.-]*)|\bHmac(?:SHA1|MD5)\b",
         primitive=Primitive.MAC, status=Status.WEAKENED, harvest_risk=False, replacement="HMAC-SHA-256",
         note="No está roto: lo que falla en MD5 y SHA-1 son las colisiones, que no afectan a HMAC. "
              "Migrar por higiene, sin urgencia.",
         consumes=True),
    Rule(id="md5", name="MD5", pattern=r"(?i)\bMD5\b|hashlib\.md5",
         primitive=Primitive.HASH, status=Status.BROKEN, harvest_risk=False, replacement="SHA-256 / SHA3-256"),
    Rule(id="sha1", name="SHA-1", pattern=r"(?i)\bSHA-?1\b|hashlib\.sha1",
         primitive=Primitive.HASH, status=Status.BROKEN, harvest_risk=False, replacement="SHA-256 / SHA3-256"),
]

SPECIAL_RULES: list[Rule] = [
    Rule(id="certificate", name="Certificado", primitive=Primitive.SIGNATURE, status=Status.VULNERABLE,
         harvest_risk=False, replacement=PQC_SIG),
    Rule(id="rsa-signature", name="RSA (firma)", primitive=Primitive.SIGNATURE, status=Status.VULNERABLE,
         harvest_risk=False, replacement=PQC_SIG),
    Rule(id="private-key", name="Clave privada", primitive=Primitive.OTHER, status=Status.EXPOSED_SECRET,
         harvest_risk=False, replacement="Usar un gestor de secretos o un HSM"),
    Rule(id="tls-legacy", name="Protocolo TLS 1.0/1.1", primitive=Primitive.OTHER, status=Status.BROKEN,
         harvest_risk=False, replacement="TLS 1.3 (y TLS 1.2 solo como respaldo)"),
]

RULES_BY_ID = {r.id: r for r in TEXT_RULES + SPECIAL_RULES}

PRIVKEY_RX = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
