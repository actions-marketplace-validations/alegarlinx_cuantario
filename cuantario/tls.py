# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import os
import socket
import ssl
import struct
from collections.abc import Callable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum

from cryptography import x509

from .certs import chain_detections
from .model import Detection, Evidence, Location, detect
from .net import (
    NetworkError,
    PeerClosed,
    ProbeConfig,
    ProtocolError,
    RateLimiter,
    exchange,
    is_ip,
    recv_exact,
    take,
    u8,
    u16,
    u24,
)
from .rules import Confidence, ServerPreference, Source

# RFC 8446 §4.1.3: un ServerHello con este random es en realidad un HelloRetryRequest.
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
RECORD_ALERT, RECORD_HANDSHAKE = 21, 22
HS_SERVER_HELLO, HS_CERTIFICATE, HS_SERVER_HELLO_DONE = 2, 11, 14
MAX_RECORD = 2**14 + 2048
MAX_CERT_MESSAGE = 1 << 17


class TlsVersion(Enum):
    TLS10 = 0x0301
    TLS11 = 0x0302
    TLS12 = 0x0303
    TLS13 = 0x0304

    @property
    def label(self) -> str:
        return f"TLS 1.{self.value - 0x0301}"


@dataclass(frozen=True)
class Group:
    name: str
    rule_id: str
    post_quantum: bool


GROUPS = {
    0x11EC: Group("X25519MLKEM768", "hybrid-kem", True),
    0x11EB: Group("SecP256r1MLKEM768", "hybrid-kem", True),
    0x11ED: Group("SecP384r1MLKEM1024", "hybrid-kem", True),
    0x0201: Group("MLKEM768", "ml-kem", True),
    0x0202: Group("MLKEM1024", "ml-kem", True),
    0x001D: Group("X25519", "ecdh", False),
    0x0017: Group("ECDHE-P256", "ecdh", False),
    0x0018: Group("ECDHE-P384", "ecdh", False),
}
PQ_GROUPS = [code for code, g in GROUPS.items() if g.post_quantum]
CLASSIC_GROUPS = [code for code, g in GROUPS.items() if not g.post_quantum]


@dataclass(frozen=True)
class Suite:
    name: str
    rule_ids: tuple[str, ...]


TLS13_SUITES = {
    0x1301: Suite("TLS_AES_128_GCM_SHA256", ("aes-128",)),
    0x1302: Suite("TLS_AES_256_GCM_SHA384", ("aes-256",)),
    0x1303: Suite("TLS_CHACHA20_POLY1305_SHA256", ("chacha20",)),
}
# Sin "ECDHE"/"DHE" delante, el intercambio de claves es transporte RSA: el secreto viaja cifrado con
# la clave del certificado, así que quien guarde el tráfico lo descifra en cuanto rompa esa clave.
LEGACY_SUITES = {
    0xC02F: Suite("ECDHE-RSA-AES128-GCM-SHA256", ("ecdh", "aes-128")),
    0xC030: Suite("ECDHE-RSA-AES256-GCM-SHA384", ("ecdh", "aes-256")),
    0xC02B: Suite("ECDHE-ECDSA-AES128-GCM-SHA256", ("ecdh", "aes-128")),
    0xC02C: Suite("ECDHE-ECDSA-AES256-GCM-SHA384", ("ecdh", "aes-256")),
    0xCCA8: Suite("ECDHE-RSA-CHACHA20-POLY1305", ("ecdh", "chacha20")),
    0xCCA9: Suite("ECDHE-ECDSA-CHACHA20-POLY1305", ("ecdh", "chacha20")),
    0xC013: Suite("ECDHE-RSA-AES128-SHA", ("ecdh", "aes-128", "aes-cbc", "hmac-legacy")),
    0xC014: Suite("ECDHE-RSA-AES256-SHA", ("ecdh", "aes-256", "aes-cbc", "hmac-legacy")),
    0xC009: Suite("ECDHE-ECDSA-AES128-SHA", ("ecdh", "aes-128", "aes-cbc", "hmac-legacy")),
    0xC00A: Suite("ECDHE-ECDSA-AES256-SHA", ("ecdh", "aes-256", "aes-cbc", "hmac-legacy")),
    0x009E: Suite("DHE-RSA-AES128-GCM-SHA256", ("dh", "aes-128")),
    0x009F: Suite("DHE-RSA-AES256-GCM-SHA384", ("dh", "aes-256")),
    0x0033: Suite("DHE-RSA-AES128-SHA", ("dh", "aes-128", "aes-cbc", "hmac-legacy")),
    0x0039: Suite("DHE-RSA-AES256-SHA", ("dh", "aes-256", "aes-cbc", "hmac-legacy")),
    0x009C: Suite("AES128-GCM-SHA256", ("rsa", "aes-128")),
    0x009D: Suite("AES256-GCM-SHA384", ("rsa", "aes-256")),
    0x002F: Suite("AES128-SHA", ("rsa", "aes-128", "aes-cbc", "hmac-legacy")),
    0x0035: Suite("AES256-SHA", ("rsa", "aes-256", "aes-cbc", "hmac-legacy")),
    0x000A: Suite("DES-CBC3-SHA", ("rsa", "3des", "hmac-legacy")),
    0x0005: Suite("RC4-SHA", ("rsa", "rc4", "hmac-legacy")),
    0x0004: Suite("RC4-MD5", ("rsa", "rc4", "hmac-legacy")),
}
SIG_ALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
            0x0807, 0x0808, 0x0904, 0x0905, 0x0906, 0x0201, 0x0203]
TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF


class Reply(Enum):
    HELLO_RETRY = "hello_retry"
    SERVER_HELLO = "server_hello"
    REJECTED = "rejected"
    NETWORK_ERROR = "network_error"


@dataclass(frozen=True)
class ServerReply:
    kind: Reply
    version: TlsVersion | None = None
    group: int | None = None
    cipher_suite: int | None = None
    detail: str = ""


class TlsAlert(Exception):
    pass


def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(data)) + data


def _u16_list(values: list[int]) -> bytes:
    raw = b"".join(struct.pack(">H", v) for v in values)
    return struct.pack(">H", len(raw)) + raw


def _sni(host: str) -> bytes:
    if not host or is_ip(host):
        return b""
    name = host.encode("idna")
    entry = struct.pack(">BH", 0, len(name)) + name
    return _ext(0, struct.pack(">H", len(entry)) + entry)


def _wrap(body: bytes) -> bytes:
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


# El key_share va vacío a propósito: si el servidor admite alguno de los grupos ofrecidos,
# está obligado a contestar con un HelloRetryRequest que lo nombra. Así sabemos qué grupos
# acepta, incluidos los híbridos, sin tener que implementar ML-KEM.
def build_client_hello(host: str, groups: list[int]) -> bytes:
    exts = (_sni(host) + _ext(43, b"\x02\x03\x04") + _ext(10, _u16_list(groups)) + _ext(51, b"\x00\x00")
            + _ext(13, _u16_list(SIG_ALGS)) + _ext(45, b"\x01\x01"))
    body = (b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32) + _u16_list(list(TLS13_SUITES))
            + b"\x01\x00" + struct.pack(">H", len(exts)) + exts)
    return _wrap(body)


# Hello "a la antigua" (sin supported_versions) para una versión concreta. Así se prueba TLS 1.0/1.1
# directamente contra el servidor: la librería ssl con OpenSSL 3 se niega a negociarlas.
def build_legacy_hello(host: str, version: TlsVersion) -> bytes:
    exts = (_sni(host) + _ext(10, _u16_list(CLASSIC_GROUPS)) + _ext(11, b"\x01\x00")
            + _ext(13, _u16_list(SIG_ALGS)))
    suites = [*LEGACY_SUITES, TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    body = (struct.pack(">H", version.value) + os.urandom(32) + b"\x00" + _u16_list(suites)
            + b"\x01\x00" + struct.pack(">H", len(exts)) + exts)
    return _wrap(body)


def handshake_messages(read: Callable[[int], bytes]) -> Iterator[tuple[int, bytes]]:
    buf = b""
    while True:
        header = read(5)
        content_type, length = u8(header, 0), u16(header, 3)
        if length > MAX_RECORD:
            raise ProtocolError(f"registro TLS demasiado grande ({length} bytes)")
        payload = read(length)
        if content_type == RECORD_ALERT:
            raise TlsAlert(payload.hex())
        if content_type != RECORD_HANDSHAKE:
            continue  # ChangeCipherSpec de compatibilidad tras un HelloRetryRequest
        buf += payload
        while len(buf) >= 4:
            msg_len = u24(buf, 1)
            if msg_len > MAX_CERT_MESSAGE:
                raise ProtocolError("mensaje de handshake demasiado grande")
            if len(buf) < 4 + msg_len:
                break
            yield buf[0], buf[4:4 + msg_len]
            buf = buf[4 + msg_len:]


def parse_server_hello(body: bytes) -> ServerReply:
    legacy_version = u16(body, 0)
    random = take(body, 2, 32)
    offset = 34
    offset += 1 + u8(body, offset)
    suite = u16(body, offset)
    offset += 3  # cipher_suite, compression

    version_code, group = legacy_version, None
    if offset < len(body):
        ext_end = offset + 2 + u16(body, offset)
        if ext_end > len(body):
            raise ProtocolError("extensiones truncadas")
        offset += 2
        while offset < ext_end:
            ext_type, ext_len = u16(body, offset), u16(body, offset + 2)
            data = take(body, offset + 4, ext_len)
            offset += 4 + ext_len
            if ext_type == 43:
                version_code = u16(data, 0)
            elif ext_type == 51 and len(data) >= 2:
                group = u16(data, 0)
    try:
        version = TlsVersion(version_code)
    except ValueError as e:
        raise ProtocolError(f"versión TLS desconocida: {version_code:#06x}") from e
    kind = Reply.HELLO_RETRY if random == HRR_RANDOM else Reply.SERVER_HELLO
    return ServerReply(kind, version, group, suite)


def parse_server_response(read: Callable[[int], bytes]) -> ServerReply:
    try:
        for msg_type, body in handshake_messages(read):
            if msg_type != HS_SERVER_HELLO:
                raise ProtocolError(f"se esperaba ServerHello y llegó el mensaje {msg_type}")
            return parse_server_hello(body)
    except TlsAlert:
        return ServerReply(Reply.REJECTED)
    raise ProtocolError("sin ServerHello")


def parse_certificate_message(body: bytes) -> list[x509.Certificate]:
    total = u24(body, 0)
    if total + 3 > len(body):
        raise ProtocolError("mensaje Certificate truncado")
    certs, offset = [], 3
    while offset < 3 + total:
        size = u24(body, offset)
        der = take(body, offset + 3, size)
        offset += 3 + size
        try:
            certs.append(x509.load_der_x509_certificate(der))
        except ValueError as e:
            raise ProtocolError("certificado DER no válido en la cadena") from e
    return certs


def probe(host: str, port: int, hello: bytes, config: ProbeConfig, limiter: RateLimiter) -> ServerReply:
    def talk(sock: socket.socket) -> ServerReply:
        sock.sendall(hello)
        try:
            return parse_server_response(lambda n: recv_exact(sock, n))
        except PeerClosed:
            return ServerReply(Reply.REJECTED)
    try:
        return exchange(host, port, config, limiter, talk)
    except (NetworkError, ProtocolError) as e:
        return ServerReply(Reply.NETWORK_ERROR, detail=str(e))


def fetch_chain_legacy(host: str, port: int, config: ProbeConfig, limiter: RateLimiter) -> list[x509.Certificate]:
    def talk(sock: socket.socket) -> list[x509.Certificate]:
        sock.sendall(build_legacy_hello(host, TlsVersion.TLS12))
        for msg_type, body in handshake_messages(lambda n: recv_exact(sock, n)):
            if msg_type == HS_CERTIFICATE:
                return parse_certificate_message(body)
            if msg_type == HS_SERVER_HELLO_DONE:
                break
        return []
    try:
        return exchange(host, port, config, limiter, talk)
    except (NetworkError, ProtocolError, PeerClosed, TlsAlert):
        return []


def fetch_chain_ssl(host: str, port: int, timeout: float) -> list[x509.Certificate]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with (socket.create_connection((host, port), timeout=timeout) as raw,
              ctx.wrap_socket(raw, server_hostname=None if is_ip(host) else host) as sock):
            unverified_chain = getattr(sock, "get_unverified_chain", None)  # Python 3.13+
            if unverified_chain is not None:
                return [x509.load_der_x509_certificate(der) for der in unverified_chain()]
            der = sock.getpeercert(binary_form=True)
            return [x509.load_der_x509_certificate(der)] if der else []
    except (OSError, ValueError):
        return []


def trust_note(host: str, port: int, timeout: float) -> str:
    ctx = ssl.create_default_context()
    try:
        with (socket.create_connection((host, port), timeout=timeout) as raw,
              ctx.wrap_socket(raw, server_hostname=host) as sock):
            sock.version()
    except ssl.SSLCertVerificationError as e:
        return f"La cadena no valida contra el almacén del sistema: {e.verify_message}."
    except (OSError, ValueError):
        return "No se pudo comprobar la cadena contra el almacén del sistema."
    return "La cadena valida contra el almacén del sistema."


def _preference(host: str, submit: Callable[[bytes], Future[ServerReply]]) -> ServerPreference:
    # Aceptar PQC no basta: hay que ver qué elige el servidor cuando se le ofrecen ambos,
    # en los dos órdenes, para distinguir su preferencia de la del cliente.
    classic_first = submit(build_client_hello(host, CLASSIC_GROUPS + PQ_GROUPS))
    pq_first = submit(build_client_hello(host, PQ_GROUPS + CLASSIC_GROUPS))
    if classic_first.result().group in PQ_GROUPS:
        return ServerPreference.PREFERS_PQ
    if pq_first.result().group in PQ_GROUPS:
        return ServerPreference.FOLLOWS_CLIENT
    return ServerPreference.PREFERS_CLASSICAL


def _suite_detections(suite_code: int | None, version: TlsVersion, location: Location,
                      notes: tuple[str, ...]) -> list[Detection]:
    suite = (TLS13_SUITES if version is TlsVersion.TLS13 else LEGACY_SUITES).get(suite_code or -1)
    if suite is None:
        return []
    return [detect(rule_id, location=location, source=Source.TLS, confidence=Confidence.HIGH,
                   evidence=Evidence(snippet=f"{version.label} · {suite.name}", notes=notes))
            for rule_id in suite.rule_ids]


def scan_tls(host: str, port: int, config: ProbeConfig | None = None) -> list[Detection]:
    config = config or ProbeConfig()
    location = Location(f"tls://{host}:{port}")
    limiter = RateLimiter(config.min_interval)

    with ThreadPoolExecutor(max_workers=config.workers) as pool:
        def submit(hello: bytes) -> Future[ServerReply]:
            return pool.submit(probe, host, port, hello, config, limiter)

        legacy = {v: submit(build_legacy_hello(host, v))
                  for v in (TlsVersion.TLS10, TlsVersion.TLS11, TlsVersion.TLS12)}
        groups = {g: submit(build_client_hello(host, [g])) for g in GROUPS}
        legacy_replies = {v: f.result() for v, f in legacy.items()}
        group_replies = {g: f.result() for g, f in groups.items()}

        all_replies = [*legacy_replies.values(), *group_replies.values()]
        if all(r.kind is Reply.NETWORK_ERROR for r in all_replies):
            raise NetworkError(f"el servidor no responde ({all_replies[0].detail})")

        legacy_ok = [v for v, r in legacy_replies.items() if r.kind is Reply.SERVER_HELLO and r.version is v]
        supported = [g for g, r in group_replies.items() if r.kind is Reply.HELLO_RETRY and r.group == g]
        missing = [v.label for v, r in legacy_replies.items() if r.kind is Reply.NETWORK_ERROR]
        missing += [GROUPS[g].name for g, r in group_replies.items() if r.kind is Reply.NETWORK_ERROR]
        has_tls13 = bool(supported)
        preference = _preference(host, submit) if any(g in PQ_GROUPS for g in supported) else None

    detections: list[Detection] = []
    for version in legacy_ok:
        if version in (TlsVersion.TLS10, TlsVersion.TLS11):
            detections.append(detect("tls-legacy", location=location, source=Source.TLS,
                                     confidence=Confidence.HIGH,
                                     evidence=Evidence(snippet=f"{version.label} aceptado")))

    if has_tls13:
        suite = next((r.cipher_suite for g, r in group_replies.items() if g in supported), None)
        detections += _suite_detections(suite, TlsVersion.TLS13, location, ())
    elif legacy_ok:
        best = max(legacy_ok, key=lambda v: v.value)
        detections += _suite_detections(legacy_replies[best].cipher_suite, best, location,
                                        ("sin TLS 1.3 no es posible el intercambio híbrido post-cuántico",))

    notes = (f"sin respuesta al sondear {', '.join(missing)}: resultado incompleto",) if missing else ()
    for code in supported:
        group = GROUPS[code]
        detections.append(detect(
            group.rule_id, location=location, source=Source.TLS,
            confidence=Confidence.MEDIUM if missing else Confidence.HIGH,
            evidence=Evidence(snippet=group.name, notes=notes, server_preference=preference),
            fallback=not group.post_quantum and preference not in (None, ServerPreference.PREFERS_CLASSICAL),
        ))

    chain = fetch_chain_legacy(host, port, config, limiter) if legacy_ok else []
    if not chain:
        chain = fetch_chain_ssl(host, port, config.timeout)
    if chain:
        leaf_notes = [trust_note(host, port, config.timeout)]
        if len(chain) == 1 and not legacy_ok and not hasattr(ssl.SSLSocket, "get_unverified_chain"):
            leaf_notes.append("Solo TLS 1.3 y Python < 3.13: solo se ha podido obtener el certificado hoja.")
        detections += chain_detections(chain, location, tuple(leaf_notes))
    return detections
