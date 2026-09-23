# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import contextlib
import ipaddress
import os
import socket
import ssl
import struct
from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import Enum
from typing import BinaryIO

from cryptography import x509

from .certs import analyze_certificate
from .model import Finding
from .rules import Confidence, Primitive, Source, Status
from .scanner import scan_text

# RFC 8446 §4.1.3: un ServerHello con este random es en realidad un HelloRetryRequest.
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
TLS_ALERT, TLS_HANDSHAKE, SERVER_HELLO = 21, 22, 2
MAX_TLS_RECORD = 2**14 + 2048
MAX_SSH_PACKET = 35_000
SSH_MSG_KEXINIT = 20

GROUP_NAMES = {
    0x11EC: "X25519MLKEM768", 0x11EB: "SecP256r1MLKEM768", 0x11ED: "SecP384r1MLKEM1024",
    0x0201: "MLKEM768", 0x0202: "MLKEM1024",
    0x001D: "X25519", 0x0017: "ECDHE-P256", 0x0018: "ECDHE-P384",
}
PQ_GROUPS = [0x11EC, 0x11EB, 0x11ED, 0x0201, 0x0202]
CLASSIC_GROUPS = [0x001D, 0x0017, 0x0018]
SIG_ALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
            0x0807, 0x0808, 0x0904, 0x0905, 0x0906]


class ProtocolError(ValueError):
    """El servidor respondió algo que no se puede interpretar."""


class Reply(Enum):
    HRR = "hrr"
    SERVER_HELLO = "server_hello"
    TLS12 = "tls12"
    REJECTED = "rechazado"
    NO_ANSWER = "sin_respuesta"
    UNKNOWN = "desconocido"


@dataclass(frozen=True)
class ServerReply:
    kind: Reply
    group: int | None = None


def parse_target(text: str, default_port: int) -> tuple[str, int]:
    text = text.strip()
    if text.startswith("["):
        host, sep, rest = text[1:].partition("]")
        if not sep or (rest and not rest.startswith(":")):
            raise ValueError(f"dirección IPv6 mal formada: {text!r}")
        port_text = rest[1:] if rest else ""
    elif text.count(":") == 1:
        host, port_text = text.split(":")
    else:
        host, port_text = text, ""
    if not host or any(c.isspace() for c in host):
        raise ValueError(f"host no válido: {text!r}")
    if not port_text:
        return host, default_port
    if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise ValueError(f"puerto no válido: {port_text!r}")
    return host, int(port_text)


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("el servidor cerró la conexión")
        buf += chunk
    return buf


def _u8(buf: bytes, offset: int) -> int:
    if offset >= len(buf):
        raise ProtocolError("mensaje truncado")
    return buf[offset]


def _u16(buf: bytes, offset: int) -> int:
    if offset + 2 > len(buf):
        raise ProtocolError("mensaje truncado")
    return int.from_bytes(buf[offset:offset + 2], "big")


def _u32(buf: bytes, offset: int) -> int:
    if offset + 4 > len(buf):
        raise ProtocolError("mensaje truncado")
    return int.from_bytes(buf[offset:offset + 4], "big")


def _take(buf: bytes, offset: int, n: int) -> bytes:
    if offset + n > len(buf):
        raise ProtocolError("mensaje truncado")
    return buf[offset:offset + n]


def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(data)) + data


def _u16_list(values: list[int]) -> bytes:
    raw = b"".join(struct.pack(">H", v) for v in values)
    return struct.pack(">H", len(raw)) + raw


# El key_share va vacío a propósito: si el servidor admite alguno de los grupos ofrecidos,
# está obligado a contestar con un HelloRetryRequest que lo nombra. Así sabemos qué grupos
# acepta, incluidos los híbridos, sin tener que implementar ML-KEM.
def build_client_hello(host: str, groups: list[int]) -> bytes:
    exts = b""
    if host and not is_ip(host):
        name = host.encode("idna")
        entry = struct.pack(">BH", 0, len(name)) + name
        exts += _ext(0, struct.pack(">H", len(entry)) + entry)
    exts += _ext(43, b"\x02\x03\x04")
    exts += _ext(10, _u16_list(groups))
    exts += _ext(51, b"\x00\x00")
    exts += _ext(13, _u16_list(SIG_ALGS))
    exts += _ext(45, b"\x01\x01")
    suites = _u16_list([0x1301, 0x1302, 0x1303])
    body = (b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32) + suites + b"\x01\x00"
            + struct.pack(">H", len(exts)) + exts)
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def parse_server_response(read: Callable[[int], bytes]) -> ServerReply:
    header = read(5)
    content_type, length = _u8(header, 0), _u16(header, 3)
    if length > MAX_TLS_RECORD:
        raise ProtocolError(f"registro TLS demasiado grande ({length} bytes)")
    payload = read(length)
    if content_type == TLS_ALERT:
        return ServerReply(Reply.REJECTED)
    if content_type != TLS_HANDSHAKE or not payload or payload[0] != SERVER_HELLO:
        return ServerReply(Reply.UNKNOWN)

    body = payload[4:]
    random = _take(body, 2, 32)
    offset = 34
    offset += 1 + _u8(body, offset) + 3  # session_id, cipher_suite, compression
    if offset == len(body):
        return ServerReply(Reply.TLS12)  # sin extensiones no puede ser TLS 1.3
    ext_end = offset + 2 + _u16(body, offset)
    if ext_end > len(body):
        raise ProtocolError("extensiones truncadas")
    offset += 2

    tls13, group = False, None
    while offset < ext_end:
        ext_type, ext_len = _u16(body, offset), _u16(body, offset + 2)
        data = _take(body, offset + 4, ext_len)
        offset += 4 + ext_len
        if ext_type == 43:
            tls13 = data == b"\x03\x04"
        elif ext_type == 51 and len(data) >= 2:
            group = _u16(data, 0)
    if not tls13:
        return ServerReply(Reply.TLS12)
    return ServerReply(Reply.HRR if random == HRR_RANDOM else Reply.SERVER_HELLO, group)


def probe_groups(host: str, port: int, groups: list[int], timeout: float) -> ServerReply:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        # Incluye ConnectionRefusedError: no poder conectar no es lo mismo que un rechazo del grupo.
        return ServerReply(Reply.NO_ANSWER)
    with sock:
        try:
            sock.sendall(build_client_hello(host, groups))
            return parse_server_response(lambda n: recv_exact(sock, n))
        except ConnectionError:
            # Muchos servidores cortan la conexión sin mandar alerta cuando no les vale ningún grupo.
            return ServerReply(Reply.REJECTED)
        except (OSError, ProtocolError):
            return ServerReply(Reply.NO_ANSWER)


def handshake_info(host: str, port: int, timeout: float) -> tuple[str, str, bytes]:
    # Sin validar el certificado: queremos inventariarlo aunque esté caducado o sea autofirmado.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with (socket.create_connection((host, port), timeout=timeout) as raw,
          ctx.wrap_socket(raw, server_hostname=None if is_ip(host) else host) as sock):
        return sock.version() or "", (sock.cipher() or ("",))[0], sock.getpeercert(binary_form=True) or b""


def _preference_note(host: str, port: int, timeout: float) -> tuple[str, bool]:
    # Aceptar PQC no basta: hay que ver qué elige el servidor cuando se le ofrecen ambos,
    # en los dos órdenes, para distinguir su preferencia de la del cliente.
    classic_first = probe_groups(host, port, CLASSIC_GROUPS + PQ_GROUPS, timeout).group
    pq_first = probe_groups(host, port, PQ_GROUPS + CLASSIC_GROUPS, timeout).group
    if classic_first in PQ_GROUPS:
        return "el servidor prefiere el grupo post-cuántico", True
    if pq_first in PQ_GROUPS:
        return "el servidor respeta la preferencia del cliente: los clientes modernos obtienen PQC", True
    return "el servidor elige el grupo clásico aunque el cliente ofrezca PQC", False


def scan_tls(host: str, port: int, timeout: float = 5.0) -> list[Finding]:
    target = f"tls://{host}:{port}"
    findings: list[Finding] = []

    version, cipher, der = "", "", b""
    handshake_error: Exception | None = None
    try:
        version, cipher, der = handshake_info(host, port, timeout)
    except (OSError, ValueError) as e:
        handshake_error = e  # hay servidores que rechazan el saludo de la librería ssl pero sí responden al sondeo
    if version:
        suffix = "" if version == "TLSv1.3" else " · sin TLS 1.3 no es posible el intercambio híbrido post-cuántico"
        findings += [replace(f, line=0, evidence=f.evidence + suffix)
                     for f in scan_text(f"{version} cifrado negociado: {cipher.replace('_', '-')}",
                                        target, Source.TLS, Confidence.HIGH)]
        if version in ("TLSv1", "TLSv1.1", "SSLv3"):
            findings.append(Finding(rule_id="tls-legacy", name=f"Protocolo {version}", status=Status.BROKEN,
                                    primitive=Primitive.OTHER, source=Source.TLS, location=target,
                                    evidence=version, replacement="TLS 1.3", confidence=Confidence.HIGH))
        if der:
            with contextlib.suppress(ValueError):
                findings.append(analyze_certificate(x509.load_der_x509_certificate(der), target))

    if version not in ("", "TLSv1.3"):
        return findings

    supported, unanswered = [], []
    for group in PQ_GROUPS + CLASSIC_GROUPS:
        reply = probe_groups(host, port, [group], timeout)
        if reply.kind is Reply.HRR and reply.group == group:
            supported.append(group)
        elif reply.kind is Reply.NO_ANSWER:
            unanswered.append(group)

    if not version and not supported and len(unanswered) == len(PQ_GROUPS + CLASSIC_GROUPS):
        raise ConnectionError(f"el servidor no responde ({handshake_error})")
    if not supported:
        return findings

    group_line = scan_text("grupos aceptados: " + ", ".join(GROUP_NAMES[g] for g in supported),
                           target, Source.TLS, Confidence.HIGH)
    notes = []
    fallback_ok = True
    if any(g in PQ_GROUPS for g in supported):
        note, fallback_ok = _preference_note(host, port, timeout)
        notes.append(note)
    if unanswered:
        notes.append(f"sin respuesta al sondear {', '.join(GROUP_NAMES[g] for g in unanswered)}: resultado incompleto")
    evidence_suffix = "".join(f" · {n}" for n in notes)
    for f in group_line:
        findings.append(replace(
            f, line=0, evidence=f.evidence + evidence_suffix,
            fallback=f.fallback and fallback_ok,
            confidence=Confidence.MEDIUM if unanswered else f.confidence,
        ))
    return findings


def _read_exact(stream: BinaryIO, n: int) -> bytes:
    data = stream.read(n)
    if len(data) != n:
        raise ProtocolError("paquete SSH truncado")
    return data


def ssh_kexinit(host: str, port: int, timeout: float) -> tuple[str, list[str]]:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(b"SSH-2.0-Cuantario\r\n")
        stream = sock.makefile("rb")
        for _ in range(50):  # RFC 4253 permite líneas de texto antes del banner
            line = stream.readline(1024)
            if not line:
                raise ConnectionError("el servidor cerró la conexión")
            if line.startswith(b"SSH-"):
                banner = line.strip().decode(errors="replace")
                break
        else:
            raise ProtocolError("no se recibió un banner SSH")

        header = _read_exact(stream, 5)
        packet_len, padding = _u32(header, 0), header[4]
        if not 16 < packet_len < MAX_SSH_PACKET:
            raise ProtocolError(f"longitud de paquete SSH no válida ({packet_len})")
        body = _read_exact(stream, packet_len - 1)
        if padding >= len(body):
            raise ProtocolError("relleno SSH mayor que el paquete")
        payload = body[:len(body) - padding]
        if _u8(payload, 0) != SSH_MSG_KEXINIT:
            raise ProtocolError("el servidor no envió KEXINIT")

        offset, lists = 17, []  # tipo de mensaje + cookie de 16 bytes
        for _ in range(10):
            size = _u32(payload, offset)
            lists.append(_take(payload, offset + 4, size).decode(errors="replace"))
            offset += 4 + size
        return banner, lists


def scan_ssh(host: str, port: int, timeout: float = 5.0) -> list[Finding]:
    target = f"ssh://{host}:{port}"
    banner, lists = ssh_kexinit(host, port, timeout)
    kex = ",".join(a for a in lists[0].split(",") if not a.startswith(("ext-info", "kex-strict")))
    findings = scan_text(f"kex: {kex}", target, Source.SSH, Confidence.HIGH)
    # La clave de host solo firma: no hay nada que un atacante pueda guardar y descifrar después.
    findings += [replace(f, harvest_risk=False)
                 for f in scan_text(f"claves de host: {lists[1]}", target, Source.SSH, Confidence.HIGH)]
    findings += scan_text(f"cifrados: {lists[2]}", target, Source.SSH, Confidence.HIGH)
    return [replace(f, line=0, evidence=f"{banner} · {f.evidence}"[:200]) for f in findings]
