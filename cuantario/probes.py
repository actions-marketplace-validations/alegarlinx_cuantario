# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import ipaddress
import os
import socket
import ssl
import struct

from cryptography import x509

from .certs import analyze_certificate
from .model import Context, Finding, prioritize
from .rules import BROKEN
from .scanner import scan_text

# RFC 8446 §4.1.3: un ServerHello con este random es en realidad un HelloRetryRequest.
HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

GROUP_NAMES = {
    0x11EC: "X25519MLKEM768", 0x11EB: "SecP256r1MLKEM768", 0x11ED: "SecP384r1MLKEM1024",
    0x0201: "MLKEM768", 0x0202: "MLKEM1024",
    0x001D: "X25519", 0x0017: "ECDHE-P256", 0x0018: "ECDHE-P384",
}
PQ_GROUPS = [0x11EC, 0x11EB, 0x11ED, 0x0201, 0x0202]
CLASSIC_GROUPS = [0x001D, 0x0017, 0x0018]
SIG_ALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
            0x0807, 0x0808, 0x0904, 0x0905, 0x0906]


def parse_target(text: str, default_port: int) -> tuple[str, int]:
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") else default_port
    if text.count(":") == 1:
        host, port = text.split(":")
        return host, int(port)
    return text, default_port


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


def parse_server_response(read) -> dict:
    header = read(5)
    content_type, length = header[0], struct.unpack(">H", header[3:5])[0]
    payload = read(length)
    if content_type == 21:
        return {"type": "alert", "group": None, "tls13": False}
    if content_type != 22 or not payload or payload[0] != 2:
        return {"type": "desconocido", "group": None, "tls13": False}

    body = payload[4:]
    random = body[2:34]
    p = 34
    p += 1 + body[p] + 3  # session_id, cipher_suite, compression
    result = {"type": "hrr" if random == HRR_RANDOM else "server_hello", "group": None, "tls13": False}
    if p + 2 <= len(body):
        end = p + 2 + struct.unpack(">H", body[p:p + 2])[0]
        p += 2
        while p + 4 <= end:
            ext_type, ext_len = struct.unpack(">HH", body[p:p + 4])
            data = body[p + 4:p + 4 + ext_len]
            p += 4 + ext_len
            if ext_type == 43 and data == b"\x03\x04":
                result["tls13"] = True
            elif ext_type == 51 and len(data) >= 2:
                result["group"] = struct.unpack(">H", data[:2])[0]
    if not result["tls13"]:
        result["type"] = "tls12"
    return result


def probe_groups(host: str, port: int, groups: list[int], timeout: float) -> dict:
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(build_client_hello(host, groups))
        try:
            return parse_server_response(lambda n: recv_exact(s, n))
        except ConnectionError:
            return {"type": "alert", "group": None, "tls13": False}


def handshake_info(host: str, port: int, timeout: float) -> tuple[str, str, bytes]:
    # Sin validar el certificado: queremos inventariarlo aunque esté caducado o sea autofirmado.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with (socket.create_connection((host, port), timeout=timeout) as raw,
          ctx.wrap_socket(raw, server_hostname=None if is_ip(host) else host) as s):
        return s.version() or "", (s.cipher() or ("",))[0], s.getpeercert(binary_form=True) or b""


def scan_tls(host: str, port: int, ctx: Context, timeout: float = 5.0) -> list[Finding]:
    target = f"tls://{host}:{port}"
    findings: list[Finding] = []

    version = ""
    try:
        version, cipher, der = handshake_info(host, port, timeout)
        cipher_line = scan_text(f"{version} cifrado negociado: {cipher.replace('_', '-')}", target, "tls", "alta")
        if version != "TLSv1.3":
            for f in cipher_line:
                f.evidence += " · sin TLS 1.3 no es posible el intercambio híbrido post-cuántico"
        findings += cipher_line
        if version in ("TLSv1", "TLSv1.1", "SSLv3"):
            findings.append(Finding("tls-legacy", f"Protocolo {version}", BROKEN, "other", target, 0,
                                    version, "TLS 1.3", "tls", confidence="alta"))
        if der:
            findings.append(analyze_certificate(x509.load_der_x509_certificate(der), target, ctx))
    except (OSError, ValueError):
        pass  # hay servidores que rechazan el saludo de la librería ssl pero sí responden al sondeo

    if version in ("", "TLSv1.3"):
        supported = [g for g in PQ_GROUPS + CLASSIC_GROUPS
                     if (r := probe_groups(host, port, [g], timeout))["type"] == "hrr" and r["group"] == g]
        if supported:
            group_line = scan_text("grupos aceptados: " + ", ".join(GROUP_NAMES[g] for g in supported),
                                   target, "tls", "alta")
            if any(g in PQ_GROUPS for g in supported):
                # Aceptar PQC no basta: hay que ver qué elige el servidor cuando se le ofrecen ambos,
                # en los dos órdenes, para distinguir su preferencia de la del cliente.
                classic_first = probe_groups(host, port, CLASSIC_GROUPS + PQ_GROUPS, timeout).get("group")
                pq_first = probe_groups(host, port, PQ_GROUPS + CLASSIC_GROUPS, timeout).get("group")
                if classic_first in PQ_GROUPS:
                    note = "el servidor prefiere el grupo post-cuántico"
                elif pq_first in PQ_GROUPS:
                    note = "el servidor respeta la preferencia del cliente: los clientes modernos obtienen PQC"
                else:
                    note = "el servidor elige el grupo clásico aunque el cliente ofrezca PQC"
                    for f in group_line:
                        f.fallback = False
                for f in group_line:
                    f.evidence += f" · {note}"
            findings += group_line

    for f in findings:
        f.line = 0
        if f.source != "certificado":
            prioritize(f, ctx)
    return findings


def ssh_kexinit(host: str, port: int, timeout: float) -> tuple[str, list[str]]:
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(b"SSH-2.0-Cuantario\r\n")
        f = s.makefile("rb")
        for _ in range(50):  # RFC 4253 permite líneas de texto antes del banner
            line = f.readline(1024)
            if not line:
                raise ConnectionError("el servidor cerró la conexión")
            if line.startswith(b"SSH-"):
                banner = line.strip().decode(errors="replace")
                break
        else:
            raise ValueError("no se recibió un banner SSH")

        header = f.read(5)
        packet_len, padding = struct.unpack(">I", header[:4])[0], header[4]
        if not 16 < packet_len < 35000:
            raise ValueError("paquete SSH inválido")
        payload = f.read(packet_len - 1)[:packet_len - 1 - padding]
        if not payload or payload[0] != 20:
            raise ValueError("el servidor no envió KEXINIT")

        p, lists = 17, []  # tipo de mensaje + cookie de 16 bytes
        for _ in range(10):
            n = struct.unpack(">I", payload[p:p + 4])[0]
            lists.append(payload[p + 4:p + 4 + n].decode(errors="replace"))
            p += 4 + n
        return banner, lists


def scan_ssh(host: str, port: int, ctx: Context, timeout: float = 5.0) -> list[Finding]:
    target = f"ssh://{host}:{port}"
    banner, lists = ssh_kexinit(host, port, timeout)
    kex = ",".join(a for a in lists[0].split(",") if not a.startswith(("ext-info", "kex-strict")))
    findings = scan_text(f"kex: {kex}", target, "ssh", "alta")
    hostkeys = scan_text(f"claves de host: {lists[1]}", target, "ssh", "alta")
    for f in hostkeys:
        f.hndl = False  # la clave de host solo firma
    findings += hostkeys
    findings += scan_text(f"cifrados: {lists[2]}", target, "ssh", "alta")
    for f in findings:
        f.evidence, f.line = f"{banner} · {f.evidence}"[:200], 0
        prioritize(f, ctx)
    return findings
