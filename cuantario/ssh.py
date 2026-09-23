# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import BinaryIO

from .model import Detection, Evidence, Location, detect
from .net import PeerClosed, ProbeConfig, ProtocolError, RateLimiter, exchange, take, u8, u32
from .rules import RULES_BY_ID, TEXT_RULES, Confidence, Primitive, Rule, Source, Status

MAX_SSH_PACKET = 35_000
SSH_MSG_KEXINIT = 20
IGNORED_KEX = ("ext-info", "kex-strict")


@dataclass(frozen=True)
class KexInit:
    banner: str
    kex: list[str]
    host_keys: list[str]
    ciphers: list[str]
    macs: list[str]


def _read_exact(stream: BinaryIO, n: int) -> bytes:
    data = stream.read(n)
    if len(data) != n:
        raise ProtocolError("paquete SSH truncado")
    return data


def _talk(sock: socket.socket) -> KexInit:
    sock.sendall(b"SSH-2.0-Cuantario\r\n")
    stream = sock.makefile("rb")
    for _ in range(50):  # RFC 4253 permite líneas de texto antes del banner
        line = stream.readline(1024)
        if not line:
            raise PeerClosed
        if line.startswith(b"SSH-"):
            banner = line.strip().decode(errors="replace")
            break
    else:
        raise ProtocolError("no se recibió un banner SSH")

    header = _read_exact(stream, 5)
    packet_len, padding = u32(header, 0), header[4]
    if not 16 < packet_len < MAX_SSH_PACKET:
        raise ProtocolError(f"longitud de paquete SSH no válida ({packet_len})")
    body = _read_exact(stream, packet_len - 1)
    if padding >= len(body):
        raise ProtocolError("relleno SSH mayor que el paquete")
    payload = body[:len(body) - padding]
    if u8(payload, 0) != SSH_MSG_KEXINIT:
        raise ProtocolError("el servidor no envió KEXINIT")

    offset, lists = 17, []  # tipo de mensaje + cookie de 16 bytes
    for _ in range(10):
        size = u32(payload, offset)
        lists.append(take(payload, offset + 4, size).decode(errors="replace").split(","))
        offset += 4 + size
    return KexInit(banner, [a for a in lists[0] if not a.startswith(IGNORED_KEX)], lists[1], lists[2], lists[4])


def ssh_kexinit(host: str, port: int, config: ProbeConfig) -> KexInit:
    try:
        return exchange(host, port, config, RateLimiter(config.min_interval), _talk)
    except PeerClosed as e:
        raise ProtocolError("el servidor cerró la conexión sin enviar banner") from e


def rule_for_algorithm(name: str) -> Rule | None:
    return next((r for r in TEXT_RULES if r.rx.search(name)), None)


def _as_signature(rule: Rule | None) -> Rule | None:
    return RULES_BY_ID["rsa-signature"] if rule is not None and rule.id == "rsa" else rule


def scan_ssh(host: str, port: int, config: ProbeConfig | None = None) -> list[Detection]:
    kexinit = ssh_kexinit(host, port, config or ProbeConfig())
    location = Location(f"ssh://{host}:{port}")
    kex_rules = [(a, rule_for_algorithm(a)) for a in kexinit.kex]
    hybrid_offered = any(r and r.status is Status.HYBRID for _, r in kex_rules)

    detections = []
    groups = [
        (kex_rules, None),
        ([(a, _as_signature(rule_for_algorithm(a))) for a in kexinit.host_keys], False),
        ([(a, rule_for_algorithm(a)) for a in kexinit.ciphers], None),
        ([(a, rule_for_algorithm(a)) for a in kexinit.macs], None),
    ]
    for pairs, harvest_risk in groups:
        for algorithm, rule in pairs:
            if rule is None:
                continue
            detections.append(detect(
                rule.id, location=location, source=Source.SSH, confidence=Confidence.HIGH,
                harvest_risk=harvest_risk, evidence=Evidence(snippet=algorithm, notes=(kexinit.banner,)),
                fallback=hybrid_offered and rule.primitive is Primitive.KEY_AGREE,
            ))
    return detections
