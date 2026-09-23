# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import ipaddress
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

T = TypeVar("T")


class ProtocolError(ValueError):
    pass


class PeerClosed(Exception):
    pass


class NetworkError(OSError):
    pass


# Un RST puede venir de un WAF, de un rate limit o de un balanceador, no solo del servidor:
# se reintenta, y si persiste se informa como error de red, nunca como "no soportado".
TRANSIENT = (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)


@dataclass(frozen=True, kw_only=True)
class ProbeConfig:
    timeout: float = 5.0
    retries: int = 2
    backoff: float = 0.5
    workers: int = 3
    min_interval: float = 0.1


class RateLimiter:
    def __init__(self, min_interval: float) -> None:
        self._interval = min_interval
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            start = max(time.monotonic(), self._next)
            self._next = start + self._interval
        delay = start - time.monotonic()
        if delay > 0:
            time.sleep(delay)


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
            raise PeerClosed
        buf += chunk
    return buf


def exchange(host: str, port: int, config: ProbeConfig, limiter: RateLimiter,
             talk: Callable[[socket.socket], T]) -> T:
    last: OSError | None = None
    for attempt in range(config.retries + 1):
        limiter.wait()
        try:
            with socket.create_connection((host, port), timeout=config.timeout) as sock:
                return talk(sock)
        except TRANSIENT as e:
            last = e
            if attempt < config.retries:
                time.sleep(config.backoff * 2 ** attempt)
        except OSError as e:
            raise NetworkError(str(e) or type(e).__name__) from e
    raise NetworkError(f"conexión reseteada {config.retries + 1} veces ({last})")


def u8(buf: bytes, offset: int) -> int:
    if offset >= len(buf):
        raise ProtocolError("mensaje truncado")
    return buf[offset]


def u16(buf: bytes, offset: int) -> int:
    return int.from_bytes(take(buf, offset, 2), "big")


def u24(buf: bytes, offset: int) -> int:
    return int.from_bytes(take(buf, offset, 3), "big")


def u32(buf: bytes, offset: int) -> int:
    return int.from_bytes(take(buf, offset, 4), "big")


def take(buf: bytes, offset: int, n: int) -> bytes:
    if n < 0 or offset + n > len(buf):
        raise ProtocolError("mensaje truncado")
    return buf[offset:offset + n]
