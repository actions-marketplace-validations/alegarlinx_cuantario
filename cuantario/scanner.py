# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import codecs
import contextlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from .certs import scan_cert_file
from .model import Detection, Evidence, Location, detect
from .python_ast import scan_python
from .rules import PRIVKEY_RX, TEXT_RULES, Confidence, Primitive, SecurityUse, Source, Status

CODE_EXT = {".java", ".kt", ".js", ".ts", ".go", ".rs", ".c", ".h", ".cpp", ".cs", ".php", ".rb",
            ".swift", ".scala", ".sh", ".gradle"}
CONFIG_EXT = {".conf", ".cnf", ".cfg", ".ini", ".yaml", ".yml", ".toml", ".json", ".xml", ".properties",
              ".tf", ".env"}
CONFIG_NAMES = {"sshd_config", "ssh_config", "Dockerfile", "openssl.cnf", "requirements.txt", "go.mod",
                "package.json", "pom.xml", "Cargo.toml"}
CERT_EXT = {".pem", ".crt", ".cer", ".der"}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "target", ".tox"}
MAX_BYTES = 2_000_000

# En las listas de cifrados de OpenSSL/nginx "!MD5" o "!RC4" significa justo lo contrario: desactivado.
EXCLUDED_TOKEN_RX = re.compile(r"![\w-]+")

_BOMS = [(codecs.BOM_UTF8, "utf-8-sig"), (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16")]


@dataclass(frozen=True)
class SkippedFile:
    path: str
    reason: str


@dataclass
class ScanResult:
    detections: list[Detection] = field(default_factory=list)
    skipped: list[SkippedFile] = field(default_factory=list)


def decode(data: bytes) -> str:
    for bom, encoding in _BOMS:
        if data.startswith(bom):
            return data.decode(encoding)
    return data.decode("utf-8")


def scan_secrets(text: str, rel: str) -> list[Detection]:
    return [detect("private-key", location=Location(rel, n), source=Source.SECRET, confidence=Confidence.HIGH,
                   evidence=Evidence(snippet="[REDACTADO]"))
            for n, line in enumerate(text.splitlines(), 1) if PRIVKEY_RX.search(line)]


def scan_text(text: str, target: str, source: Source, confidence: Confidence) -> list[Detection]:
    security_use = SecurityUse.UNKNOWN if source is Source.CODE else SecurityUse.SECURITY
    detections = []
    for n, raw in enumerate(text.splitlines(), 1):
        if PRIVKEY_RX.search(raw):
            continue
        line = EXCLUDED_TOKEN_RX.sub(" ", raw)
        hybrid_seen = False
        for rule in TEXT_RULES:
            if not rule.rx.search(line):
                continue
            detections.append(detect(
                rule.id, location=Location(target, n), source=source, confidence=confidence,
                evidence=Evidence(snippet=raw.strip()[:160]), security_use=security_use,
                fallback=hybrid_seen and rule.primitive is Primitive.KEY_AGREE,
            ))
            if rule.consumes:
                line = rule.rx.sub(" ", line)
            if rule.status is Status.HYBRID:
                hybrid_seen = True
    return detections


def scan_file(path: Path, rel: str, result: ScanResult) -> None:
    ext = path.suffix.lower()
    is_config = ext in CONFIG_EXT or path.name in CONFIG_NAMES
    if ext not in CERT_EXT and ext != ".py" and not is_config and ext not in CODE_EXT:
        return
    try:
        size = path.stat().st_size
        if size > MAX_BYTES:
            result.skipped.append(SkippedFile(rel, f"supera {MAX_BYTES // 1_000_000} MB"))
            return
        data = path.read_bytes()
    except OSError as e:
        result.skipped.append(SkippedFile(rel, f"no se pudo leer: {e.strerror or e}"))
        return

    if ext in CERT_EXT:
        result.detections += scan_cert_file(data, rel)
        with contextlib.suppress(UnicodeDecodeError):
            result.detections += scan_secrets(decode(data), rel)
        return

    try:
        text = decode(data)
    except UnicodeDecodeError:
        result.skipped.append(SkippedFile(rel, "codificación no reconocida (ni UTF-8 ni UTF-16 con BOM)"))
        return

    if ext == ".py":
        found = scan_python(text, rel)
        if found is None:
            found = scan_text(text, rel, Source.CODE, Confidence.LOW)
    elif is_config:
        found = scan_text(text, rel, Source.CONFIG, Confidence.MEDIUM)
    else:
        found = scan_text(text, rel, Source.CODE, Confidence.LOW)
    result.detections += found + scan_secrets(text, rel)


def scan(root: Path) -> ScanResult:
    result = ScanResult()
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if SKIP_DIRS.intersection(rel.parts) or not path.is_file():
            continue
        scan_file(path, str(rel), result)
    return result
