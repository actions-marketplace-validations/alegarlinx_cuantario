# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import re
from pathlib import Path

from .certs import scan_cert
from .model import Finding
from .python_ast import scan_python
from .rules import PRIVKEY_RX, RULES, Confidence, Primitive, Source, Status

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


def scan_secrets(text: str, rel: str) -> list[Finding]:
    return [Finding(rule_id="private-key", name="Clave privada", status=Status.SECRET, primitive=Primitive.OTHER,
                    source=Source.SECRET, location=rel, line=n, evidence="[REDACTADO]",
                    replacement="Usar un gestor de secretos o un HSM", confidence=Confidence.HIGH)
            for n, line in enumerate(text.splitlines(), 1) if PRIVKEY_RX.search(line)]


def scan_text(text: str, rel: str, source: Source, confidence: Confidence) -> list[Finding]:
    security_use = None if source is Source.CODE else True
    findings = []
    for n, raw in enumerate(text.splitlines(), 1):
        if PRIVKEY_RX.search(raw):
            continue
        line = EXCLUDED_TOKEN_RX.sub(" ", raw)
        hybrid_seen = False
        for rule in RULES:
            if not rule.rx.search(line):
                continue
            findings.append(Finding(
                rule_id=rule.id, name=rule.name, status=rule.status, primitive=rule.primitive, source=source,
                location=rel, line=n, evidence=raw.strip()[:160], replacement=rule.replacement,
                confidence=confidence, harvest_risk=rule.harvest_risk, nist_level=rule.nist_level, note=rule.note,
                security_use=security_use,
                fallback=hybrid_seen and rule.primitive is Primitive.KEY_AGREE,
            ))
            if rule.consumes:
                line = rule.rx.sub(" ", line)
            if rule.status is Status.HYBRID:
                hybrid_seen = True
    return findings


def scan_file(path: Path, rel: str) -> list[Finding]:
    ext = path.suffix.lower()
    if ext in CERT_EXT:
        return scan_cert(path, rel) + scan_secrets(path.read_text(errors="ignore"), rel)

    text = path.read_text(encoding="utf-8", errors="ignore")
    if ext == ".py":
        found = scan_python(text, rel)
        if found is None:
            found = scan_text(text, rel, Source.CODE, Confidence.LOW)
    elif ext in CONFIG_EXT or path.name in CONFIG_NAMES:
        found = scan_text(text, rel, Source.CONFIG, Confidence.MEDIUM)
    elif ext in CODE_EXT:
        found = scan_text(text, rel, Source.CODE, Confidence.LOW)
    else:
        return []
    return found + scan_secrets(text, rel)


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if not path.is_file() or SKIP_DIRS.intersection(rel.parts):
            continue
        try:
            if path.stat().st_size <= MAX_BYTES:
                findings += scan_file(path, str(rel))
        except OSError:
            continue
    return findings
