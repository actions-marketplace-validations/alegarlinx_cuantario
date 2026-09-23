# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

from pathlib import Path

from .certs import scan_cert
from .model import Context, Finding, prioritize
from .python_ast import scan_python
from .rules import CONFIDENCE, PRIORITIES, PRIVKEY_RX, RULES, SECRET

CODE_EXT = {".java", ".kt", ".js", ".ts", ".go", ".rs", ".c", ".h", ".cpp", ".cs", ".php", ".rb",
            ".swift", ".scala", ".sh", ".gradle"}
CONFIG_EXT = {".conf", ".cnf", ".cfg", ".ini", ".yaml", ".yml", ".toml", ".json", ".xml", ".properties",
              ".tf", ".env"}
CONFIG_NAMES = {"sshd_config", "ssh_config", "Dockerfile", "openssl.cnf", "requirements.txt", "go.mod",
                "package.json", "pom.xml", "Cargo.toml"}
CERT_EXT = {".pem", ".crt", ".cer", ".der"}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "target", ".tox"}
MAX_BYTES = 2_000_000


def scan_secrets(text: str, rel: str) -> list[Finding]:
    return [Finding("private-key", "Clave privada", SECRET, "other", rel, n, "[REDACTADO]",
                    "Usar un gestor de secretos o un HSM", "secreto", confidence="alta")
            for n, line in enumerate(text.splitlines(), 1) if PRIVKEY_RX.search(line)]


def scan_text(text: str, rel: str, source: str, confidence: str) -> list[Finding]:
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        if PRIVKEY_RX.search(raw):
            continue
        # Los híbridos se borran de la línea tras detectarlos para que "X25519MLKEM768" no cuente
        # también como X25519. Lo clásico que quede en la misma línea es un fallback.
        line, hybrid_seen = raw, False
        for r in RULES:
            if not r.rx.search(line):
                continue
            out.append(Finding(r.id, r.name, r.status, r.primitive, rel, n, raw.strip()[:160], r.replacement,
                               source, confidence=confidence, hndl=r.hndl, nist_level=r.nist_level,
                               fallback=hybrid_seen and r.primitive == "key-agree"))
            if r.consumes:
                line, hybrid_seen = r.rx.sub(" ", line), True
    return out


def scan_file(path: Path, rel: str, ctx: Context) -> list[Finding]:
    ext = path.suffix.lower()
    if ext in CERT_EXT:
        return scan_cert(path, rel, ctx) + scan_secrets(path.read_text(errors="ignore"), rel)

    text = path.read_text(encoding="utf-8", errors="ignore")
    if ext == ".py":
        found = scan_python(text, rel)
        if found is None:
            found = scan_text(text, rel, "codigo", "baja")
    elif ext in CONFIG_EXT or path.name in CONFIG_NAMES:
        found = scan_text(text, rel, "config", "media")
    elif ext in CODE_EXT:
        found = scan_text(text, rel, "codigo", "baja")
    else:
        return []
    return found + scan_secrets(text, rel)


def scan(root: Path, ctx: Context, min_confidence: str = "baja") -> list[Finding]:
    limit = CONFIDENCE.index(min_confidence)
    findings: list[Finding] = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if not p.is_file() or SKIP_DIRS.intersection(rel.parts):
            continue
        try:
            if p.stat().st_size <= MAX_BYTES:
                findings += scan_file(p, str(rel), ctx)
        except OSError:
            continue

    for f in findings:
        if f.source != "certificado":
            prioritize(f, ctx)
    findings = [f for f in findings if CONFIDENCE.index(f.confidence) <= limit]
    findings.sort(key=lambda f: (PRIORITIES.index(f.priority), f.location, f.line))
    return findings
