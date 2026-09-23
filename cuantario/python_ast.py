# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
"""Detector para Python basado en el árbol sintáctico (AST).

En lugar de buscar palabras en el texto, entiende la estructura del programa:
ignora comentarios y nombres de variables, y solo informa de llamadas reales
a librerías criptográficas (cryptography, PyCryptodome, hashlib) y de cadenas
de configuración (p. ej. listas de cifrados TLS).
"""
from __future__ import annotations

import ast

from .model import Finding
from .rules import RULES, RULES_BY_ID

# Final del nombre de la llamada -> regla. Se compara por sufijo: "rsa.generate_private_key"
# encaja con "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key".
CALLS = {
    "rsa.generate_private_key": "rsa", "RSA.generate": "rsa", "RSA.import_key": "rsa",
    "RSA.importKey": "rsa", "padding.OAEP": "rsa", "PKCS1_OAEP.new": "rsa",
    "ec.generate_private_key": "ecdsa", "ECC.generate": "ecdsa", "ec.ECDSA": "ecdsa", "DSS.new": "ecdsa",
    "ec.ECDH": "ecdh", "X25519PrivateKey.generate": "ecdh", "X448PrivateKey.generate": "ecdh",
    "Ed25519PrivateKey.generate": "eddsa", "Ed448PrivateKey.generate": "eddsa",
    "dsa.generate_private_key": "dsa", "DSA.generate": "dsa",
    "dh.generate_parameters": "dh",
    "hashlib.md5": "md5", "MD5.new": "md5", "hashes.MD5": "md5",
    "hashlib.sha1": "sha1", "SHA1.new": "sha1", "hashes.SHA1": "sha1",
    "algorithms.TripleDES": "3des", "DES3.new": "3des", "DES.new": "des",
    "algorithms.ARC4": "rc4", "ARC4.new": "rc4",
}
HASHLIB_NEW = {"md5": "md5", "sha1": "sha1"}


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _match_call(name: str) -> str | None:
    for suffix, rule_id in CALLS.items():
        if name == suffix or name.endswith("." + suffix):
            return rule_id
    return None


def _key_size(call: ast.Call) -> int | None:
    for kw in call.keywords:
        if kw.arg in ("key_size", "bits") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
            return kw.value.value
    return None


def _make(rule_id: str, rel: str, line: int, lines: list[str], confidence: str, extra: dict | None = None) -> Finding:
    r = RULES_BY_ID[rule_id]
    ev = lines[line - 1].strip()[:160] if 0 < line <= len(lines) else ""
    return Finding(r.id, r.name, r.status, r.primitive, rel, line, ev, r.replacement, "codigo",
                   confidence=confidence, hndl=r.hndl, nist_level=r.nist_level, extra=extra or {})


def scan_python(source: str, rel: str) -> list[Finding] | None:
    """Devuelve los hallazgos, o None si el archivo no es Python válido (se usará el detector de texto)."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    lines = source.splitlines()
    found: dict[tuple[str, int], Finding] = {}

    def add(f: Finding) -> None:
        key = (f.rule_id, f.line)
        if key not in found or f.confidence == "alta":
            found[key] = f

    # Las cadenas sueltas (docstrings) son documentación, no configuración: se ignoran.
    doc_ids = {id(n.value) for n in ast.walk(tree)
               if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)}

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            rule_id = _match_call(name)
            if name == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant):
                rule_id = HASHLIB_NEW.get(str(node.args[0].value).lower().replace("-", ""), rule_id)
            if rule_id:
                size = _key_size(node)
                f = _make(rule_id, rel, node.lineno, lines, "alta", {"key_size": size} if size else None)
                if rule_id == "rsa" and size and size < 2048:
                    f.status = "roto_hoy"
                add(f)
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
              and id(node) not in doc_ids and len(node.value) < 2000):
            # Cadenas: listas de cifrados, nombres de algoritmos en configuración, etc.
            text, hybrid_seen = node.value, False
            for r in RULES:
                if r.rx.search(text):
                    f = _make(r.id, rel, node.lineno, lines, "media")
                    f.fallback = hybrid_seen and r.primitive == "key-agree"
                    add(f)
                    if r.consumes:
                        text, hybrid_seen = r.rx.sub(" ", text), True
    return sorted(found.values(), key=lambda f: f.line)
