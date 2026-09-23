# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import ast

from .model import Finding
from .rules import BROKEN, RULES, RULES_BY_ID

# Se compara por sufijo para cubrir cualquier forma de importar: "rsa.generate_private_key"
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


def dotted_name(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def match_call(call: ast.Call) -> str | None:
    name = dotted_name(call.func)
    if name == "hashlib.new" and call.args and isinstance(call.args[0], ast.Constant):
        algo = str(call.args[0].value).lower().replace("-", "")
        return algo if algo in ("md5", "sha1") else None
    for suffix, rule_id in CALLS.items():
        if name == suffix or name.endswith("." + suffix):
            return rule_id
    return None


def key_size(call: ast.Call) -> int | None:
    for kw in call.keywords:
        if kw.arg in ("key_size", "bits") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
            return kw.value.value
    return None


def make_finding(rule_id: str, rel: str, line: int, lines: list[str], confidence: str) -> Finding:
    r = RULES_BY_ID[rule_id]
    evidence = lines[line - 1].strip()[:160] if 0 < line <= len(lines) else ""
    return Finding(r.id, r.name, r.status, r.primitive, rel, line, evidence, r.replacement, "codigo",
                   confidence=confidence, hndl=r.hndl, nist_level=r.nist_level)


def scan_python(source: str, rel: str) -> list[Finding] | None:
    """None si no es Python válido; el llamador usa entonces el detector de texto."""
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

    # Los docstrings hablan de algoritmos sin usarlos; solo interesan las cadenas que son datos.
    docstrings = {id(n.value) for n in ast.walk(tree)
                  if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)}

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            rule_id = match_call(node)
            if not rule_id:
                continue
            f = make_finding(rule_id, rel, node.lineno, lines, "alta")
            size = key_size(node)
            if size:
                f.extra["key_size"] = size
                if rule_id == "rsa" and size < 2048:
                    f.status = BROKEN
            add(f)
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
              and id(node) not in docstrings and len(node.value) < 2000):
            text, hybrid_seen = node.value, False
            for r in RULES:
                if r.rx.search(text):
                    f = make_finding(r.id, rel, node.lineno, lines, "media")
                    f.fallback = hybrid_seen and r.primitive == "key-agree"
                    add(f)
                    if r.consumes:
                        text, hybrid_seen = r.rx.sub(" ", text), True
    return sorted(found.values(), key=lambda f: f.line)
