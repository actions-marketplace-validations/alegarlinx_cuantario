# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import ast
from dataclasses import replace

from .model import Finding
from .rules import RULES, RULES_BY_ID, Confidence, Primitive, Source, Status

# Se compara por sufijo sobre el nombre ya resuelto: "rsa.generate_private_key" encaja con
# "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key".
CALLS = {
    "rsa.generate_private_key": "rsa", "rsa.newkeys": "rsa", "RSA.generate": "rsa", "RSA.import_key": "rsa",
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
HASH_RULES = {"md5", "sha1"}


def import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                if name.asname:
                    aliases[name.asname] = name.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for name in node.names:
                aliases[name.asname or name.name] = f"{node.module}.{name.name}"
    return aliases


def dotted_name(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def resolve(name: str, aliases: dict[str, str]) -> str:
    head, _, rest = name.partition(".")
    full = aliases.get(head, head)
    return f"{full}.{rest}" if rest else full


def match_call(call: ast.Call, aliases: dict[str, str]) -> str | None:
    name = resolve(dotted_name(call.func), aliases)
    if name == "hashlib.new":
        if call.args and isinstance(call.args[0], ast.Constant):
            algo = str(call.args[0].value).lower().replace("-", "")
            return algo if algo in HASH_RULES else None
        return None
    for suffix, rule_id in CALLS.items():
        if name == suffix or name.endswith("." + suffix):
            return rule_id
    return None


def keyword_constant(call: ast.Call, *names: str) -> object:
    for kw in call.keywords:
        if kw.arg in names and isinstance(kw.value, ast.Constant):
            return kw.value.value
    return None


def make_finding(rule_id: str, rel: str, line: int, lines: list[str], confidence: Confidence) -> Finding:
    rule = RULES_BY_ID[rule_id]
    return Finding(
        rule_id=rule.id, name=rule.name, status=rule.status, primitive=rule.primitive, source=Source.CODE,
        location=rel, line=line, evidence=lines[line - 1].strip()[:160] if 0 < line <= len(lines) else "",
        replacement=rule.replacement, confidence=confidence, harvest_risk=rule.harvest_risk,
        nist_level=rule.nist_level, note=rule.note, security_use=None,
    )


def scan_python(source: str, rel: str) -> list[Finding] | None:
    """None si no es Python válido; el llamador usa entonces el detector de texto."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None

    lines = source.splitlines()
    aliases = import_aliases(tree)
    found: dict[tuple[str, int], Finding] = {}

    def add(finding: Finding) -> None:
        key = (finding.rule_id, finding.line)
        if key not in found or finding.confidence is Confidence.HIGH:
            found[key] = finding

    # Los docstrings hablan de algoritmos sin usarlos; solo interesan las cadenas que son datos.
    docstrings = {id(n.value) for n in ast.walk(tree)
                  if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)}

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            rule_id = match_call(node, aliases)
            if rule_id is None:
                continue
            finding = make_finding(rule_id, rel, node.lineno, lines, Confidence.HIGH)
            size = keyword_constant(node, "key_size", "bits")
            if isinstance(size, int):
                weak_rsa = rule_id == "rsa" and size < 2048
                finding = replace(finding, key_size=size, status=Status.BROKEN if weak_rsa else finding.status)
            if rule_id in HASH_RULES and keyword_constant(node, "usedforsecurity") is False:
                finding = replace(finding, security_use=False)
            add(finding)

        elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
              and id(node) not in docstrings and len(node.value) < 2000):
            text, hybrid_seen = node.value, False
            for rule in RULES:
                if not rule.rx.search(text):
                    continue
                finding = make_finding(rule.id, rel, node.lineno, lines, Confidence.MEDIUM)
                add(replace(finding, fallback=hybrid_seen and rule.primitive is Primitive.KEY_AGREE))
                if rule.consumes:
                    text = rule.rx.sub(" ", text)
                if rule.status is Status.HYBRID:
                    hybrid_seen = True
    return sorted(found.values(), key=lambda f: f.line)
