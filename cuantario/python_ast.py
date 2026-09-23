# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import ast
from dataclasses import dataclass, field

from .model import Detection, Evidence, Location, detect
from .rules import TEXT_RULES, Confidence, Primitive, SecurityUse, Source, Status

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
SHADOWED = ""  # nombre redefinido localmente con algo que no es una importación conocida


def dotted_name(node: ast.AST) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def rule_for(qualified: str) -> str | None:
    for suffix, rule_id in CALLS.items():
        if qualified == suffix or qualified.endswith("." + suffix):
            return rule_id
    return None


def keyword_constant(call: ast.Call, *names: str) -> object:
    for kw in call.keywords:
        if kw.arg in names and isinstance(kw.value, ast.Constant):
            return kw.value.value
    return None


@dataclass
class _Scope:
    is_class: bool = False
    names: dict[str, str] = field(default_factory=dict)


class _Visitor(ast.NodeVisitor):
    # Recorrido en orden de aparición con una pila de ámbitos. No sigue el flujo de control
    # (if/else, bucles): se queda con la última asignación vista, que es el caso habitual.

    def __init__(self, rel: str, lines: list[str], docstrings: set[int]) -> None:
        self.rel, self.lines, self.docstrings = rel, lines, docstrings
        self.scopes = [_Scope()]
        self.found: dict[tuple[str, int], Detection] = {}

    def bind(self, name: str, qualified: str) -> None:
        self.scopes[-1].names[name] = qualified

    def lookup(self, name: str) -> str | None:
        for depth, scope in enumerate(reversed(self.scopes)):
            if scope.is_class and depth > 0:
                continue
            if name in scope.names:
                return scope.names[name]
        return None

    def resolve(self, node: ast.AST) -> str | None:
        name = dotted_name(node)
        if name is None:
            return None
        head, _, rest = name.partition(".")
        bound = self.lookup(head)
        if bound == SHADOWED:
            return None
        base = bound or head
        return f"{base}.{rest}" if rest else base

    def add(self, finding: Detection) -> None:
        key = (finding.rule.id, finding.location.line)
        if key not in self.found or finding.confidence is Confidence.HIGH:
            self.found[key] = finding

    def evidence(self, line: int) -> Evidence:
        return Evidence(snippet=self.lines[line - 1].strip()[:160] if 0 < line <= len(self.lines) else "")

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self.bind(alias.asname, alias.name)
            else:
                self.bind(alias.name.partition(".")[0], alias.name.partition(".")[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            qualified = f"{node.module}.{alias.name}" if node.module else SHADOWED
            self.bind(alias.asname or alias.name, qualified)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        target = self.resolve(node.value) if isinstance(node.value, (ast.Name, ast.Attribute)) else None
        alias = target if target and rule_for(target) else SHADOWED
        for t in node.targets:
            if isinstance(t, ast.Name):
                self.bind(t.id, alias)
            else:
                self.visit(t)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Store):
            self.bind(node.id, SHADOWED)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> None:
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if default is not None:
                self.visit(default)
        if not isinstance(node, ast.Lambda):
            for decorator in node.decorator_list:
                self.visit(decorator)
            self.bind(node.name, SHADOWED)
        self.scopes.append(_Scope())
        args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs, node.args.vararg, node.args.kwarg]
        for arg in args:
            if arg is not None:
                self.bind(arg.arg, SHADOWED)
        body = [node.body] if isinstance(node, ast.Lambda) else node.body
        for stmt in body:
            self.visit(stmt)
        self.scopes.pop()

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function
    visit_Lambda = _visit_function

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expr in [*node.decorator_list, *node.bases]:
            self.visit(expr)
        self.bind(node.name, SHADOWED)
        self.scopes.append(_Scope(is_class=True))
        for stmt in node.body:
            self.visit(stmt)
        self.scopes.pop()

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)
        qualified = self.resolve(node.func)
        if qualified is None:
            return
        if qualified == "hashlib.new":
            algo = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else None
            rule_id = str(algo).lower().replace("-", "") if algo is not None else None
            if rule_id not in HASH_RULES:
                return
        else:
            rule_id = rule_for(qualified)
        if rule_id is None:
            return

        size = keyword_constant(node, "key_size", "bits")
        key_size = size if isinstance(size, int) else None
        status = Status.BROKEN if rule_id == "rsa" and key_size is not None and key_size < 2048 else None
        security_use = SecurityUse.UNKNOWN
        if rule_id in HASH_RULES and keyword_constant(node, "usedforsecurity") is False:
            security_use = SecurityUse.NON_SECURITY
        self.add(detect(rule_id, location=Location(self.rel, node.lineno), source=Source.CODE,
                        confidence=Confidence.HIGH, evidence=self.evidence(node.lineno), status=status,
                        key_size=key_size, security_use=security_use))

    def visit_Constant(self, node: ast.Constant) -> None:
        if not isinstance(node.value, str) or id(node) in self.docstrings or len(node.value) >= 2000:
            return
        text, hybrid_seen = node.value, False
        for rule in TEXT_RULES:
            if not rule.rx.search(text):
                continue
            self.add(detect(rule.id, location=Location(self.rel, node.lineno), source=Source.CODE,
                            confidence=Confidence.MEDIUM, evidence=self.evidence(node.lineno),
                            security_use=SecurityUse.UNKNOWN,
                            fallback=hybrid_seen and rule.primitive is Primitive.KEY_AGREE))
            if rule.consumes:
                text = rule.rx.sub(" ", text)
            if rule.status is Status.HYBRID:
                hybrid_seen = True


def scan_python(source: str, rel: str) -> list[Detection] | None:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    docstrings = {id(n.value) for n in ast.walk(tree)
                  if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)}
    visitor = _Visitor(rel, source.splitlines(), docstrings)
    visitor.visit(tree)
    return sorted(visitor.found.values(), key=lambda d: d.location.line)
