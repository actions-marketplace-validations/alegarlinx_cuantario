# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import hashlib
from typing import Any

from . import __version__
from .model import Finding
from .rules import RULES_BY_ID, Priority

INFO_URI = "https://github.com/alegarlinx/cuantario"

LEVELS = {
    Priority.CRITICAL: ("error", "9.5"),
    Priority.HIGH: ("error", "7.5"),
    Priority.MEDIUM: ("warning", "5.0"),
    Priority.LOW: ("note", "2.0"),
}

EXTRA_RULES = {
    "certificado": ("Certificado con firma vulnerable a la computación cuántica",
                    "Certificado X.509 cuya clave pública (RSA, ECDSA, EdDSA o DSA) romperá un ordenador "
                    "cuántico. Planificar su sustitución por ML-DSA o SLH-DSA, en modo híbrido durante la transición."),
    "private-key": ("Clave privada en el repositorio",
                    "Una clave privada nunca debe guardarse en el código. Rotarla, retirarla del historial de Git "
                    "y usar un gestor de secretos o un HSM."),
}


def _rule_key(f: Finding) -> str:
    return "certificado" if f.cert else f.rule_id


def _describe(key: str) -> tuple[str, str]:
    if key in EXTRA_RULES:
        return EXTRA_RULES[key]
    rule = RULES_BY_ID.get(key)
    if rule is None:
        return key, key
    status = rule.status.value.replace("_", " ")
    return (f"{rule.name}: {status}",
            f"Uso de {rule.name} detectado. Estado frente a la amenaza cuántica: {status}. "
            f"Sustituto recomendado: {rule.replacement}.")


def _fingerprint(f: Finding) -> str:
    # Estable entre ejecuciones aunque se muevan líneas: archivo + regla + evidencia.
    return hashlib.sha256(f"{f.location}|{_rule_key(f)}|{f.evidence}".encode()).hexdigest()[:32]


def _rule(key: str, level: str, severity: str) -> dict[str, Any]:
    short, full = _describe(key)
    return {
        "id": f"pqc/{key}",
        "name": key.replace("-", "_"),
        "shortDescription": {"text": short},
        "fullDescription": {"text": full},
        "helpUri": INFO_URI,
        "help": {"text": full, "markdown": full},
        "defaultConfiguration": {"level": level},
        "properties": {"tags": ["security", "cryptography", "post-quantum"], "security-severity": severity},
    }


def build_sarif(findings: list[Finding]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in findings:
        # Lo analizado en vivo no tiene archivo ni línea a la que GitHub pueda apuntar.
        if f.priority is None or f.priority is Priority.OK or "://" in f.location:
            continue
        key = _rule_key(f)
        level, severity = LEVELS[f.priority]
        if key not in rules:
            rules[key] = _rule(key, level, severity)
        elif float(severity) > float(rules[key]["properties"]["security-severity"]):
            rules[key]["properties"]["security-severity"] = severity

        location: dict[str, Any] = {"physicalLocation": {"artifactLocation": {"uri": f.location.replace("\\", "/")}}}
        if f.line:
            location["physicalLocation"]["region"] = {"startLine": f.line}
        results.append({
            "ruleId": f"pqc/{key}",
            "ruleIndex": list(rules).index(key),
            "level": level,
            "message": {"text": f"[{f.priority}] {f.name} (confianza {f.confidence}). {f.reason} "
                                f"Sustituto: {f.replacement}."},
            "locations": [location],
            "partialFingerprints": {"cuantario/v1": _fingerprint(f)},
            "properties": {"prioridad": f.priority.value, "confianza": f.confidence.value},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Cuantario", "version": __version__, "semanticVersion": __version__,
                                "informationUri": INFO_URI, "rules": list(rules.values())}},
            "results": results,
        }],
    }
