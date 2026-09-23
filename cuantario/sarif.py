# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

from . import __version__
from .model import Assessment
from .rules import Priority

INFO_URI = "https://github.com/alegarlinx/cuantario"

LEVELS = {
    Priority.CRITICAL: ("error", "9.5"),
    Priority.HIGH: ("error", "7.5"),
    Priority.MEDIUM: ("warning", "5.0"),
    Priority.LOW: ("note", "2.0"),
}

DESCRIPTIONS = {
    "certificate": ("Certificado con firma vulnerable a la computación cuántica",
                    "Certificado X.509 cuya clave pública (RSA, ECDSA, EdDSA o DSA) romperá un ordenador "
                    "cuántico. Planificar su sustitución por ML-DSA o SLH-DSA, en modo híbrido durante la transición."),
    "private-key": ("Clave privada en el repositorio",
                    "Una clave privada nunca debe guardarse en el código. Rotarla, retirarla del historial de Git "
                    "y usar un gestor de secretos o un HSM."),
}


def _describe(a: Assessment) -> tuple[str, str]:
    rule = a.detection.rule
    if rule.id in DESCRIPTIONS:
        return DESCRIPTIONS[rule.id]
    status = rule.status.label
    return (f"{rule.name}: {status}",
            f"Uso de {rule.name} detectado. Estado frente a la amenaza cuántica: {status}. "
            f"Sustituto recomendado: {rule.replacement}.")


def _fingerprint(a: Assessment) -> str:
    d = a.detection
    return hashlib.sha256(f"{d.location.target}|{d.rule.id}|{d.evidence.snippet}".encode()).hexdigest()[:32]


def _rule(a: Assessment, level: str, severity: str) -> dict[str, Any]:
    short, full = _describe(a)
    return {
        "id": f"pqc/{a.detection.rule.id}",
        "name": a.detection.rule.id.replace("-", "_"),
        "shortDescription": {"text": short},
        "fullDescription": {"text": full},
        "helpUri": INFO_URI,
        "help": {"text": full, "markdown": full},
        "defaultConfiguration": {"level": level},
        "properties": {"tags": ["security", "cryptography", "post-quantum"], "security-severity": severity},
    }


def build_sarif(assessments: Sequence[Assessment]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for a in assessments:
        d = a.detection
        if a.priority is Priority.OK or "://" in d.location.target:
            continue
        level, severity = LEVELS[a.priority]
        if d.rule.id not in rules:
            rules[d.rule.id] = _rule(a, level, severity)
        elif float(severity) > float(rules[d.rule.id]["properties"]["security-severity"]):
            rules[d.rule.id]["properties"]["security-severity"] = severity

        location: dict[str, Any] = {"physicalLocation": {"artifactLocation": {
            "uri": d.location.target.replace("\\", "/")}}}
        if d.location.line:
            location["physicalLocation"]["region"] = {"startLine": d.location.line}
        results.append({
            "ruleId": f"pqc/{d.rule.id}",
            "ruleIndex": list(rules).index(d.rule.id),
            "level": level,
            "message": {"text": f"[{a.priority.label}] {d.name} (confianza {d.confidence.label}). {a.reason} "
                                f"Sustituto: {d.rule.replacement}."},
            "locations": [location],
            "partialFingerprints": {"cuantario/v1": _fingerprint(a)},
            "properties": {"priority": a.priority.value, "confidence": d.confidence.value},
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
