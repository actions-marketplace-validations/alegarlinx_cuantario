# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import hashlib

from . import __version__
from .model import Finding
from .rules import RULES_BY_ID

INFO_URI = "https://github.com/alegarlinx/cuantario"

# security-severity es lo que usa GitHub para clasificar la alerta como crítica, alta, media o baja.
LEVELS = {"CRITICO": ("error", "9.5"), "ALTO": ("error", "7.5"), "MEDIO": ("warning", "5.0"),
          "BAJO": ("note", "2.0")}

EXTRA_RULES = {
    "certificado": ("Certificado con firma vulnerable a la computación cuántica",
                    "Certificado X.509 cuya clave pública (RSA, ECDSA, EdDSA o DSA) romperá un ordenador "
                    "cuántico. Planificar su sustitución por ML-DSA o SLH-DSA, en modo híbrido durante la transición."),
    "private-key": ("Clave privada en el repositorio",
                    "Una clave privada nunca debe guardarse en el código. Rotarla, retirarla del historial de Git "
                    "y usar un gestor de secretos o un HSM."),
}


def _rule_key(f: Finding) -> str:
    return "certificado" if f.source == "certificado" else f.rule_id


def _describe(key: str) -> tuple[str, str]:
    if key in EXTRA_RULES:
        return EXTRA_RULES[key]
    r = RULES_BY_ID.get(key)
    if r is None:
        return key, key
    return (f"{r.name}: {r.status.replace('_', ' ')}",
            f"Uso de {r.name} detectado. Estado frente a la amenaza cuántica: {r.status.replace('_', ' ')}. "
            f"Sustituto recomendado: {r.replacement}.")


def _fingerprint(f: Finding) -> str:
    # Estable entre ejecuciones aunque se muevan líneas: archivo + regla + evidencia.
    return hashlib.sha256(f"{f.location}|{_rule_key(f)}|{f.evidence}".encode()).hexdigest()[:32]


def build_sarif(findings: list[Finding]) -> dict:
    results, rules, order = [], {}, []
    for f in findings:
        # Lo analizado en vivo no tiene archivo ni línea a la que GitHub pueda apuntar.
        if f.priority == "OK" or "://" in f.location:
            continue
        key = _rule_key(f)
        level, severity = LEVELS[f.priority]
        if key not in rules:
            short, full = _describe(key)
            rules[key] = {
                "id": f"pqc/{key}",
                "name": key.replace("-", "_"),
                "shortDescription": {"text": short},
                "fullDescription": {"text": full},
                "helpUri": INFO_URI,
                "help": {"text": full, "markdown": full},
                "defaultConfiguration": {"level": level},
                "properties": {"tags": ["security", "cryptography", "post-quantum"],
                               "security-severity": severity},
            }
            order.append(key)
        elif float(severity) > float(rules[key]["properties"]["security-severity"]):
            rules[key]["properties"]["security-severity"] = severity
        location = {"physicalLocation": {"artifactLocation": {"uri": f.location.replace("\\", "/")}}}
        if f.line:
            location["physicalLocation"]["region"] = {"startLine": f.line}
        results.append({
            "ruleId": f"pqc/{key}",
            "ruleIndex": order.index(key),
            "level": level,
            "message": {"text": f"[{f.priority}] {f.name} (confianza {f.confidence}). {f.reason} "
                                f"Sustituto: {f.replacement}."},
            "locations": [location],
            "partialFingerprints": {"cuantario/v1": _fingerprint(f)},
            "properties": {"prioridad": f.priority, "confianza": f.confidence},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Cuantario", "version": __version__, "semanticVersion": __version__,
                                "informationUri": INFO_URI, "rules": [rules[k] for k in order]}},
            "results": results,
        }],
    }
