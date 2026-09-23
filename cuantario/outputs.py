# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from . import __version__
from .model import Assessment, Context, now
from .rules import EU_MILESTONES, KEY_EXCHANGE, Primitive, Priority, Status
from .scanner import SkippedFile

MAX_ROWS = 60


@dataclass(frozen=True)
class Score:
    value: int | None
    ready: int
    total: int

    def text(self) -> str:
        return "sin datos" if self.value is None else f"{self.value}/100"


def _score(assessments: Sequence[Assessment], primitives: tuple[Primitive, ...]) -> Score:
    relevant = [a.detection for a in assessments
                if a.detection.primitive in primitives and not a.detection.fallback
                and a.detection.status in (Status.VULNERABLE, Status.RESISTANT, Status.HYBRID)]
    ready = sum(d.status in (Status.RESISTANT, Status.HYBRID) for d in relevant)
    return Score(round(100 * ready / len(relevant)) if relevant else None, ready, len(relevant))


def readiness_scores(assessments: Sequence[Assessment]) -> tuple[Score, Score]:
    return _score(assessments, KEY_EXCHANGE), _score(assessments, (Primitive.SIGNATURE,))


def _crypto_properties(a: Assessment) -> dict[str, Any]:
    cert = a.detection.cert
    if cert is not None:
        return {"assetType": "certificate", "certificateProperties": {
            "subjectName": cert.subject, "issuerName": cert.issuer,
            "notValidBefore": cert.not_before.isoformat(), "notValidAfter": cert.not_after.isoformat(),
            "certificateFormat": "X.509"}}
    return {"assetType": "algorithm", "algorithmProperties": {
        "primitive": a.detection.primitive.value, "nistQuantumSecurityLevel": a.detection.rule.nist_level}}


def build_cbom(assessments: Sequence[Assessment], target: str) -> dict[str, Any]:
    components: dict[str, dict[str, Any]] = {}
    for a in assessments:
        d = a.detection
        if d.status is Status.EXPOSED_SECRET:
            continue
        ref = f"crypto/certificate/{d.cert.subject}" if d.cert else f"crypto/algorithm/{d.rule.id}"
        if ref not in components:
            components[ref] = {
                "type": "cryptographic-asset", "bom-ref": ref, "name": d.name,
                "cryptoProperties": _crypto_properties(a), "evidence": {"occurrences": []},
                "properties": [{"name": "cuantario:status", "value": d.status.value},
                               {"name": "cuantario:priority", "value": a.priority.value},
                               {"name": "cuantario:replacement", "value": d.rule.replacement}],
            }
        occurrence: dict[str, Any] = {"location": d.location.target}
        if d.location.line:
            occurrence["line"] = d.location.line
        occurrence["additionalContext"] = f"confidence={d.confidence.value}"
        occurrences = components[ref]["evidence"]["occurrences"]
        if len(occurrences) < 500:
            occurrences.append(occurrence)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": now().isoformat(timespec="seconds"),
                     "tools": {"components": [{"type": "application", "name": "cuantario", "version": __version__}]},
                     "component": {"type": "application", "name": target, "bom-ref": "target"}},
        "components": list(components.values()),
    }


def mosca_message(assessments: Sequence[Assessment], ctx: Context) -> str:
    exposed = [a for a in assessments if a.detection.status is Status.VULNERABLE and a.detection.harvest_risk
               and not a.detection.fallback]
    if not ctx.mosca_violated:
        return "La desigualdad no se cumple con estos parámetros, pero conviene planificar la migración."
    if exposed:
        n = len(exposed)
        return (f"⚠️ **La desigualdad se cumple y hay {n} uso{'s' if n != 1 else ''} de cifrado o intercambio "
                f"de claves clásico sin protección post-cuántica: su migración es urgente.**")
    return ("La desigualdad se cumple con estos parámetros, pero no se ha encontrado cifrado ni intercambio de "
            "claves clásico sin protección post-cuántica. ✅")


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("`", "'")


def _table(assessments: Sequence[Assessment], detailed: bool) -> list[str]:
    if detailed:
        rows = ["| Activo | Ubicación | Confianza | Evidencia | Motivo | Sustituto |", "|---|---|---|---|---|---|"]
    else:
        rows = ["| Activo | Ubicación | Confianza | Evidencia |", "|---|---|---|---|"]
    for a in assessments[:MAX_ROWS]:
        d = a.detection
        row = f"| {d.name} | `{d.location}` | {d.confidence.label} | `{_cell(d.evidence.text())}` |"
        rows.append(row + (f" {a.reason} | {d.rule.replacement} |" if detailed else ""))
    if len(assessments) > MAX_ROWS:
        rows.append(f"| … | {len(assessments) - MAX_ROWS} más en el CBOM |" + " |" * (4 if detailed else 2))
    return rows + [""]


def build_report(assessments: Sequence[Assessment], ctx: Context, target: str,
                 unreachable: Sequence[str] = (), skipped: Sequence[SkippedFile] = ()) -> str:
    kex, sig = readiness_scores(assessments)
    lines = [
        f"# Informe de preparación post-cuántica: `{target}`", "",
        f"Generado por Cuantario {__version__} el {now():%d/%m/%Y %H:%M} UTC · perfil `{ctx.profile.value}` · "
        f"riesgo del sector `{'alto' if ctx.high_risk else 'medio'}`", "",
        "## Resumen", "",
        "**Índice de preparación post-cuántica**", "",
        "| Uso | Índice | Detalle |", "|---|---|---|",
        f"| Intercambio de claves y cifrado | **{kex.text()}** | "
        + (f"{kex.ready} de {kex.total} protegidos con criptografía híbrida o post-cuántica |" if kex.total
           else "no se encontraron usos |"),
        f"| Firmas y certificados | **{sig.text()}** | "
        + (f"{sig.ready} de {sig.total} resistentes |" if sig.total else "no se encontraron usos |"), "",
        "El intercambio de claves es lo urgente: lo que se cifra hoy puede capturarse y descifrarse cuando "
        "exista el ordenador cuántico. Las firmas solo corren peligro a partir de ese momento, y los certificados "
        "post-cuánticos todavía no se usan de forma general en la web, así que un índice bajo en firmas es lo "
        "habitual hoy. Los grupos clásicos que se mantienen como respaldo junto a uno híbrido no restan.", "",
        "| Prioridad | Hallazgos |", "|---|---|",
    ]
    lines += [f"| {p.label} | {sum(a.priority is p for a in assessments)} |" for p in Priority]
    lines += [
        "", "## Parámetros de Mosca", "",
        f"Vida útil de la confidencialidad: **{ctx.data_life} años** · tiempo de migración: "
        f"**{ctx.migration} años** · año estimado de un ordenador cuántico relevante: **{ctx.crqc_year}**.", "",
        mosca_message(assessments, ctx), "",
        "La columna *Confianza* indica cómo se detectó: **alta** (análisis sintáctico, certificado o protocolo), "
        "**media** (configuración o cadena de texto del programa), **baja** (búsqueda de texto en código).", "",
    ]
    for priority in Priority:
        items = [a for a in assessments if a.priority is priority]
        if not items:
            continue
        if priority is Priority.OK:
            lines += [f"## Correcto ({len(items)})", "",
                      "Criptografía resistente, híbrida o con margen suficiente. No requiere acción.", ""]
        else:
            lines += [f"## Prioridad {priority.label} ({len(items)})", ""]
        lines += _table(items, detailed=priority is not Priority.OK)
    if unreachable:
        lines += ["## Objetivos no accesibles", ""] + [f"- {u}" for u in unreachable] + [""]
    if skipped:
        lines += [f"## Archivos omitidos ({len(skipped)})", ""]
        lines += [f"- `{s.path}`: {s.reason}" for s in skipped[:MAX_ROWS]] + [""]
    lines += ["## Hitos del roadmap coordinado de la UE", ""]
    lines += [f"- **{date}**: {text}" for date, text in EU_MILESTONES]
    lines += ["", "## Aviso", "",
              "Este informe es un punto de partida para el inventario, no una auditoría ni una certificación. "
              "Los hallazgos de confianza baja deben revisarse manualmente. "
              "Contrastar siempre con la versión vigente de CCN-STIC 221 y las recomendaciones de ENISA."]
    return "\n".join(lines)
