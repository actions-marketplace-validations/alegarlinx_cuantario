# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from . import __version__
from .model import Context, Finding, now
from .rules import EU_MILESTONES, KEY_EXCHANGE, Primitive, Priority, Status

MAX_ROWS = 60


@dataclass(frozen=True)
class Score:
    value: int | None
    ready: int
    total: int

    def text(self) -> str:
        return "sin datos" if self.value is None else f"{self.value}/100"


def _score(findings: list[Finding], primitives: tuple[Primitive, ...]) -> Score:
    relevant = [f for f in findings
                if f.primitive in primitives and f.status in (Status.VULNERABLE, Status.SAFE, Status.HYBRID)
                and not f.fallback]
    ready = sum(f.status in (Status.SAFE, Status.HYBRID) for f in relevant)
    return Score(round(100 * ready / len(relevant)) if relevant else None, ready, len(relevant))


# Se separan porque no tienen la misma urgencia: el intercambio de claves ya está expuesto a
# "cosechar ahora, descifrar después", y los certificados post-cuánticos aún no existen en la web.
def readiness_scores(findings: list[Finding]) -> tuple[Score, Score]:
    return _score(findings, KEY_EXCHANGE), _score(findings, (Primitive.SIGNATURE,))


def _crypto_properties(f: Finding) -> dict[str, Any]:
    if f.cert is not None:
        return {"assetType": "certificate", "certificateProperties": {
            "subjectName": f.cert.subject, "issuerName": f.cert.issuer,
            "notValidBefore": f.cert.not_before.isoformat(), "notValidAfter": f.cert.not_after.isoformat(),
            "certificateFormat": "X.509"}}
    return {"assetType": "algorithm", "algorithmProperties": {
        "primitive": f.primitive.value, "nistQuantumSecurityLevel": f.nist_level}}


def build_cbom(findings: list[Finding], target: str) -> dict[str, Any]:
    components: dict[str, dict[str, Any]] = {}
    for f in findings:
        if f.status is Status.SECRET:
            continue
        ref = f"crypto/{'certificate' if f.cert else 'algorithm'}/{f.rule_id}"
        if ref not in components:
            components[ref] = {
                "type": "cryptographic-asset", "bom-ref": ref, "name": f.name,
                "cryptoProperties": _crypto_properties(f), "evidence": {"occurrences": []},
                "properties": [{"name": "cuantario:estado", "value": f.status.value},
                               {"name": "cuantario:prioridad", "value": str(f.priority)},
                               {"name": "cuantario:sustituto", "value": f.replacement}],
            }
        occurrence: dict[str, Any] = {"location": f.location}
        if f.line:
            occurrence["line"] = f.line
        occurrence["additionalContext"] = f"confianza={f.confidence.value}"
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


def mosca_message(findings: list[Finding], ctx: Context) -> str:
    exposed = [f for f in findings if f.status is Status.VULNERABLE and f.harvest_risk and not f.fallback]
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


def _table(findings: list[Finding], detailed: bool) -> list[str]:
    if detailed:
        rows = ["| Activo | Ubicación | Confianza | Evidencia | Motivo | Sustituto |", "|---|---|---|---|---|---|"]
    else:
        rows = ["| Activo | Ubicación | Confianza | Evidencia |", "|---|---|---|---|"]
    for f in findings[:MAX_ROWS]:
        loc = f"{f.location}:{f.line}" if f.line else f.location
        row = f"| {f.name} | `{loc}` | {f.confidence} | `{_cell(f.evidence)}` |"
        rows.append(row + (f" {f.reason} | {f.replacement} |" if detailed else ""))
    if len(findings) > MAX_ROWS:
        rows.append(f"| … | {len(findings) - MAX_ROWS} más en el CBOM |" + " |" * (4 if detailed else 2))
    return rows + [""]


def build_report(findings: list[Finding], ctx: Context, target: str, unreachable: list[str] | None = None) -> str:
    kex, sig = readiness_scores(findings)
    lines = [
        f"# Informe de preparación post-cuántica: `{target}`", "",
        f"Generado por Cuantario {__version__} el {now():%d/%m/%Y %H:%M} UTC · perfil `{ctx.profile}` · "
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
    lines += [f"| {p} | {sum(f.priority is p for f in findings)} |" for p in Priority]
    lines += [
        "", "## Parámetros de Mosca", "",
        f"Vida útil de la confidencialidad: **{ctx.data_life} años** · tiempo de migración: "
        f"**{ctx.migration} años** · año estimado de un ordenador cuántico relevante: **{ctx.crqc_year}**.", "",
        mosca_message(findings, ctx), "",
        "La columna *Confianza* indica cómo se detectó: **alta** (análisis sintáctico o certificado), "
        "**media** (configuración o cadena de texto del programa), **baja** (búsqueda de texto en código).", "",
    ]
    for priority in Priority:
        items = [f for f in findings if f.priority is priority]
        if not items:
            continue
        if priority is Priority.OK:
            lines += [f"## Correcto ({len(items)})", "",
                      "Criptografía resistente, híbrida o con margen suficiente. No requiere acción.", ""]
        else:
            lines += [f"## Prioridad {priority} ({len(items)})", ""]
        lines += _table(items, detailed=priority is not Priority.OK)
    if unreachable:
        lines += ["## Objetivos no accesibles", ""] + [f"- {u}" for u in unreachable] + [""]
    lines += ["## Hitos del roadmap coordinado de la UE", ""]
    lines += [f"- **{date}**: {text}" for date, text in EU_MILESTONES]
    lines += ["", "## Aviso", "",
              "Este informe es un punto de partida para el inventario, no una auditoría ni una certificación. "
              "Los hallazgos de confianza baja deben revisarse manualmente. "
              "Contrastar siempre con la versión vigente de CCN-STIC 221 y las recomendaciones de ENISA."]
    return "\n".join(lines)
