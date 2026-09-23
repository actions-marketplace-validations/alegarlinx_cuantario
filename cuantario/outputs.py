# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import uuid
from dataclasses import dataclass

from . import __version__
from .model import Context, Finding, now
from .rules import EU_MILESTONES, HYBRID, PRIORITIES, SAFE, SECRET, VULN

KEY_EXCHANGE = ("pke", "kem", "key-agree")
SIGNATURE = ("signature",)


@dataclass
class Score:
    value: int | None
    ready: int
    total: int

    def text(self) -> str:
        return "sin datos" if self.value is None else f"{self.value}/100"


def _score(findings: list[Finding], primitives: tuple[str, ...]) -> Score:
    relevant = [f for f in findings if f.primitive in primitives and f.status in (VULN, SAFE, HYBRID)
                and not f.fallback]
    ready = sum(f.status in (SAFE, HYBRID) for f in relevant)
    return Score(round(100 * ready / len(relevant)) if relevant else None, ready, len(relevant))


# Se separan porque no tienen la misma urgencia: el intercambio de claves ya está expuesto a
# "cosechar ahora, descifrar después", y los certificados post-cuánticos aún no existen en la web.
def readiness_scores(findings: list[Finding]) -> tuple[Score, Score]:
    return _score(findings, KEY_EXCHANGE), _score(findings, SIGNATURE)


def build_cbom(findings: list[Finding], target: str) -> dict:
    comps: dict[str, dict] = {}
    for f in findings:
        if f.status == SECRET:
            continue
        is_cert = f.source == "certificado"
        ref = f"crypto/{'certificate' if is_cert else 'algorithm'}/{f.rule_id}"
        c = comps.get(ref)
        if c is None:
            if is_cert:
                crypto = {"assetType": "certificate", "certificateProperties": {
                    "subjectName": f.extra["subject"], "issuerName": f.extra["issuer"],
                    "notValidBefore": f.extra["not_before"], "notValidAfter": f.extra["not_after"],
                    "certificateFormat": "X.509"}}
            else:
                crypto = {"assetType": "algorithm", "algorithmProperties": {
                    "primitive": f.primitive, "nistQuantumSecurityLevel": f.nist_level}}
            c = comps[ref] = {"type": "cryptographic-asset", "bom-ref": ref, "name": f.name,
                              "cryptoProperties": crypto, "evidence": {"occurrences": []},
                              "properties": [{"name": "cuantario:estado", "value": f.status},
                                             {"name": "cuantario:prioridad", "value": f.priority},
                                             {"name": "cuantario:sustituto", "value": f.replacement}]}
        occ = {"location": f.location}
        if f.line:
            occ["line"] = f.line
        occ["additionalContext"] = f"confianza={f.confidence}"
        if len(c["evidence"]["occurrences"]) < 500:
            c["evidence"]["occurrences"].append(occ)
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {"timestamp": now().isoformat(timespec="seconds"),
                         "tools": {"components": [{"type": "application", "name": "cuantario",
                                                   "version": __version__}]},
                         "component": {"type": "application", "name": target, "bom-ref": "target"}},
            "components": list(comps.values())}


def mosca_message(findings: list[Finding], ctx: Context) -> str:
    exposed = [f for f in findings if f.status == VULN and f.hndl and not f.fallback]
    if not ctx.mosca_violated:
        return "La desigualdad no se cumple con estos parámetros, pero conviene planificar la migración."
    if exposed:
        n = len(exposed)
        return (f"⚠️ **La desigualdad se cumple y hay {n} uso{'s' if n != 1 else ''} de cifrado o intercambio "
                f"de claves clásico sin protección post-cuántica: su migración es urgente.**")
    return ("La desigualdad se cumple con estos parámetros, pero no se ha encontrado cifrado ni intercambio de "
            "claves clásico sin protección post-cuántica. ✅")


def build_report(findings: list[Finding], ctx: Context, target: str, unreachable: list[str] | None = None) -> str:
    counts = {p: sum(f.priority == p for f in findings) for p in PRIORITIES}
    kex, sig = readiness_scores(findings)
    L = [f"# Informe de preparación post-cuántica: `{target}`", "",
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
         "| Prioridad | Hallazgos |", "|---|---|"]
    L += [f"| {p} | {counts[p]} |" for p in PRIORITIES]
    L += ["", "## Parámetros de Mosca", "",
          f"Vida útil de la confidencialidad: **{ctx.data_life} años** · tiempo de migración: "
          f"**{ctx.migration} años** · año estimado de un ordenador cuántico relevante: **{ctx.crqc_year}**.", "",
          mosca_message(findings, ctx),
          "", "La columna *Confianza* indica cómo se detectó: **alta** (análisis sintáctico o certificado), "
          "**media** (configuración o cadena de texto del programa), **baja** (búsqueda de texto en código).", ""]
    for p in PRIORITIES[:-1]:
        items = [f for f in findings if f.priority == p]
        if not items:
            continue
        L += [f"## Prioridad {p} ({len(items)})", "",
              "| Activo | Ubicación | Confianza | Evidencia | Motivo | Sustituto |", "|---|---|---|---|---|---|"]
        for f in items[:60]:
            loc = f"{f.location}:{f.line}" if f.line else f.location
            ev = f.evidence.replace("|", "\\|").replace("`", "'")
            L.append(f"| {f.name} | `{loc}` | {f.confidence} | `{ev}` | {f.reason} | {f.replacement} |")
        if len(items) > 60:
            L.append(f"| … | {len(items) - 60} más en el CBOM | | | | |")
        L.append("")
    ok = [f for f in findings if f.priority == "OK"]
    if ok:
        L += [f"## Correcto ({len(ok)})", "",
              "Criptografía resistente, híbrida o con margen suficiente. No requiere acción.", "",
              "| Activo | Ubicación | Confianza | Evidencia |", "|---|---|---|---|"]
        for f in ok[:60]:
            loc = f"{f.location}:{f.line}" if f.line else f.location
            ev = f.evidence.replace("|", "\\|").replace("`", "'")
            L.append(f"| {f.name} | `{loc}` | {f.confidence} | `{ev}` |")
        if len(ok) > 60:
            L.append(f"| … | {len(ok) - 60} más en el CBOM | | |")
        L.append("")
    if unreachable:
        L += ["## Objetivos no accesibles", ""] + [f"- {u}" for u in unreachable] + [""]
    L += ["## Hitos del roadmap coordinado de la UE", ""]
    L += [f"- **{d}**: {t}" for d, t in EU_MILESTONES]
    L += ["", "## Aviso", "",
          "Este informe es un punto de partida para el inventario, no una auditoría ni una certificación. "
          "Los hallazgos de confianza baja deben revisarse manualmente. "
          "Contrastar siempre con la versión vigente de CCN-STIC 221 y las recomendaciones de ENISA."]
    return "\n".join(L)
