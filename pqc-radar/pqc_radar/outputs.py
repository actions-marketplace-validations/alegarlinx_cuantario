"""Salidas: CBOM (CycloneDX 1.6) e informe de migración en Markdown."""
from __future__ import annotations

import uuid

from . import __version__
from .model import Context, Finding, now
from .rules import EU_MILESTONES, HYBRID, PRIORITIES, SAFE, SECRET, VULN

PUBLIC_KEY = ("pke", "kem", "key-agree", "signature")


def readiness_score(findings: list[Finding]) -> tuple[int, int, int]:
    relevant = [f for f in findings if f.primitive in PUBLIC_KEY and f.status in (VULN, SAFE, HYBRID)]
    ready = sum(f.status in (SAFE, HYBRID) for f in relevant)
    score = round(100 * ready / len(relevant)) if relevant else 100
    return score, ready, len(relevant)


def build_cbom(findings: list[Finding], target: str) -> dict:
    comps: dict[str, dict] = {}
    for f in findings:
        if f.status == SECRET:
            continue  # los secretos nunca van al CBOM
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
                              "properties": [{"name": "pqc-radar:estado", "value": f.status},
                                             {"name": "pqc-radar:prioridad", "value": f.priority},
                                             {"name": "pqc-radar:sustituto", "value": f.replacement}]}
        occ = {"location": f.location}
        if f.line:
            occ["line"] = f.line
        occ["additionalContext"] = f"confianza={f.confidence}"
        if len(c["evidence"]["occurrences"]) < 500:
            c["evidence"]["occurrences"].append(occ)
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {"timestamp": now().isoformat(timespec="seconds"),
                         "tools": {"components": [{"type": "application", "name": "pqc-radar",
                                                   "version": __version__}]},
                         "component": {"type": "application", "name": target, "bom-ref": "target"}},
            "components": list(comps.values())}


def build_report(findings: list[Finding], ctx: Context, target: str) -> str:
    counts = {p: sum(f.priority == p for f in findings) for p in PRIORITIES}
    score, ready, total = readiness_score(findings)
    L = [f"# Informe de preparación post-cuántica: `{target}`", "",
         f"Generado por PQC-Radar {__version__} el {now():%d/%m/%Y %H:%M} UTC · perfil `{ctx.profile}` · "
         f"riesgo del sector `{'alto' if ctx.high_risk else 'medio'}`", "",
         "## Resumen", "",
         f"**Índice de preparación PQC (clave pública): {score}/100** "
         f"({ready} de {total} usos de clave pública son resistentes o híbridos).", "",
         "| Prioridad | Hallazgos |", "|---|---|"]
    L += [f"| {p} | {counts[p]} |" for p in PRIORITIES]
    L += ["", "## Parámetros de Mosca", "",
          f"Vida útil de la confidencialidad: **{ctx.data_life} años** · tiempo de migración: "
          f"**{ctx.migration} años** · año estimado de un ordenador cuántico relevante: **{ctx.crqc_year}**.", "",
          ("⚠️ **La desigualdad se cumple: los intercambios de clave vulnerables ya son urgentes.**"
           if ctx.mosca_violated else "La desigualdad no se cumple con estos parámetros, pero conviene planificar."),
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
    L += ["## Hitos del roadmap coordinado de la UE", ""]
    L += [f"- **{d}**: {t}" for d, t in EU_MILESTONES]
    L += ["", "## Aviso", "",
          "Este informe es un punto de partida para el inventario, no una auditoría ni una certificación. "
          "Los hallazgos de confianza baja deben revisarse manualmente. "
          "Contrastar siempre con la versión vigente de CCN-STIC 221 y las recomendaciones de ENISA."]
    return "\n".join(L)
