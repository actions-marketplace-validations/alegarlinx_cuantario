# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import datetime as dt
from collections.abc import Iterable
from dataclasses import dataclass, replace

from .rules import Confidence, Primitive, Priority, Source, Status


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


@dataclass(frozen=True, kw_only=True)
class CertInfo:
    algorithm: str
    key_size: int
    signature_hash: str
    subject: str
    issuer: str
    not_before: dt.datetime
    not_after: dt.datetime


@dataclass(frozen=True, kw_only=True)
class Finding:
    rule_id: str
    name: str
    status: Status
    primitive: Primitive
    source: Source
    location: str
    line: int = 0
    evidence: str = ""
    replacement: str = ""
    confidence: Confidence = Confidence.MEDIUM
    harvest_risk: bool = False
    fallback: bool = False
    nist_level: int = 0
    note: str = ""
    # None: no sabemos si el hash se usa para algo de seguridad (p. ej. un md5 en código puede ser un checksum).
    security_use: bool | None = True
    key_size: int | None = None
    cert: CertInfo | None = None
    priority: Priority | None = None
    reason: str = ""


@dataclass(frozen=True, kw_only=True)
class Context:
    profile: str = "eu"
    high_risk: bool = True
    data_life: int = 10
    migration: int = 5
    crqc_year: int = 2035

    @property
    def mosca_violated(self) -> bool:
        return now().year + self.data_life + self.migration > self.crqc_year


def _assess_cert(cert: CertInfo, status: Status, ctx: Context) -> tuple[Priority, str]:
    notes = []
    if status is Status.BROKEN:
        priority = Priority.CRITICAL
        notes.append("Parámetros inseguros ya hoy.")
    elif cert.not_after.year > 2030 and ctx.high_risk:
        priority = Priority.CRITICAL
        notes.append("Caduca después de 2030 con firma vulnerable: incumple el hito UE de alto riesgo.")
    else:
        priority = Priority.HIGH if ctx.high_risk else Priority.MEDIUM
    if cert.not_after < now():
        notes.append("Certificado ya caducado.")
    # CCN-STIC 807, anexo 1. Comprobar en cada versión de la guía si la fecha sigue vigente.
    if ctx.profile == "ccn" and cert.algorithm == "RSA" and 1900 <= cert.key_size < 3000:
        notes.append("CCN: RSA de 1900–3000 bits solo autorizado a prestadores de confianza hasta 31/12/2026.")
    notes.append("Firma vulnerable a Shor. Roadmap UE: alto riesgo migrado antes del 31/12/2030."
                 if ctx.high_risk else "Firma vulnerable a Shor. Roadmap UE: migrar antes del 31/12/2035.")
    return priority, " ".join(notes)


def _assess(f: Finding, ctx: Context) -> tuple[Priority, str]:
    if f.status is Status.SECRET:
        return Priority.CRITICAL, "Clave privada dentro del repositorio: rotarla y retirarla del historial."
    if f.cert is not None:
        return _assess_cert(f.cert, f.status, ctx)
    if f.status is Status.BROKEN and f.primitive is Primitive.HASH:
        if f.security_use is False:
            return Priority.LOW, "Declarado como uso no criptográfico (usedforsecurity=False)."
        if f.security_use is None:
            return Priority.MEDIUM, (f"{f.name} está roto para usos de seguridad. Si es un checksum o una clave de "
                                     "caché no hay problema; si protege contraseñas, firmas o integridad frente a "
                                     "un atacante, hay que cambiarlo.")
    if f.status is Status.BROKEN:
        return Priority.CRITICAL, "Inseguro ya hoy, sin necesidad de un ordenador cuántico."
    if f.status is Status.VULNERABLE:
        if f.fallback:
            return Priority.MEDIUM, ("Fallback clásico junto a un grupo híbrido: aceptable durante la transición; "
                                     "retirarlo cuando todos los clientes soporten PQC.")
        if f.harvest_risk and ctx.mosca_violated:
            return Priority.CRITICAL, (f"Mosca: {now().year} + {ctx.data_life} años de vida del dato + "
                                       f"{ctx.migration} de migración > {ctx.crqc_year}. "
                                       "Los datos capturados hoy podrían descifrarse mañana.")
        if f.harvest_risk:
            return Priority.HIGH, "Expuesto a 'cosechar ahora, descifrar después'."
        if ctx.high_risk:
            return Priority.HIGH, "Firma vulnerable a Shor. Roadmap UE: alto riesgo migrado antes del 31/12/2030."
        return Priority.MEDIUM, "Firma vulnerable a Shor. Roadmap UE: migrar antes del 31/12/2035."
    if f.status is Status.WEAK:
        return Priority.LOW, f.note or "Grover reduce su margen de seguridad; preferible la versión de 256 bits."
    return Priority.OK, "Algoritmo resistente o híbrido."


def prioritize(f: Finding, ctx: Context) -> Finding:
    priority, reason = _assess(f, ctx)
    return replace(f, priority=priority, reason=reason)


def rank(f: Finding) -> int:
    return f.priority.rank if f.priority is not None else len(Priority)


def assess(findings: Iterable[Finding], ctx: Context, min_confidence: Confidence = Confidence.LOW) -> list[Finding]:
    """Único punto donde se asigna prioridad; el resto del código solo produce hallazgos."""
    assessed = [prioritize(f, ctx) for f in findings if f.confidence.rank <= min_confidence.rank]
    return sorted(assessed, key=lambda f: (rank(f), f.location, f.line))
