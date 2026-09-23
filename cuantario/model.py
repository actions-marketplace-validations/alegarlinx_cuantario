# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import datetime as dt
from collections.abc import Iterable
from dataclasses import dataclass, field

from .rules import (
    RULES_BY_ID,
    Confidence,
    Primitive,
    Priority,
    Profile,
    Rule,
    SecurityUse,
    ServerPreference,
    Source,
    Status,
)


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


@dataclass(frozen=True)
class Location:
    target: str
    line: int = 0

    def __str__(self) -> str:
        return f"{self.target}:{self.line}" if self.line else self.target


@dataclass(frozen=True, kw_only=True)
class Evidence:
    snippet: str = ""
    notes: tuple[str, ...] = ()
    server_preference: ServerPreference | None = None

    def text(self) -> str:
        parts = [self.snippet, *self.notes]
        if self.server_preference:
            parts.append(self.server_preference.label)
        return " · ".join(p for p in parts if p)


@dataclass(frozen=True, kw_only=True)
class CertInfo:
    algorithm: str
    key_size: int
    signature_hash: str
    subject: str
    issuer: str
    not_before: dt.datetime
    not_after: dt.datetime
    position: int = 0  # 0 = hoja; el resto, intermedios en el orden que los envía el servidor


@dataclass(frozen=True, kw_only=True)
class Detection:
    rule: Rule
    status: Status
    harvest_risk: bool
    location: Location
    source: Source
    confidence: Confidence
    evidence: Evidence = field(default_factory=Evidence)
    fallback: bool = False
    security_use: SecurityUse = SecurityUse.SECURITY
    key_size: int | None = None
    cert: CertInfo | None = None

    @property
    def name(self) -> str:
        if self.cert is None:
            return self.rule.name
        role = "hoja" if self.cert.position == 0 else f"intermedio {self.cert.position}"
        return f"Certificado {self.cert.algorithm}-{self.cert.key_size} ({role})"

    @property
    def primitive(self) -> Primitive:
        return self.rule.primitive


def detect(rule_id: str, *, location: Location, source: Source, confidence: Confidence,
           status: Status | None = None, harvest_risk: bool | None = None, evidence: Evidence | None = None,
           fallback: bool = False, security_use: SecurityUse = SecurityUse.SECURITY,
           key_size: int | None = None, cert: CertInfo | None = None) -> Detection:
    rule = RULES_BY_ID[rule_id]
    return Detection(
        rule=rule, status=status or rule.status,
        harvest_risk=rule.harvest_risk if harvest_risk is None else harvest_risk,
        location=location, source=source, confidence=confidence, evidence=evidence or Evidence(),
        fallback=fallback, security_use=security_use, key_size=key_size, cert=cert,
    )


@dataclass(frozen=True, kw_only=True)
class Context:
    profile: Profile = Profile.EU
    high_risk: bool = True
    data_life: int = 10
    migration: int = 5
    crqc_year: int = 2035

    @property
    def mosca_violated(self) -> bool:
        return now().year + self.data_life + self.migration > self.crqc_year


@dataclass(frozen=True)
class Assessment:
    detection: Detection
    priority: Priority
    reason: str


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
    if ctx.profile is Profile.CCN and cert.algorithm == "RSA" and 1900 <= cert.key_size < 3000:
        notes.append("CCN: RSA de 1900–3000 bits solo autorizado a prestadores de confianza hasta 31/12/2026.")
    notes.append("Firma vulnerable a Shor. Roadmap UE: alto riesgo migrado antes del 31/12/2030."
                 if ctx.high_risk else "Firma vulnerable a Shor. Roadmap UE: migrar antes del 31/12/2035.")
    return priority, " ".join(notes)


def _assess(d: Detection, ctx: Context) -> tuple[Priority, str]:
    if d.status is Status.EXPOSED_SECRET:
        return Priority.CRITICAL, "Clave privada dentro del repositorio: rotarla y retirarla del historial."
    if d.cert is not None:
        return _assess_cert(d.cert, d.status, ctx)
    if d.status is Status.BROKEN and d.primitive is Primitive.HASH:
        if d.security_use is SecurityUse.NON_SECURITY:
            return Priority.LOW, "Declarado como uso no criptográfico (usedforsecurity=False)."
        if d.security_use is SecurityUse.UNKNOWN:
            return Priority.MEDIUM, (f"{d.name} está roto para usos de seguridad. Si es un checksum o una clave de "
                                     "caché no hay problema; si protege contraseñas, firmas o integridad frente a "
                                     "un atacante, hay que cambiarlo.")
    if d.status is Status.BROKEN:
        return Priority.CRITICAL, "Inseguro ya hoy, sin necesidad de un ordenador cuántico."
    if d.status is Status.VULNERABLE:
        if d.fallback:
            return Priority.MEDIUM, ("Fallback clásico junto a un grupo híbrido: aceptable durante la transición; "
                                     "retirarlo cuando todos los clientes soporten PQC.")
        if d.harvest_risk and ctx.mosca_violated:
            return Priority.CRITICAL, (f"Mosca: {now().year} + {ctx.data_life} años de vida del dato + "
                                       f"{ctx.migration} de migración > {ctx.crqc_year}. "
                                       "Los datos capturados hoy podrían descifrarse mañana.")
        if d.harvest_risk:
            return Priority.HIGH, "Expuesto a 'cosechar ahora, descifrar después'."
        if ctx.high_risk:
            return Priority.HIGH, "Firma vulnerable a Shor. Roadmap UE: alto riesgo migrado antes del 31/12/2030."
        return Priority.MEDIUM, "Firma vulnerable a Shor. Roadmap UE: migrar antes del 31/12/2035."
    if d.status is Status.WEAKENED:
        return Priority.LOW, d.rule.note or "Grover reduce su margen de seguridad; preferible la versión de 256 bits."
    return Priority.OK, "Algoritmo resistente o híbrido."


def assess_one(d: Detection, ctx: Context) -> Assessment:
    return Assessment(d, *_assess(d, ctx))


def assess(detections: Iterable[Detection], ctx: Context,
           min_confidence: Confidence = Confidence.LOW) -> list[Assessment]:
    assessed = [assess_one(d, ctx) for d in detections if d.confidence.rank <= min_confidence.rank]
    return sorted(assessed, key=lambda a: (a.priority.rank, a.detection.location.target, a.detection.location.line))
