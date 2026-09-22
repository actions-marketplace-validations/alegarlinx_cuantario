"""Hallazgos, contexto del análisis y reglas de priorización."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from .rules import BROKEN, SECRET, VULN, WEAK


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


@dataclass
class Finding:
    rule_id: str
    name: str
    status: str
    primitive: str
    location: str
    line: int
    evidence: str
    replacement: str
    source: str                 # "codigo", "config", "certificado", "secreto"
    confidence: str = "media"   # alta (AST/certificado), media (config/cadena), baja (texto en código)
    hndl: bool = False
    fallback: bool = False      # clásico ofrecido junto a un grupo híbrido
    nist_level: int = 0
    priority: str = "OK"
    reason: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class Context:
    profile: str = "eu"
    high_risk: bool = True
    data_life: int = 10
    migration: int = 5
    crqc_year: int = 2035

    @property
    def mosca_violated(self) -> bool:
        """Desigualdad de Mosca: vida del dato + tiempo de migración > años hasta el CRQC."""
        return now().year + self.data_life + self.migration > self.crqc_year


def prioritize(f: Finding, ctx: Context) -> None:
    if f.status == SECRET:
        f.priority, f.reason = "CRITICO", "Clave privada dentro del repositorio: rotarla y retirarla del historial."
    elif f.status == BROKEN:
        f.priority, f.reason = "CRITICO", "Inseguro ya hoy, sin necesidad de un ordenador cuántico."
    elif f.status == VULN and f.fallback:
        f.priority = "MEDIO"
        f.reason = ("Fallback clásico junto a un grupo híbrido: aceptable durante la transición; "
                    "retirarlo cuando todos los clientes soporten PQC.")
    elif f.status == VULN and f.hndl and ctx.mosca_violated:
        f.priority = "CRITICO"
        f.reason = (f"Mosca: {now().year} + {ctx.data_life} años de vida del dato + {ctx.migration} de migración "
                    f"> {ctx.crqc_year}. Los datos capturados hoy podrían descifrarse mañana.")
    elif f.status == VULN and f.hndl:
        f.priority, f.reason = "ALTO", "Expuesto a 'cosechar ahora, descifrar después'."
    elif f.status == VULN:
        f.priority = "ALTO" if ctx.high_risk else "MEDIO"
        f.reason = ("Firma vulnerable a Shor. Roadmap UE: alto riesgo migrado antes del 31/12/2030."
                    if ctx.high_risk else "Firma vulnerable a Shor. Roadmap UE: migrar antes del 31/12/2035.")
    elif f.status == WEAK:
        f.priority, f.reason = "BAJO", "Grover reduce su margen de seguridad; preferible la versión de 256 bits."
    else:
        f.priority, f.reason = "OK", "Algoritmo resistente o híbrido."
