# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .certs import cert_info, link_problem
from .net import NetworkError, ProbeConfig, ProtocolError, is_ip, parse_target
from .rules import ServerPreference
from .tls import GROUPS, TlsProfile, TlsVersion, Trust, probe_tls


def load_list(path: Path) -> list[str]:
    hosts: list[str] = []
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        # Las listas de Tranco vienen como "rango,dominio".
        host = line.rsplit(",", 1)[-1].strip()
        try:
            parse_target(host, 443)
        except ValueError as e:
            raise ValueError(f"{path}:{n}: {e}") from None
        if host not in hosts:
            hosts.append(host)
    return hosts


@dataclass(frozen=True, kw_only=True)
class HostResult:
    domain: str
    scanned: str | None = None
    error: str | None = None
    tls_versions: tuple[str, ...] = ()
    pq_groups: tuple[str, ...] = ()
    classic_groups: tuple[str, ...] = ()
    preference: str | None = None
    incomplete: bool = False
    leaf_algorithm: str | None = None
    leaf_key_size: int | None = None
    leaf_expires_after_2030: bool | None = None
    chain_length: int = 0
    chain_broken: bool = False
    trust: str | None = None

    @property
    def reachable(self) -> bool:
        return self.error is None

    @property
    def hybrid(self) -> bool:
        return any(GROUPS_BY_NAME[g].rule_id == "hybrid-kem" for g in self.pq_groups)


GROUPS_BY_NAME = {g.name: g for g in GROUPS.values()}


def summarize(domain: str, profile: TlsProfile) -> HostResult:
    versions = [v.label for v in profile.legacy_versions]
    if profile.tls13:
        versions.append(TlsVersion.TLS13.label)
    leaf = cert_info(profile.chain[0]) if profile.chain else None
    broken = any(link_problem(c, profile.chain[i + 1]) for i, c in enumerate(profile.chain[:-1]))
    return HostResult(
        domain=domain, scanned=profile.host, tls_versions=tuple(versions),
        pq_groups=tuple(GROUPS[g].name for g in profile.groups if GROUPS[g].post_quantum),
        classic_groups=tuple(GROUPS[g].name for g in profile.groups if not GROUPS[g].post_quantum),
        preference=profile.preference.value if profile.preference else None,
        incomplete=bool(profile.missing),
        leaf_algorithm=leaf.algorithm if leaf else None, leaf_key_size=leaf.key_size if leaf else None,
        leaf_expires_after_2030=leaf.not_after.year > 2030 if leaf else None,
        chain_length=len(profile.chain), chain_broken=broken,
        trust=profile.trust.value if profile.chain else None,
    )


def study_host(entry: str, config: ProbeConfig) -> HostResult:
    host, port = parse_target(entry, 443)
    # Muchos dominios de las listas de popularidad solo sirven la web en www.
    try_www = not (host.startswith("www.") or is_ip(host) or port != 443)
    candidates = [host, f"www.{host}"] if try_www else [host]
    error = ""
    for candidate in candidates:
        try:
            return summarize(entry, probe_tls(candidate, port, config))
        except (NetworkError, ProtocolError) as e:
            error = str(e)
    return HostResult(domain=entry, error=error or "sin respuesta")


def run_study(domains: Sequence[str], config: ProbeConfig, workers: int,
              progress: Callable[[int, int], None] | None = None) -> list[HostResult]:
    results: list[HostResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for done, result in enumerate(pool.map(lambda d: study_host(d, config), domains), 1):
            results.append(result)
            if progress:
                progress(done, len(domains))
    return results


def save_raw(results: Sequence[HostResult], path: Path) -> None:
    path.write_text(json.dumps([asdict(r) for r in results], indent=2, ensure_ascii=False), encoding="utf-8")


def _pct(part: int, total: int) -> str:
    return f"{100 * part / total:.1f} %" if total else "—"


def _row(label: str, part: int, total: int) -> str:
    return f"| {label} | {part} | {_pct(part, total)} |"


def _error_kind(error: str) -> str:
    text = error.lower()
    if "reseteada" in text:
        return "reset repetido (posible WAF o rate limit)"
    if "timed out" in text or "timeout" in text:
        return "tiempo de espera agotado"
    if "refused" in text:
        return "conexión rechazada"
    if "name or service" in text or "nodename" in text or "getaddrinfo" in text:
        return "el dominio no resuelve"
    return "otros"


def study_report(results: Sequence[HostResult], meta: dict[str, Any]) -> str:
    ok = [r for r in results if r.reachable]
    n = len(ok)
    hybrid = [r for r in ok if r.hybrid]
    preferences = Counter(r.preference for r in hybrid)
    with_cert = [r for r in ok if r.leaf_algorithm]
    algorithms = Counter(f"{r.leaf_algorithm.split('-')[0]}" for r in with_cert if r.leaf_algorithm)
    rsa_sizes = Counter(r.leaf_key_size for r in with_cert if r.leaf_algorithm == "RSA")
    errors = Counter(_error_kind(r.error) for r in results if r.error)

    lines = [
        "# Preparación post-cuántica de TLS: resultados agregados", "",
        f"Medido el {meta['date']} con Cuantario {__version__}. {meta['source']}.", "",
        "## Muestra", "",
        "| | Dominios | % |", "|---|---|---|",
        _row("En la lista", len(results), len(results)),
        _row("Analizados", n, len(results)),
        _row("No se pudieron medir", len(results) - n, len(results)),
        "",
    ]
    if errors:
        lines += ["Motivos por los que no se pudieron medir:", ""]
        lines += [f"- {kind}: {count}" for kind, count in errors.most_common()] + [""]
    lines += [
        "Los porcentajes siguientes se calculan sobre los dominios analizados.", "",
        "## Protocolo", "",
        "| | Dominios | % |", "|---|---|---|",
        _row("Admiten TLS 1.3", sum(TlsVersion.TLS13.label in r.tls_versions for r in ok), n),
        _row("Solo hasta TLS 1.2", sum(TlsVersion.TLS13.label not in r.tls_versions for r in ok), n),
        _row("Aceptan TLS 1.0 o 1.1", sum(any(v in r.tls_versions for v in ("TLS 1.0", "TLS 1.1")) for r in ok),
             n),
        "",
        "## Intercambio de claves post-cuántico", "",
        "| | Dominios | % |", "|---|---|---|",
        _row("Admiten un grupo híbrido con ML-KEM", len(hybrid), n),
        _row("…y lo prefieren aunque el cliente pida antes el clásico",
             preferences[ServerPreference.PREFERS_PQ.value], n),
        _row("…y lo usan si el cliente lo pide primero", preferences[ServerPreference.FOLLOWS_CLIENT.value], n),
        _row("…pero eligen siempre el clásico", preferences[ServerPreference.PREFERS_CLASSICAL.value], n),
        _row("Admiten ML-KEM sin combinar", sum(any(GROUPS_BY_NAME[g].rule_id == "ml-kem" for g in r.pq_groups)
                                                 for r in ok), n),
        _row("Resultado incompleto (alguna sonda sin respuesta)", sum(r.incomplete for r in ok), n),
        "",
        "Un navegador actual obtiene protección post-cuántica en los dominios de las dos primeras filas "
        "con \"…\". En los de la tercera, el servidor la tiene configurada pero no la usa.", "",
        "## Certificados", "",
        "| | Dominios | % |", "|---|---|---|",
    ]
    lines += [_row(f"Certificado {alg}", count, len(with_cert)) for alg, count in algorithms.most_common()]
    lines += [_row(f"RSA de {size} bits", count, len(with_cert)) for size, count in sorted(rsa_sizes.items())]
    lines += [
        _row("Caducan después de 2030", sum(bool(r.leaf_expires_after_2030) for r in with_cert), len(with_cert)),
        _row("Cadena rota", sum(r.chain_broken for r in with_cert), len(with_cert)),
        _row("No validan contra el almacén de confianza",
             sum(r.trust == Trust.INVALID.value for r in with_cert), len(with_cert)),
        "",
        "Ningún certificado de la muestra puede ser post-cuántico todavía: las autoridades de certificación de la "
        "web no los emiten. Esta sección sirve como línea base.", "",
        "## Metodología", "",
        f"- Fuente de los dominios: {meta['source']}.",
        f"- Parámetros: timeout de {meta['timeout']} s por conexión, {meta['workers']} dominios en paralelo y "
        f"al menos {meta['interval']} s entre conexiones al mismo servidor.",
        "- Para cada dominio se prueba el dominio tal cual y, si no responde, con `www.` delante. Solo el "
        "puerto 443.",
        "- Unas 15 conexiones por dominio: un saludo TLS por versión antigua (1.0, 1.1, 1.2), uno por grupo de "
        "TLS 1.3 con el `key_share` vacío (el servidor responde con un HelloRetryRequest si lo admite), dos para "
        "conocer su preferencia, uno para leer la cadena y otro para validarla. No se envían datos de aplicación.",
        "- Es una foto de un momento concreto: los CDN cambian su configuración a menudo.",
        "- Los CDN y WAF pueden bloquear o limitar las mediciones; esos casos se cuentan como \"no se pudieron "
        "medir\", nunca como \"no admite\".",
        "- Grupos sondeados: " + ", ".join(g.name for g in GROUPS.values()) + ".",
        "",
        "Este informe no identifica dominios concretos a propósito.",
    ]
    return "\n".join(lines)
