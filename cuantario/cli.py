# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from . import __version__
from .demo import make_demo
from .model import Context, Detection, assess
from .net import NetworkError, ProbeConfig, ProtocolError, parse_target
from .outputs import build_cbom, build_report, readiness_scores
from .rules import Confidence, Priority, Profile
from .sarif import build_sarif
from .scanner import ScanResult, scan
from .ssh import scan_ssh
from .tls import scan_tls

Target = tuple[str, int]


def _target_type(default_port: int) -> Callable[[str], Target]:
    def convert(text: str) -> Target:
        try:
            return parse_target(text, default_port)
        except ValueError as e:
            raise argparse.ArgumentTypeError(str(e)) from None
    return convert


def _bounded_int(low: int, high: int, what: str) -> Callable[[str], int]:
    def convert(text: str) -> int:
        try:
            value = int(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{what} no es un número entero: {text!r}") from None
        if not low <= value <= high:
            raise argparse.ArgumentTypeError(f"{what} fuera de rango ({low}-{high}): {value}")
        return value
    return convert


def _positive_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"no es un número: {text!r}") from None
    if value <= 0:
        raise argparse.ArgumentTypeError("tiene que ser mayor que 0")
    return value


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="cuantario",
                                 description="Inventario criptográfico y priorización PQC con políticas UE.")
    ap.add_argument("ruta", nargs="?", type=Path, help="carpeta o repositorio a analizar")
    ap.add_argument("--perfil", choices=[p.value for p in Profile], default=Profile.EU.value)
    ap.add_argument("--riesgo", choices=["alto", "medio"], default="alto",
                    help="alto: infraestructura crítica, salud, finanzas, administración")
    ap.add_argument("--vida-datos", type=_bounded_int(0, 100, "vida de los datos"), default=10,
                    help="años que los datos deben seguir siendo secretos")
    ap.add_argument("--anos-migracion", type=_bounded_int(0, 100, "años de migración"), default=5,
                    help="años estimados para migrar")
    ap.add_argument("--ano-crqc", type=_bounded_int(2000, 2200, "año"), default=2035,
                    help="año supuesto de un ordenador cuántico relevante")
    ap.add_argument("--confianza-min", choices=[c.label for c in Confidence], default=Confidence.LOW.label)
    ap.add_argument("--salida", default="cuantario", help="prefijo de los ficheros de salida")
    ap.add_argument("--sarif", metavar="ARCHIVO", help="escribir también un informe SARIF 2.1.0")
    ap.add_argument("--fail-on", choices=[p.label for p in Priority if p is not Priority.OK],
                    help="salir con código 1 si hay hallazgos de esta prioridad o superior")
    ap.add_argument("--tls", action="append", default=[], type=_target_type(443), metavar="HOST[:PUERTO]")
    ap.add_argument("--ssh", action="append", default=[], type=_target_type(22), metavar="HOST[:PUERTO]")
    ap.add_argument("--timeout", type=_positive_float, default=5.0, help="segundos por conexión")
    ap.add_argument("--hosts-paralelos", type=_bounded_int(1, 32, "hosts en paralelo"), default=4)
    ap.add_argument("--intervalo", type=_positive_float, default=0.1,
                    help="segundos mínimos entre conexiones al mismo host")
    ap.add_argument("--demo", action="store_true", help="crear y analizar un proyecto de ejemplo")
    ap.add_argument("--version", action="version", version=f"cuantario {__version__}")
    return ap


def write_json(path: str, data: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _probe_hosts(args: argparse.Namespace) -> tuple[list[Detection], list[str]]:
    config = ProbeConfig(timeout=args.timeout, min_interval=args.intervalo)
    jobs: list[tuple[str, Target, Callable[[str, int, ProbeConfig], list[Detection]]]] = (
        [("TLS", t, scan_tls) for t in args.tls] + [("SSH", t, scan_ssh) for t in args.ssh])
    detections: list[Detection] = []
    unreachable = []
    with ThreadPoolExecutor(max_workers=args.hosts_paralelos) as pool:
        futures = [(kind, target, pool.submit(fn, target[0], target[1], config)) for kind, target, fn in jobs]
        for kind, (host, port), future in futures:
            try:
                detections += future.result()
            except (NetworkError, ProtocolError) as e:
                unreachable.append(f"{kind} {host}:{port} ({e})")
                print(f"Aviso: no se pudo analizar {kind} {host}:{port}: {e}", file=sys.stderr)
    return detections, unreachable


def run(argv: list[str] | None) -> int:
    ap = parser()
    args = ap.parse_args(argv)
    root: Path | None
    if args.demo:
        root = Path("cuantario_demo")
        make_demo(root)
    elif args.ruta:
        root = args.ruta
        if not root.is_dir():
            ap.error(f"{root} no es una carpeta")
    elif args.tls or args.ssh:
        root = None
    else:
        ap.error("indica una RUTA, usa --tls/--ssh o --demo")

    ctx = Context(profile=Profile(args.perfil), high_risk=args.riesgo == "alto", data_life=args.vida_datos,
                  migration=args.anos_migracion, crqc_year=args.ano_crqc)
    files = scan(root) if root else ScanResult()
    remote, unreachable = _probe_hosts(args)
    assessments = assess(files.detections + remote, ctx, Confidence.from_label(args.confianza_min))
    target = root.resolve().name if root else "escaneo-remoto"

    outputs = [f"{args.salida}_cbom.json", f"{args.salida}_informe.md"]
    write_json(outputs[0], build_cbom(assessments, target))
    Path(outputs[1]).write_text(build_report(assessments, ctx, target, unreachable, files.skipped),
                                encoding="utf-8")
    if args.sarif:
        write_json(args.sarif, build_sarif(assessments))
        outputs.append(args.sarif)

    kex, sig = readiness_scores(assessments)
    print(f"Cuantario {__version__} · {len(assessments)} hallazgos en '{target}'")
    print(f"  Preparación PQC · intercambio de claves: {kex.text()} · firmas y certificados: {sig.text()}")
    for priority in Priority:
        count = sum(a.priority is priority for a in assessments)
        if count:
            print(f"  {priority.label:<8} {count}")
    if files.skipped:
        print(f"Aviso: {len(files.skipped)} archivos omitidos (tamaño o codificación); detalle en el informe.",
              file=sys.stderr)
    print("Salidas: " + " · ".join(outputs))

    if args.fail_on:
        threshold = Priority.from_label(args.fail_on).rank
        return int(any(a.priority.rank <= threshold for a in assessments))
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return run(argv)
    except BrokenPipeError:
        # `cuantario ... | head`: Python intentaría escribir otra vez al salir y fallaría de nuevo.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
