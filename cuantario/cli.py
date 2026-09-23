# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from . import __version__
from .model import Context, now
from .outputs import build_cbom, build_report, readiness_scores
from .probes import parse_target, scan_ssh, scan_tls
from .rules import CONFIDENCE, PRIORITIES
from .sarif import build_sarif
from .scanner import scan

DEMO_FILES = {
    "app/crypto_utils.py": (
        '"""Utilidades de cifrado. La versión antigua usaba RSA y MD5."""\n'
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n\n"
        "# TODO: quitar RSA cuando el cliente soporte ML-KEM\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "checksum = hashlib.md5(b'datos').hexdigest()\n"
        'TLS_CIPHERS = "ECDHE-RSA-AES256-GCM-SHA384"\n'
    ),
    "config/sshd_config": "KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256\n"
                          "HostKeyAlgorithms ssh-ed25519,ssh-rsa\n",
    "config/nginx.conf": "ssl_protocols TLSv1.3;\nssl_ecdh_curve X25519MLKEM768:X25519;\n",
    "src/Main.java": 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n'
                     'Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");\n',
    "src/pq.go": "// firma de actualizaciones con ML-DSA-65\n",
}


def make_demo(root: Path) -> None:
    for rel, content in DEMO_FILES.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo.sede.example")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now())
            .not_valid_after(now() + dt.timedelta(days=365 * 6)).sign(key, hashes.SHA256()))
    (root / "certs").mkdir(exist_ok=True)
    (root / "certs" / "server.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="cuantario",
                                 description="Inventario criptográfico y priorización PQC con políticas UE.")
    ap.add_argument("ruta", nargs="?", help="carpeta o repositorio a analizar")
    ap.add_argument("--perfil", choices=["eu", "ccn"], default="eu")
    ap.add_argument("--riesgo", choices=["alto", "medio"], default="alto",
                    help="alto: infraestructura crítica, salud, finanzas, administración")
    ap.add_argument("--vida-datos", type=int, default=10, help="años que los datos deben seguir siendo secretos")
    ap.add_argument("--anos-migracion", type=int, default=5, help="años estimados para migrar")
    ap.add_argument("--ano-crqc", type=int, default=2035, help="año supuesto de un ordenador cuántico relevante")
    ap.add_argument("--confianza-min", choices=CONFIDENCE, default="baja")
    ap.add_argument("--salida", default="cuantario", help="prefijo de los ficheros de salida")
    ap.add_argument("--sarif", metavar="ARCHIVO", help="escribir también un informe SARIF 2.1.0")
    ap.add_argument("--fail-on", choices=PRIORITIES[:-1],
                    help="salir con código 1 si hay hallazgos de esta prioridad o superior")
    ap.add_argument("--tls", action="append", default=[], metavar="HOST[:PUERTO]")
    ap.add_argument("--ssh", action="append", default=[], metavar="HOST[:PUERTO]")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--demo", action="store_true", help="crear y analizar un proyecto de ejemplo")
    ap.add_argument("--version", action="version", version=f"cuantario {__version__}")
    return ap


def write_json(path: str, data: dict) -> None:
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def run(argv: list[str] | None) -> int:
    ap = parser()
    a = ap.parse_args(argv)
    if a.demo:
        root = Path("cuantario_demo")
        make_demo(root)
    elif a.ruta:
        root = Path(a.ruta)
        if not root.is_dir():
            ap.error(f"{root} no es una carpeta")
    elif a.tls or a.ssh:
        root = None
    else:
        ap.error("indica una RUTA, usa --tls/--ssh o --demo")

    ctx = Context(a.perfil, a.riesgo == "alto", a.vida_datos, a.anos_migracion, a.ano_crqc)
    findings = scan(root, ctx, a.confianza_min) if root else []
    unreachable = []
    for kind, targets, port, scan_fn in (("TLS", a.tls, 443, scan_tls), ("SSH", a.ssh, 22, scan_ssh)):
        for t in targets:
            host, p = parse_target(t, port)
            try:
                findings += scan_fn(host, p, ctx, a.timeout)
            except (OSError, ValueError) as e:
                unreachable.append(f"{kind} {host}:{p} ({e})")
                print(f"Aviso: no se pudo analizar {kind} {host}:{p}: {e}", file=sys.stderr)
    findings.sort(key=lambda f: (PRIORITIES.index(f.priority), f.location, f.line))
    target = root.resolve().name if root else "escaneo-remoto"

    outputs = [f"{a.salida}_cbom.json", f"{a.salida}_informe.md"]
    write_json(outputs[0], build_cbom(findings, target))
    Path(outputs[1]).write_text(build_report(findings, ctx, target, unreachable), encoding="utf-8")
    if a.sarif:
        write_json(a.sarif, build_sarif(findings))
        outputs.append(a.sarif)

    kex, sig = readiness_scores(findings)
    print(f"Cuantario {__version__} · {len(findings)} hallazgos en '{target}'")
    print(f"  Preparación PQC · intercambio de claves: {kex.text()} · firmas y certificados: {sig.text()}")
    for p in PRIORITIES:
        n = sum(f.priority == p for f in findings)
        if n:
            print(f"  {p:<8} {n}")
    print("Salidas: " + " · ".join(outputs))

    if a.fail_on:
        limit = PRIORITIES.index(a.fail_on)
        return int(any(PRIORITIES.index(f.priority) <= limit for f in findings))
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return run(argv)
    except BrokenPipeError:
        # `cuantario ... | head`: Python intentaría escribir otra vez al salir y fallaría de nuevo.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0
