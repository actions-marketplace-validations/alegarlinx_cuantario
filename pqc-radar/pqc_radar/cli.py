# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
"""Interfaz de línea de comandos."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

from . import __version__
from .certs import HAS_CRYPTO
from .model import Context, now
from .outputs import build_cbom, build_report, readiness_score
from .rules import CONFIDENCE, PRIORITIES
from .probes import parse_target, scan_ssh, scan_tls
from .sarif import build_sarif
from .scanner import scan

DEMO_FILES = {
    "app/crypto_utils.py": (
        '"""Utilidades. Antes usábamos RSA y MD5 (este comentario NO debe detectarse)."""\n'
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n\n"
        "# TODO: quitar RSA  <- comentario, ignorado por el análisis sintáctico\n"
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
    if HAS_CRYPTO:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo.sede.example")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now())
                .not_valid_after(now() + dt.timedelta(days=365 * 6)).sign(key, hashes.SHA256()))
        (root / "certs").mkdir(exist_ok=True)
        (root / "certs" / "server.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pqc-radar",
                                 description="Inventario criptográfico y priorización PQC con políticas UE.")
    ap.add_argument("ruta", nargs="?", help="Carpeta o repositorio a analizar")
    ap.add_argument("--perfil", choices=["eu", "ccn"], default="eu")
    ap.add_argument("--riesgo", choices=["alto", "medio"], default="alto",
                    help="alto: infraestructura crítica, salud, finanzas, administración")
    ap.add_argument("--vida-datos", type=int, default=10, help="Años que los datos deben seguir siendo secretos")
    ap.add_argument("--anos-migracion", type=int, default=5, help="Años estimados para migrar")
    ap.add_argument("--ano-crqc", type=int, default=2035, help="Año supuesto de un ordenador cuántico relevante")
    ap.add_argument("--confianza-min", choices=CONFIDENCE, default="baja",
                    help="Descartar hallazgos por debajo de esta confianza")
    ap.add_argument("--salida", default="pqc_radar", help="Prefijo de los ficheros de salida")
    ap.add_argument("--sarif", metavar="ARCHIVO", help="Generar también un informe SARIF 2.1.0 (GitHub Code Scanning)")
    ap.add_argument("--fail-on", choices=PRIORITIES[:-1],
                    help="Código de salida 1 si hay hallazgos de esta prioridad o superior (para CI)")
    ap.add_argument("--tls", action="append", default=[], metavar="HOST[:PUERTO]",
                    help="Servidor TLS a analizar en vivo (repetible; puerto 443 por defecto)")
    ap.add_argument("--ssh", action="append", default=[], metavar="HOST[:PUERTO]",
                    help="Servidor SSH a analizar en vivo (repetible; puerto 22 por defecto)")
    ap.add_argument("--timeout", type=float, default=5.0, help="Segundos de espera por conexión")
    ap.add_argument("--demo", action="store_true", help="Crear y analizar un proyecto de ejemplo")
    ap.add_argument("--version", action="version", version=f"pqc-radar {__version__}")
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = parser()
    a = ap.parse_args(argv)
    if a.demo:
        root = Path("pqc_radar_demo")
        make_demo(root)
    elif a.ruta:
        root = Path(a.ruta)
    elif a.tls or a.ssh:
        root = None
    else:
        ap.error("indica una RUTA, usa --tls/--ssh o --demo")
    if root is not None and not root.is_dir():
        ap.error(f"{root} no es una carpeta")
    if not HAS_CRYPTO:
        print("Aviso: instala 'cryptography' para analizar certificados.", file=sys.stderr)

    ctx = Context(a.perfil, a.riesgo == "alto", a.vida_datos, a.anos_migracion, a.ano_crqc)
    findings = scan(root, ctx, a.confianza_min) if root is not None else []
    unreachable: list[str] = []
    for kind, items, port, func in (("TLS", a.tls, 443, scan_tls), ("SSH", a.ssh, 22, scan_ssh)):
        for item in items:
            host, p = parse_target(item, port)
            try:
                findings += func(host, p, ctx, a.timeout)
            except (OSError, ValueError) as e:
                unreachable.append(f"{kind} {host}:{p} ({e})")
                print(f"Aviso: no se pudo analizar {kind} {host}:{p}: {e}", file=sys.stderr)
    findings.sort(key=lambda f: (PRIORITIES.index(f.priority), f.location, f.line))
    target = root.resolve().name if root is not None else "escaneo-remoto"

    Path(f"{a.salida}_cbom.json").write_text(
        json.dumps(build_cbom(findings, target), indent=2, ensure_ascii=False), encoding="utf-8")
    Path(f"{a.salida}_informe.md").write_text(build_report(findings, ctx, target, unreachable), encoding="utf-8")

    outputs = [f"{a.salida}_cbom.json", f"{a.salida}_informe.md"]
    if a.sarif:
        Path(a.sarif).write_text(json.dumps(build_sarif(findings), indent=2, ensure_ascii=False), encoding="utf-8")
        outputs.append(a.sarif)

    score, _, _ = readiness_score(findings)
    print(f"PQC-Radar {__version__} · {len(findings)} hallazgos en '{target}' · preparación PQC {'sin datos' if score is None else f'{score}/100'}")
    for p in PRIORITIES:
        n = sum(f.priority == p for f in findings)
        if n:
            print(f"  {p:<8} {n}")
    print("Salidas: " + " · ".join(outputs))

    if a.fail_on:
        limit = PRIORITIES.index(a.fail_on)
        if any(PRIORITIES.index(f.priority) <= limit for f in findings):
            return 1
    return 0
