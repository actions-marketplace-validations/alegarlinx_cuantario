# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
import datetime as dt
import json

import pytest

from cuantario.cli import main
from cuantario.model import Context, Finding, prioritize
from cuantario.outputs import build_cbom
from cuantario.python_ast import scan_python
from cuantario.rules import RULES_BY_ID, VULN
from cuantario.scanner import scan, scan_text


def ids(findings):
    return {f.rule_id for f in findings}


@pytest.mark.parametrize("text,expected", [
    ("KeyPairGenerator.getInstance(\"RSA\")", {"rsa"}),
    ("HostKeyAlgorithms ssh-ed25519", {"eddsa"}),
    ("Cipher.getInstance(\"DESede/CBC\")", {"3des"}),
    ("KexAlgorithms diffie-hellman-group14-sha256", {"dh"}),
    ("ssl_ecdh_curve X25519MLKEM768", {"hybrid-kem"}),
    ("sign with ML-DSA-65", {"ml-dsa"}),
    ("cipher AES-256-GCM", {"aes-256"}),
])
def test_text_rules_positive(text, expected):
    assert ids(scan_text(text, "f", "config", "media")) == expected


@pytest.mark.parametrize("text,forbidden", [
    ("sign with ML-DSA-65", "dsa"),          # ML-DSA no es DSA clásico
    ("use SLH-DSA", "dsa"),
    ("curve ECDSA P-256", "dsa"),            # ECDSA no es DSA
    ("Cipher DESede", "des"),                 # 3DES no se cuenta dos veces
    ("ssl_ecdh_curve X25519MLKEM768", "ecdh"),  # el híbrido no es un X25519 suelto
    ("ssl_ecdh_curve X25519MLKEM768", "ml-kem"),
    ("the word crsa or rsafe", "rsa"),
])
def test_text_rules_negative(text, forbidden):
    assert forbidden not in ids(scan_text(text, "f", "config", "media"))


def test_classical_fallback_next_to_hybrid_is_medium():
    [hyb, fb] = scan_text("ssl_ecdh_curve X25519MLKEM768:X25519;", "f", "config", "media")
    assert hyb.rule_id == "hybrid-kem" and fb.rule_id == "ecdh" and fb.fallback
    prioritize(fb, Context())
    assert fb.priority == "MEDIO"


def test_ast_ignores_comments_and_docstrings():
    src = '"""Antes usábamos RSA."""\n# TODO quitar MD5\nx = 1\n'
    assert scan_python(src, "a.py") == []


def test_ast_detects_real_calls_with_high_confidence():
    src = ("from cryptography.hazmat.primitives.asymmetric import rsa\n"
           "k = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n")
    [f] = scan_python(src, "a.py")
    assert f.rule_id == "rsa" and f.confidence == "alta" and f.line == 2
    assert f.extra["key_size"] == 3072


def test_ast_small_rsa_key_is_broken():
    [f] = scan_python("import rsa as r\nk = rsa.generate_private_key(65537, key_size=1024)\n", "a.py")
    assert f.status == "roto_hoy"


def test_ast_hashlib_new_detected_once():
    found = scan_python('import hashlib\nh = hashlib.new("md5")\n', "a.py")
    assert [(f.rule_id, f.confidence) for f in found] == [("md5", "alta")]


def test_ast_string_config_medium_confidence():
    found = scan_python('CIPHERS = "ECDHE-RSA-AES256-GCM"\n', "a.py")
    assert ids(found) == {"ecdh", "rsa", "aes-256"}
    assert {f.confidence for f in found} == {"media"}


def test_invalid_python_falls_back_to_text(tmp_path):
    (tmp_path / "broken.py").write_text("def x(:\n  RSA\n")
    [f] = scan(tmp_path, Context())
    assert f.rule_id == "rsa" and f.confidence == "baja"


def _vuln_kex():
    r = RULES_BY_ID["ecdh"]
    return Finding(r.id, r.name, VULN, r.primitive, "f", 1, "", r.replacement, "config", hndl=True)


def test_mosca_violated_is_critical():
    f = _vuln_kex()
    prioritize(f, Context(data_life=10, migration=5, crqc_year=2035))
    assert f.priority == "CRITICO"


def test_mosca_not_violated_is_high():
    f = _vuln_kex()
    prioritize(f, Context(data_life=1, migration=1, crqc_year=2100))
    assert f.priority == "ALTO"


def _write_cert(path, bits, years):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    start = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(start)
            .not_valid_after(start + dt.timedelta(days=365 * years)).sign(key, hashes.SHA256()))
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def test_weak_certificate_is_critical(tmp_path):
    _write_cert(tmp_path / "weak.pem", 1024, 1)
    [f] = scan(tmp_path, Context(high_risk=False))
    assert f.priority == "CRITICO" and f.status == "roto_hoy"


def test_long_lived_certificate_depends_on_risk(tmp_path):
    _write_cert(tmp_path / "c.pem", 2048, 8)
    assert scan(tmp_path, Context(high_risk=True))[0].priority == "CRITICO"
    assert scan(tmp_path, Context(high_risk=False))[0].priority == "MEDIO"


def test_private_key_is_reported_and_redacted(tmp_path):
    (tmp_path / "k.pem").write_text("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
    [f] = scan(tmp_path, Context())
    assert f.priority == "CRITICO" and f.evidence == "[REDACTADO]"
    assert build_cbom([f], "t")["components"] == []  # nunca va al CBOM


def test_cli_demo_end_to_end(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["--demo", "--fail-on", "CRITICO"]) == 1
    cbom = json.loads((tmp_path / "cuantario_cbom.json").read_text())
    assert cbom["bomFormat"] == "CycloneDX" and cbom["specVersion"] == "1.6"
    report = (tmp_path / "cuantario_informe.md").read_text()
    assert "Informe de preparación post-cuántica" in report
    # el docstring y el comentario del demo mencionan RSA/MD5 y no deben aparecer como hallazgos
    lines = {(o["location"], o.get("line")) for c in cbom["components"] for o in c["evidence"]["occurrences"]}
    assert ("app/crypto_utils.py", 1) not in lines
    assert ("app/crypto_utils.py", 5) not in lines


def test_min_confidence_filter(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    main(["--demo", "--confianza-min", "alta"])
    cbom = json.loads((tmp_path / "cuantario_cbom.json").read_text())
    ctx = {o["additionalContext"] for c in cbom["components"] for o in c["evidence"]["occurrences"]}
    assert ctx == {"confianza=alta"}


def _report_for(line: str, ctx: Context) -> str:
    from cuantario.outputs import build_report
    findings = scan_text(line, "tls://ejemplo:443", "tls", "alta")
    for f in findings:
        prioritize(f, ctx)
    return build_report(findings, ctx, "prueba")


def test_mosca_message_not_alarming_when_everything_has_pq():
    # Caso real de Cloudflare/Google: híbrido preferido y X25519 como respaldo.
    report = _report_for("grupos aceptados: X25519MLKEM768, X25519", Context())
    assert "ya son urgentes" not in report and "migración es urgente" not in report
    assert "no se ha encontrado cifrado ni intercambio de claves clásico sin protección" in report


def test_mosca_message_urgent_when_classical_only():
    report = _report_for("grupos aceptados: X25519, ECDHE-P256", Context())
    assert "hay 1 uso de cifrado o intercambio de claves clásico sin protección post-cuántica" in report


def test_mosca_message_when_inequality_not_violated():
    report = _report_for("grupos aceptados: X25519", Context(data_life=1, migration=1, crqc_year=2100))
    assert "no se cumple con estos parámetros" in report


def test_report_lists_ok_findings():
    report = _report_for("grupos aceptados: X25519MLKEM768, X25519", Context())
    assert "## Correcto (1)" in report
    assert "Intercambio híbrido clásico + ML-KEM" in report.split("## Correcto")[1]


def _scores_for(*lines):
    from cuantario.outputs import readiness_scores
    findings = []
    for line in lines:
        findings += scan_text(line, "tls://ejemplo:443", "tls", "alta")
    return readiness_scores(findings)


def test_scores_like_cloudflare():
    # Híbrido preferido, X25519 de respaldo y certificado ECDSA: el caso real de Cloudflare.
    kex, sig = _scores_for("grupos aceptados: X25519MLKEM768, X25519", "firma ECDSA")
    assert kex.text() == "100/100" and (kex.ready, kex.total) == (1, 1)   # el respaldo no resta
    assert sig.text() == "0/100"


def test_scores_classical_server():
    kex, sig = _scores_for("grupos aceptados: X25519, ECDHE-P256")
    assert kex.text() == "0/100" and sig.text() == "sin datos"


def test_scores_without_public_key_crypto():
    kex, sig = _scores_for("cifrado AES-256-GCM")
    assert kex.text() == "sin datos" and sig.text() == "sin datos"


def test_report_shows_both_scores(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    main(["--demo"])
    report = (tmp_path / "cuantario_informe.md").read_text()
    assert "| Intercambio de claves y cifrado |" in report and "| Firmas y certificados |" in report
