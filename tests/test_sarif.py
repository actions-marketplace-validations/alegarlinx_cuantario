# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
import json
import os
from pathlib import Path

import pytest

from cuantario.cli import main
from cuantario.model import Context
from cuantario.sarif import build_sarif
from cuantario.scanner import scan


def _demo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    main(["--demo", "--perfil", "ccn", "--sarif", "out.sarif"])
    return (json.loads((tmp_path / "cuantario_cbom.json").read_text()),
            json.loads((tmp_path / "out.sarif").read_text()))


def test_sarif_structure(tmp_path, monkeypatch):
    _, sarif = _demo(tmp_path, monkeypatch)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "Cuantario"
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))                      # sin reglas duplicadas
    for res in run["results"]:
        assert rule_ids[res["ruleIndex"]] == res["ruleId"]           # índices coherentes
        assert res["level"] in ("error", "warning", "note")
        assert "://" not in res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_sarif_excludes_ok_and_keeps_certificates(tmp_path, monkeypatch):
    _, sarif = _demo(tmp_path, monkeypatch)
    run = sarif["runs"][0]
    ids = {r["ruleId"] for r in run["results"]}
    assert "pqc/aes-256" not in ids and "pqc/ml-dsa" not in ids     # lo correcto no genera alertas
    assert "pqc/certificado" in ids and "pqc/md5" in ids
    cert = next(r for r in run["results"] if r["ruleId"] == "pqc/certificado")
    assert "region" not in cert["locations"][0]["physicalLocation"]  # un certificado no tiene línea


def test_sarif_private_key_is_redacted(tmp_path):
    (tmp_path / "k.pem").write_text("-----BEGIN PRIVATE KEY-----\nSECRETO123\n-----END PRIVATE KEY-----\n")
    sarif = build_sarif(scan(tmp_path, Context()))
    text = json.dumps(sarif)
    assert "pqc/private-key" in text and "SECRETO123" not in text


def test_sarif_fingerprints_are_stable(tmp_path):
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    def fingerprints():
        return [r["partialFingerprints"] for r in build_sarif(scan(tmp_path, Context()))["runs"][0]["results"]]
    assert fingerprints() == fingerprints()


SCHEMAS = Path(os.environ.get("PQC_SCHEMAS", "schemas")).resolve()
needs_schemas = pytest.mark.skipif(not (SCHEMAS / "bom-1.6.schema.json").exists(),
                                   reason="esquemas no descargados (se descargan en CI)")


@needs_schemas
def test_outputs_match_official_schemas(tmp_path, monkeypatch):
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")

    def load(name):
        return json.loads((SCHEMAS / name).read_text())
    registry = referencing.Registry().with_resources(
        [(n, referencing.Resource.from_contents(load(n))) for n in ("spdx.schema.json", "jsf-0.82.schema.json")])
    cbom, sarif = _demo(tmp_path, monkeypatch)
    jsonschema.Draft7Validator(load("bom-1.6.schema.json"), registry=registry).validate(cbom)
    jsonschema.Draft7Validator(load("sarif-schema-2.1.0.json")).validate(sarif)
