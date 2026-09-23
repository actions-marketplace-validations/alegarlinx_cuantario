# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
import json
import os
from pathlib import Path

import pytest

from cuantario import cli
from cuantario.model import Context, assess
from cuantario.sarif import build_sarif
from cuantario.scanner import scan


@pytest.fixture
def demo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cli.main(["--demo", "--perfil", "ccn", "--sarif", "out.sarif"])
    return (json.loads((tmp_path / "cuantario_cbom.json").read_text()),
            json.loads((tmp_path / "out.sarif").read_text()))


def test_sarif_structure(demo):
    run = demo[1]["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    for result in run["results"]:
        assert rule_ids[result["ruleIndex"]] == result["ruleId"]
        assert "://" not in result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_sarif_excludes_ok_and_keeps_certificates(demo):
    results = demo[1]["runs"][0]["results"]
    ids = {r["ruleId"] for r in results}
    assert "pqc/aes-256" not in ids and "pqc/ml-dsa" not in ids and "pqc/certificate" in ids
    cert = next(r for r in results if r["ruleId"] == "pqc/certificate")
    assert "region" not in cert["locations"][0]["physicalLocation"]


def test_sarif_private_key_is_redacted(tmp_path):
    (tmp_path / "k.pem").write_text("-----BEGIN PRIVATE KEY-----\nSECRETO123\n-----END PRIVATE KEY-----\n")
    text = json.dumps(build_sarif(assess(scan(tmp_path).detections, Context())))
    assert "pqc/private-key" in text and "SECRETO123" not in text


def test_sarif_fingerprints_are_stable(tmp_path):
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")

    def fingerprints():
        return [r["partialFingerprints"]
                for r in build_sarif(assess(scan(tmp_path).detections, Context()))["runs"][0]["results"]]
    assert fingerprints() == fingerprints()


SCHEMAS = Path(os.environ.get("PQC_SCHEMAS", "schemas")).resolve()


@pytest.mark.skipif(not (SCHEMAS / "bom-1.6.schema.json").exists(), reason="esquemas no descargados (CI)")
def test_outputs_match_official_schemas(demo):
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")

    def load(name):
        return json.loads((SCHEMAS / name).read_text())
    registry = referencing.Registry().with_resources(
        [(n, referencing.Resource.from_contents(load(n))) for n in ("spdx.schema.json", "jsf-0.82.schema.json")])
    jsonschema.Draft7Validator(load("bom-1.6.schema.json"), registry=registry).validate(demo[0])
    jsonschema.Draft7Validator(load("sarif-schema-2.1.0.json")).validate(demo[1])
