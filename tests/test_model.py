# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
import dataclasses

import pytest

from cuantario.model import Context, Detection, Location, assess, assess_one, detect
from cuantario.outputs import build_report, readiness_scores
from cuantario.rules import RULES_BY_ID, Confidence, Priority, Source, Status
from cuantario.scanner import scan_text


def kex() -> Detection:
    return detect("ecdh", location=Location("f", 1), source=Source.CONFIG, confidence=Confidence.MEDIUM)


def test_detection_requires_keywords():
    with pytest.raises(TypeError):
        Detection(RULES_BY_ID["rsa"], Status.VULNERABLE, True, Location("f"), Source.CODE,  # type: ignore[misc]
                  Confidence.LOW)


def test_detection_is_immutable():
    with pytest.raises(dataclasses.FrozenInstanceError):
        kex().fallback = True  # type: ignore[misc]


def test_enum_labels():
    assert Priority.CRITICAL.label == "CRITICO" and Priority.from_label("MEDIO") is Priority.MEDIUM
    assert Confidence.from_label("alta") is Confidence.HIGH


def test_assessment_does_not_depend_on_input_order():
    raw = scan_text("grupos X25519MLKEM768, X25519", "t", Source.TLS, Confidence.HIGH)
    assert assess(raw, Context()) == assess(list(reversed(raw)), Context())


def test_mosca():
    assert assess_one(kex(), Context(data_life=10, migration=5, crqc_year=2035)).priority is Priority.CRITICAL
    assert assess_one(kex(), Context(data_life=1, migration=1, crqc_year=2100)).priority is Priority.HIGH


def test_min_confidence_filter():
    low = detect("rsa", location=Location("x.java"), source=Source.CODE, confidence=Confidence.LOW)
    assert assess([low, kex()], Context(), Confidence.MEDIUM) == assess([kex()], Context())


def _report(text: str) -> str:
    ctx = Context()
    return build_report(assess(scan_text(text, "tls://e:443", Source.TLS, Confidence.HIGH), ctx), ctx, "p")


def test_mosca_message_not_alarming_when_everything_has_pq():
    report = _report("X25519MLKEM768, X25519")
    assert "migración es urgente" not in report and "sin protección post-cuántica. ✅" in report


def test_mosca_message_urgent_when_classical_only():
    assert "hay 1 uso de cifrado o intercambio de claves clásico" in _report("X25519, ECDHE")


def test_report_lists_ok_findings():
    assert "## Correcto (1)" in _report("X25519MLKEM768, X25519")


@pytest.mark.parametrize("lines,kex_score,sig_score", [
    (["X25519MLKEM768, X25519", "ECDSA"], "100/100", "0/100"),
    (["X25519, ECDHE-P256"], "0/100", "sin datos"),
    (["AES-256-GCM"], "sin datos", "sin datos"),
])
def test_scores(lines, kex_score, sig_score):
    detections = [d for line in lines for d in scan_text(line, "t", Source.TLS, Confidence.HIGH)]
    kex_s, sig_s = readiness_scores(assess(detections, Context()))
    assert (kex_s.text(), sig_s.text()) == (kex_score, sig_score)
