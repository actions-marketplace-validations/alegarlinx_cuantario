# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
import pytest

from cuantario.model import Context, assess
from cuantario.rules import Confidence, Priority, Source
from cuantario.scanner import scan_text


def ids(text: str) -> set[str]:
    return {d.rule.id for d in scan_text(text, "f", Source.CONFIG, Confidence.MEDIUM)}


def assessed(text: str) -> dict[str, Priority]:
    return {a.detection.rule.id: a.priority
            for a in assess(scan_text(text, "f", Source.CONFIG, Confidence.MEDIUM), Context())}


@pytest.mark.parametrize("text,expected", [
    ('KeyPairGenerator.getInstance("RSA")', {"rsa"}),
    ("HostKeyAlgorithms ssh-ed25519", {"eddsa"}),
    ('Cipher.getInstance("DESede/CBC")', {"3des"}),
    ("KexAlgorithms diffie-hellman-group14-sha256", {"dh"}),
    ("ssl_ecdh_curve X25519MLKEM768", {"hybrid-kem"}),
    ("sign with ML-DSA-65", {"ml-dsa"}),
    ("cipher AES-256-GCM", {"aes-256"}),
])
def test_positive(text, expected):
    assert ids(text) == expected


@pytest.mark.parametrize("text,forbidden", [
    ("sign with ML-DSA-65", "dsa"),
    ("use SLH-DSA", "dsa"),
    ("curve ECDSA P-256", "dsa"),
    ("Cipher DESede", "des"),
    ("ssl_ecdh_curve X25519MLKEM768", "ecdh"),
    ("ssl_ecdh_curve X25519MLKEM768", "ml-kem"),
    ("the word crsa or rsafe", "rsa"),
])
def test_negative(text, forbidden):
    assert forbidden not in ids(text)


def test_classical_fallback_next_to_hybrid_is_medium():
    hybrid, fallback = scan_text("ssl_ecdh_curve X25519MLKEM768:X25519;", "f", Source.CONFIG, Confidence.MEDIUM)
    assert hybrid.rule.id == "hybrid-kem" and fallback.rule.id == "ecdh" and fallback.fallback
    assert assessed("ssl_ecdh_curve X25519MLKEM768:X25519;")["ecdh"] is Priority.MEDIUM


def test_hmac_does_not_mark_the_next_classical_algorithm_as_fallback():
    [d] = [d for d in scan_text("MACs hmac-sha1 ; kex ECDH", "f", Source.CONFIG, Confidence.MEDIUM)
           if d.rule.id == "ecdh"]
    assert not d.fallback


@pytest.mark.parametrize("line", ["MACs hmac-sha1,hmac-sha2-256", 'Mac.getInstance("HmacSHA1")',
                                  "MACs hmac-md5-etm@openssh.com"])
def test_hmac_with_legacy_hash_is_low(line):
    found = assessed(line)
    assert "sha1" not in found and "md5" not in found and found["hmac-legacy"] is Priority.LOW


def test_md5_in_config_is_critical():
    assert assessed("password_encryption = md5")["md5"] is Priority.CRITICAL


def test_cbc_mode():
    found = assessed("cipher AES-256-CBC")
    assert found == {"aes-256": Priority.OK, "aes-cbc": Priority.LOW}


def test_excluded_ciphers_are_not_findings():
    assert scan_text("ssl_ciphers HIGH:!aNULL:!MD5:!RC4:!3DES;", "f", Source.CONFIG, Confidence.MEDIUM) == []
