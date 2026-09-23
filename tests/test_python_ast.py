# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
import pytest

from cuantario.model import Context, assess
from cuantario.python_ast import scan_python
from cuantario.rules import Confidence, Priority, SecurityUse, Status


def found(src: str) -> list[tuple[str, int]]:
    return [(d.rule.id, d.location.line) for d in scan_python(src, "a.py")]


def test_ignores_comments_and_docstrings():
    assert found('"""Antes usábamos RSA."""\n# TODO quitar MD5\nx = 1\n') == []


def test_real_call_has_high_confidence_and_key_size():
    [d] = scan_python("from cryptography.hazmat.primitives.asymmetric import rsa\n"
                      "k = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n", "a.py")
    assert (d.rule.id, d.confidence, d.location.line, d.key_size) == ("rsa", Confidence.HIGH, 2, 3072)


def test_small_rsa_key_is_broken():
    [d] = scan_python("from cryptography.hazmat.primitives.asymmetric import rsa\n"
                      "k = rsa.generate_private_key(65537, key_size=1024)\n", "a.py")
    assert d.status is Status.BROKEN


def test_hashlib_new_detected_once():
    [d] = scan_python('import hashlib\nh = hashlib.new("md5")\n', "a.py")
    assert (d.rule.id, d.confidence) == ("md5", Confidence.HIGH)


def test_string_constants_have_medium_confidence():
    detections = scan_python('CIPHERS = "ECDHE-RSA-AES256-GCM"\n', "a.py")
    assert {d.rule.id for d in detections} == {"ecdh", "rsa", "aes-256"}
    assert {d.confidence for d in detections} == {Confidence.MEDIUM}


def test_invalid_python_returns_none():
    assert scan_python("def x(:\n", "a.py") is None


@pytest.mark.parametrize("src,expected", [
    ("import hashlib as h\nh.md5(b'x')\n", [("md5", 2)]),
    ("from hashlib import md5\nmd5(b'x')\n", [("md5", 2)]),
    ("from hashlib import md5 as digest\ndigest(b'x')\n", [("md5", 2)]),
    ("from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key\n"
     "k = generate_private_key(public_exponent=65537, key_size=2048)\n", [("rsa", 2)]),
    ("import hashlib\nmd5 = hashlib.md5\nmd5(b'x')\n", [("md5", 3)]),
    ("import hashlib\nhasher = hashlib.sha1\ndef f():\n    return hasher(b'x')\n", [("sha1", 4)]),
], ids=["alias", "from-import", "from-import-as", "from-import-crypto", "reasignacion", "reasignacion-global"])
def test_follows_aliases_and_reassignments(src, expected):
    assert found(src) == expected


@pytest.mark.parametrize("src", [
    "def f():\n    import hashlib as h\n\nh = object()\nh.md5()\n",
    "import hashlib\ndef f(hashlib):\n    hashlib.md5()\n",
    "import hashlib as h\nh = object()\nh.md5()\n",
    "def md5(x):\n    return x\nmd5(1)\n",
    "import hashlib\nf = lambda hashlib: hashlib.md5()\n",
], ids=["import-local", "parametro", "reasignado", "funcion-propia", "lambda"])
def test_respects_scopes_and_shadowing(src):
    assert found(src) == []


def test_methods_do_not_see_class_attributes():
    src = "import hashlib\nclass A:\n    hashlib = None\n    def m(self):\n        hashlib.md5()\n"
    assert found(src) == [("md5", 5)]


def test_md5_priority_depends_on_declared_use():
    src = "import hashlib\nhashlib.md5(b'x', usedforsecurity=False)\nhashlib.md5(b'y')\n"
    detections = scan_python(src, "a.py")
    assert [d.security_use for d in detections] == [SecurityUse.NON_SECURITY, SecurityUse.UNKNOWN]
    assert {a.priority for a in assess(detections, Context())} == {Priority.LOW, Priority.MEDIUM}
