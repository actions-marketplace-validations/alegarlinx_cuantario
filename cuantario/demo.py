# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from __future__ import annotations

import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .model import now

DEMO_FILES = {
    "app/crypto_utils.py": (
        '"""Utilidades de cifrado. La versión antigua usaba RSA y MD5."""\n'
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n\n"
        "# TODO: quitar RSA cuando el cliente soporte ML-KEM\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "checksum = hashlib.md5(b'datos', usedforsecurity=False).hexdigest()\n"
        'TLS_CIPHERS = "ECDHE-RSA-AES256-GCM-SHA384"\n'
        "token = hashlib.sha1(secreto).hexdigest()\n"
    ),
    "config/sshd_config": "KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256\n"
                          "HostKeyAlgorithms ssh-ed25519,ssh-rsa\n"
                          "MACs hmac-sha2-256,hmac-sha1\n",
    "config/nginx.conf": "ssl_protocols TLSv1.3;\nssl_ecdh_curve X25519MLKEM768:X25519;\n"
                         "ssl_ciphers HIGH:!aNULL:!MD5:!RC4;\n",
    "src/Main.java": 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n'
                     'Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");\n'
                     'Cipher d = Cipher.getInstance("AES/CBC/PKCS5Padding");\n',
    "src/pq.go": "// firma de actualizaciones con ML-DSA-65\n",
}


def make_demo(root: Path) -> None:
    for rel, content in DEMO_FILES.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo.sede.example")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now())
            .not_valid_after(now() + dt.timedelta(days=365 * 6)).sign(key, hashes.SHA256()))
    (root / "certs").mkdir(exist_ok=True)
    (root / "certs" / "server.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
