# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
import os
import shutil
import struct
import subprocess

import pytest
from conftest import free_port, kexinit_packet, wait_for_port

from cuantario.model import Context, assess
from cuantario.net import NetworkError, ProtocolError
from cuantario.rules import Priority
from cuantario.ssh import scan_ssh


def priorities(detections):
    result = {}
    for a in assess(detections, Context()):
        result.setdefault(a.detection.rule.id, set()).add(a.priority)
    return result


def test_hybrid_kex_makes_classical_a_fallback(ssh_server, fast):
    port = ssh_server(kexinit_packet(
        "mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,ext-info-s",
        "rsa-sha2-512,ssh-ed25519", "chacha20-poly1305@openssh.com,aes128-ctr", "hmac-sha1"))
    found = priorities(scan_ssh("127.0.0.1", port, fast))
    assert found["hybrid-kem"] == found["hybrid-sntrup"] == {Priority.OK}
    assert found["ecdh"] == {Priority.MEDIUM}
    assert found["rsa-signature"] == found["eddsa"] == {Priority.HIGH}
    assert found["aes-128"] == found["hmac-legacy"] == {Priority.LOW}
    assert "rsa" not in found


def test_classical_only(ssh_server, fast):
    port = ssh_server(kexinit_packet("curve25519-sha256,diffie-hellman-group14-sha256", "ssh-rsa", "aes256-ctr"))
    found = priorities(scan_ssh("127.0.0.1", port, fast))
    assert found["ecdh"] == found["dh"] == {Priority.CRITICAL}


@pytest.mark.parametrize("raw", [
    b"",
    struct.pack(">IB", 20, 4) + b"\x14" + b"x" * 5,
    struct.pack(">IB", 10**6, 4),
    struct.pack(">IB", 20, 200) + b"\x14" + b"x" * 18,
    struct.pack(">IB", 24, 4) + b"\x14" + os.urandom(16) + struct.pack(">I", 999) + b"ab",
], ids=["corta", "truncado", "longitud-absurda", "relleno", "name-list"])
def test_malformed_servers_raise_protocol_error(ssh_server, fast, raw):
    with pytest.raises((ProtocolError, NetworkError)):
        scan_ssh("127.0.0.1", ssh_server(raw), fast)


@pytest.fixture
def real_sshd(tmp_path):
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    if not os.path.exists(sshd) or not shutil.which("ssh-keygen"):
        pytest.skip("OpenSSH no disponible")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp_path / "hk")], check=True)
    port = free_port()
    (tmp_path / "cfg").write_text(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {tmp_path / 'hk'}\n"
                                  f"PidFile {tmp_path / 'pid'}\nUsePAM no\n")
    proc = subprocess.Popen([sshd, "-D", "-f", str(tmp_path / "cfg")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    wait_for_port(port)
    if proc.poll() is not None:
        pytest.skip(f"sshd no arranca aquí: {proc.stderr.read().decode()[:100] if proc.stderr else ''}")
    yield port
    proc.kill()


def test_real_openssh(real_sshd, fast):
    detections = scan_ssh("127.0.0.1", real_sshd, fast)
    assert all(d.evidence.notes[0].startswith("SSH-2.0-OpenSSH") for d in detections)
    found = priorities(detections)
    assert found["eddsa"] == {Priority.HIGH}
    if "hybrid-sntrup" in found or "hybrid-kem" in found:
        assert all(Priority.CRITICAL not in p for p in found.values())
