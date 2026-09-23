# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
import json

import pytest

from cuantario import cli


def test_demo_end_to_end(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["--demo", "--fail-on", "CRITICO"]) == 1
    cbom = json.loads((tmp_path / "cuantario_cbom.json").read_text())
    assert cbom["bomFormat"] == "CycloneDX" and cbom["specVersion"] == "1.6"
    lines = {(o["location"], o.get("line")) for c in cbom["components"] for o in c["evidence"]["occurrences"]}
    assert ("app/crypto_utils.py", 1) not in lines and ("app/crypto_utils.py", 5) not in lines
    assert "## Resumen" in (tmp_path / "cuantario_informe.md").read_text()


def test_min_confidence_filter(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cli.main(["--demo", "--confianza-min", "alta"])
    cbom = json.loads((tmp_path / "cuantario_cbom.json").read_text())
    assert {o["additionalContext"] for c in cbom["components"]
            for o in c["evidence"]["occurrences"]} == {"confidence=high"}


@pytest.mark.parametrize("args", [
    ["--tls", "ejemplo.es:abc"], ["--ssh", "[::1"], ["--timeout", "0"], ["--ano-crqc", "35"],
    ["--vida-datos", "-1"], ["--vida-datos", "diez"], ["--hosts-paralelos", "0"], ["--perfil", "xx"],
])
def test_bad_input_exits_cleanly(args, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    assert exc.value.code == 2 and "Traceback" not in capsys.readouterr().err


def test_skipped_files_are_announced(tmp_path, monkeypatch, capsys):
    (tmp_path / "raro.conf").write_bytes("contraseña\n".encode("latin-1"))
    monkeypatch.chdir(tmp_path)
    cli.main([str(tmp_path), "--salida", "out"])
    assert "1 archivos omitidos" in capsys.readouterr().err
    assert "## Archivos omitidos (1)" in (tmp_path / "out_informe.md").read_text()


def test_hosts_are_scanned_concurrently(tls_server, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ports = [tls_server({0x11EC, 0x001D}, "pq") for _ in range(3)]
    args = [a for p in ports for a in ("--tls", f"127.0.0.1:{p}")] + ["--timeout", "1", "--intervalo", "0.01"]
    assert cli.main(args) == 0
    assert "## Objetivos no accesibles" not in (tmp_path / "cuantario_informe.md").read_text()


def test_demo_lives_outside_the_cli():
    assert not hasattr(cli, "DEMO_FILES")
