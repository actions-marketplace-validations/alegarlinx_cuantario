# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
import json
import socket

import pytest
from conftest import free_port, read_client_hello, send_rst

from cuantario import cli
from cuantario.study import HostResult, load_list, run_study, study_report


def test_load_list_accepts_tranco_format_comments_and_duplicates(tmp_path):
    path = tmp_path / "l.txt"
    path.write_text("# comentario\n1,elpais.es\n2,boe.es  # otro\n\nboe.es\nejemplo.es:8443\n")
    assert load_list(path) == ["elpais.es", "boe.es", "ejemplo.es:8443"]


def test_load_list_rejects_bad_lines(tmp_path):
    path = tmp_path / "l.txt"
    path.write_text("ok.es\nmal.es:abc\n")
    with pytest.raises(ValueError, match="l.txt:2"):
        load_list(path)


@pytest.fixture
def mixed_targets(tls_server, openssl_server, serve):
    def waf(conn: socket.socket) -> None:
        read_client_hello(conn)
        send_rst(conn)

    return {
        "pq": f"127.0.0.1:{tls_server({0x11EC, 0x001D}, 'pq')}",
        "pq_unused": f"127.0.0.1:{tls_server({0x11EC, 0x001D}, 'clasico')}",
        "tls10": f"127.0.0.1:{openssl_server('-tls1', '-cipher', 'ALL:@SECLEVEL=0')}",
        "tls13": f"127.0.0.1:{openssl_server()}",
        "waf": f"127.0.0.1:{serve(waf)}",
        "closed": f"127.0.0.1:{free_port()}",
    }


def test_study_end_to_end(mixed_targets, fast):
    results = {r.domain: r for r in run_study(list(mixed_targets.values()), fast, workers=3)}
    by_name = {name: results[target] for name, target in mixed_targets.items()}
    assert by_name["pq"].hybrid and by_name["pq"].preference == "prefers_pq"
    assert by_name["pq_unused"].hybrid and by_name["pq_unused"].preference == "prefers_classical"
    assert "TLS 1.0" in by_name["tls10"].tls_versions and by_name["tls10"].chain_length == 2
    assert "TLS 1.3" in by_name["tls13"].tls_versions and not by_name["tls13"].hybrid
    assert not by_name["waf"].reachable and "reseteada" in (by_name["waf"].error or "")
    assert not by_name["closed"].reachable

    report = study_report(list(results.values()), {"date": "hoy", "source": "prueba", "timeout": 0.5,
                                                   "workers": 3, "interval": 0.0})
    assert "| Analizados | 4 | 66.7 % |" in report
    assert "| Admiten un grupo híbrido con ML-KEM | 2 | 50.0 % |" in report
    assert "| …pero eligen siempre el clásico | 1 | 25.0 % |" in report
    assert "| Aceptan TLS 1.0 o 1.1 | 1 | 25.0 % |" in report
    assert "reset repetido (posible WAF o rate limit): 1" in report
    assert "127.0.0.1" not in report and all(t.split(":")[1] not in report for t in mixed_targets.values())


def test_cli_study_writes_anonymous_summary_and_private_data(mixed_targets, tmp_path, monkeypatch):
    lista = tmp_path / "lista.txt"
    lista.write_text("\n".join(mixed_targets.values()))
    monkeypatch.chdir(tmp_path)
    assert cli.main(["--estudio", str(lista), "--salida", "e", "--timeout", "0.5", "--intervalo", "0.01",
                     "--fuente", "Prueba local"]) == 0
    assert "127.0.0.1" not in (tmp_path / "e_resumen.md").read_text()
    data = json.loads((tmp_path / "e_datos.json").read_text())
    assert len(data) == 6 and {d["domain"] for d in data} == set(mixed_targets.values())


def test_empty_study_does_not_divide_by_zero():
    report = study_report([HostResult(domain="x", error="timed out")],
                          {"date": "hoy", "source": "s", "timeout": 1, "workers": 1, "interval": 0.1})
    assert "| Analizados | 0 | 0.0 % |" in report and "tiempo de espera agotado: 1" in report
