# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
"""Extrae de una lista de Tranco (rango,dominio) los N primeros dominios de un TLD.

    curl -LO https://tranco-list.eu/top-1m.csv.zip && unzip top-1m.csv.zip
    python scripts/preparar_lista.py top-1m.csv --tld es --n 200 > dominios_es.txt
"""
from __future__ import annotations

import argparse
import csv
import sys


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv")
    ap.add_argument("--tld", default="es")
    ap.add_argument("--n", type=int, default=200)
    args = ap.parse_args()

    suffix = "." + args.tld.lstrip(".")
    written = 0
    with open(args.csv, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) == 2 and row[1].endswith(suffix):
                print(f"{row[0]},{row[1]}")
                written += 1
                if written == args.n:
                    break
    print(f"{written} dominios {suffix}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
