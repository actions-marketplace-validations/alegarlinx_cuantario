# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Alejandro Garcia Linero
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cuantario")
except PackageNotFoundError:  # ejecutado desde el código fuente sin instalar
    __version__ = "0+desconocida"
