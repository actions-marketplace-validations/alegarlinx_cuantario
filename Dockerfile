# syntax=docker/dockerfile:1
# Cuantario en un contenedor: no hace falta instalar Python.
#   docker run --rm ghcr.io/alegarlinx/cuantario --tls ejemplo.es

# --- Etapa 1: construir el paquete y sus dependencias ---
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY cuantario ./cuantario
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

# --- Etapa 2: imagen final, mínima y sin herramientas de compilación ---
FROM python:3.12-slim
LABEL org.opencontainers.image.title="Cuantario" \
      org.opencontainers.image.description="Inventario criptográfico y priorización post-cuántica con políticas europeas" \
      org.opencontainers.image.source="https://github.com/alegarlinx/cuantario" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authors="Alejandro Garcia Linero"
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links /wheels cuantario \
    && rm -rf /wheels \
    && useradd --create-home --uid 10001 cuantario \
    && mkdir /scan && chown cuantario:cuantario /scan
# Nunca como administrador: una herramienta de seguridad debe dar ejemplo.
USER cuantario
WORKDIR /scan
ENTRYPOINT ["cuantario"]
CMD ["--help"]
