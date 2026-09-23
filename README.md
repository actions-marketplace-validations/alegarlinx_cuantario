# Cuantario

Inventario criptográfico para la migración post-cuántica. Analiza código, configuración, certificados y
servidores TLS/SSH, clasifica lo que encuentra según su resistencia a un ordenador cuántico y prioriza
según los plazos del roadmap coordinado de la UE (2026/2030/2035). Tiene un perfil `ccn` que añade las
restricciones de las guías CCN-STIC.

Saca un CBOM en CycloneDX 1.6, un SARIF 2.1.0 para GitHub y un informe en Markdown. Antes se llamaba PQC-Radar.

## Instalación

```bash
pip install git+https://github.com/alegarlinx/cuantario.git
```

O con Docker:

```bash
docker run --rm -v "$PWD:/scan" ghcr.io/alegarlinx/cuantario --tls ejemplo.es
```

La imagen corre como usuario sin privilegios; en Linux puede hacer falta `--user "$(id -u):$(id -g)"` para
que pueda escribir en la carpeta montada. Cada release lleva también el wheel adjunto.

## Uso

```bash
cuantario ./proyecto
cuantario ./proyecto --perfil ccn --fail-on CRITICO
cuantario --tls ejemplo.es --tls ejemplo.es:8443 --ssh ejemplo.es
cuantario --demo
```

`cuantario --help` lista todas las opciones. Las que más se usan:

- `--vida-datos`, `--anos-migracion`, `--ano-crqc`: parámetros de la desigualdad de Mosca. Con los valores
  por defecto (10, 5 y 2035) cualquier intercambio de claves clásico sale como crítico.
- `--riesgo medio`: para sectores fuera de alto riesgo, las firmas vulnerables bajan de ALTO a MEDIO.
- `--confianza-min media`: descarta los hallazgos que salen de buscar texto en código (ver abajo).
- `--sarif archivo.sarif`: salida para GitHub Code Scanning.

## Cómo detecta

| Fuente | Método | Confianza |
|---|---|---|
| Python | AST: llamadas a `cryptography`, PyCryptodome y `hashlib`, y cadenas de configuración | alta / media |
| Certificados PEM/DER | parseo X.509 | alta |
| Configuración (sshd, nginx, YAML, JSON…) | expresiones regulares | media |
| Otros lenguajes | expresiones regulares | baja |
| TLS en vivo | sondeo de grupos, cifrado negociado y certificado | alta |
| SSH en vivo | lectura del KEXINIT | alta |

Para TLS se manda un ClientHello por grupo con el `key_share` vacío; si el servidor acepta el grupo responde
con un HelloRetryRequest que lo nombra. Después se ofrecen los grupos clásicos y los post-cuánticos en los dos
órdenes para ver cuál elige el servidor, porque hay servidores que admiten `X25519MLKEM768` pero nunca lo usan.

En código Python, `hashlib.md5()` o `sha1()` salen con prioridad media porque pueden ser un simple checksum;
con `usedforsecurity=False` bajan a baja. HMAC-SHA1 no se trata como roto. Las exclusiones de las listas de
cifrados (`!MD5`) no cuentan como uso.

Solo se lee lo que el servidor anuncia en el saludo, igual que un navegador. Aun así, analiza únicamente
servidores propios o con permiso.

Probado contra Cloudflare y Google (ambos anuncian `X25519MLKEM768`; Google también `MLKEM1024`) en Linux,
macOS y Windows.

## Índice de preparación

El informe da dos índices en lugar de uno. El de intercambio de claves es el urgente, porque el tráfico de hoy
se puede guardar y descifrar más adelante. El de firmas y certificados sale bajo casi en cualquier servidor,
porque los certificados post-cuánticos todavía no se usan en la web. Un X25519 que se mantiene como fallback
junto a un grupo híbrido no penaliza.

## GitHub Actions

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  cuantario:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: alegarlinx/cuantario@v0.6.0
        id: cuantario
        with:
          perfil: ccn
          fail-on: CRITICO
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: ${{ steps.cuantario.outputs.sarif }}
```

La action también expone `cbom` e `informe` como outputs, y deja el informe en el resumen del job.

## Limitaciones

- Fuera de Python la detección es por texto y da falsos positivos; por eso existe `--confianza-min`.
- No sustituye a una auditoría. Las referencias al CCN y a ENISA conviene contrastarlas con la versión vigente
  de cada guía.
- La imagen Docker solo se publica para amd64.

Otras herramientas del mismo espacio: CryptoBOM-Forge (Santander, open source, solo código), PCert
(Data-Warehouse), SSHerlock (SSH.com) y COMPASS (CryptoNext).

## Desarrollo

```bash
pip install -e ".[dev]"
pytest
ruff check cuantario tests
mypy cuantario
```

Apache 2.0.
