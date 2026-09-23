# Cuantario

*Cuántico + inventario.* Antes conocido como PQC-Radar.

**Inventario criptográfico y priorización post-cuántica con políticas europeas.**

Cuantario analiza un repositorio (código, configuraciones TLS/SSH y certificados X.509) **y servidores
TLS/SSH en vivo**, detecta la criptografía que usa, la clasifica según su resistencia a un ordenador cuántico y prioriza la migración
según los hitos del **roadmap coordinado de la UE** (2026 / 2030 / 2035) y, opcionalmente, las
autorizaciones del **CCN** español.

Genera un **CBOM** estándar (CycloneDX 1.6), un **informe SARIF 2.1.0** para GitHub y un **informe de
migración en español**. Ambos formatos se validan en cada cambio contra sus esquemas oficiales.

## Qué lo diferencia

- **Políticas europeas**, no solo plazos de EE. UU. (NIST, CNSA 2.0).
- **Priorización con la desigualdad de Mosca**: si la vida útil del dato más el tiempo de migración
  supera la llegada estimada de un ordenador cuántico relevante, el intercambio de claves es crítico.
- **Nivel de confianza por hallazgo**: `alta` (análisis sintáctico o certificado), `media`
  (configuración o cadena del programa), `baja` (búsqueda de texto).
- **Reconoce esquemas híbridos** (p. ej. `X25519MLKEM768`) y trata el fallback clásico como aceptable
  durante la transición.

## Instalación

```bash
pip install -e .
```

## Uso

### Repositorios

```bash
cuantario --demo                         # proyecto de ejemplo
cuantario ./mi-proyecto --perfil ccn     # con notas del CCN
cuantario ./mi-proyecto --vida-datos 20 --anos-migracion 4 --ano-crqc 2033
cuantario ./mi-proyecto --confianza-min media --fail-on CRITICO   # para CI
```

### Servidores en vivo

```bash
cuantario --tls ejemplo.es                       # puerto 443
cuantario --tls ejemplo.es:8443 --ssh ejemplo.es  # varios objetivos a la vez
cuantario ./mi-proyecto --tls ejemplo.es         # código y servidor en el mismo informe
```

Para TLS, Cuantario detecta qué grupos de intercambio de claves acepta el servidor (incluidos los
híbridos `X25519MLKEM768`, `SecP256r1MLKEM768` y `SecP384r1MLKEM1024`) y **qué obtiene realmente un
cliente moderno**: distingue entre un servidor que prefiere PQC, uno que sigue la preferencia del
cliente y uno que la admite pero siempre elige el grupo clásico. Para SSH, lee los algoritmos que
anuncia el servidor (`mlkem768x25519-sha256`, `sntrup761x25519-sha512`, etc.).

La técnica es pasiva: solo lee lo que el servidor anuncia en el saludo inicial, como un navegador,
sin autenticarse ni enviar datos.

> ⚠️ **Analiza solo servidores propios o para los que tengas autorización.**

### En GitHub (integración continua)

Añade este archivo a tu repositorio como `.github/workflows/cuantario.yml`. Los hallazgos aparecerán en la
pestaña **Security → Code scanning** y en cada pull request, junto a la línea afectada. El informe
completo se muestra en el resumen de cada ejecución.

```yaml
name: Cuantario
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  pqc:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: alegarlinx/cuantario@v0.4.0
        id: radar
        with:
          perfil: ccn          # eu o ccn
          fail-on: CRITICO     # opcional: bloquea el merge si hay hallazgos críticos
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: ${{ steps.radar.outputs.sarif }}
      - uses: actions/upload-artifact@v6
        if: always()
        with:
          name: inventario-criptografico
          path: |
            ${{ steps.radar.outputs.cbom }}
            ${{ steps.radar.outputs.informe }}
```

| Opción | Significado |
|---|---|
| `--perfil eu\|ccn` | Hitos UE; `ccn` añade notas de las guías CCN-STIC |
| `--riesgo alto\|medio` | Alto: infraestructura crítica, salud, finanzas, administración |
| `--vida-datos N` | Años que los datos deben seguir siendo confidenciales |
| `--anos-migracion N` | Años estimados para completar la migración |
| `--ano-crqc N` | Año supuesto de un ordenador cuántico criptográficamente relevante |
| `--confianza-min` | Descarta hallazgos por debajo de ese nivel de confianza |
| `--fail-on` | Devuelve código 1 si hay hallazgos de esa prioridad o superior |
| `--tls HOST[:PUERTO]` | Servidor TLS a analizar en vivo (repetible) |
| `--ssh HOST[:PUERTO]` | Servidor SSH a analizar en vivo (repetible) |
| `--timeout N` | Segundos de espera por conexión (5 por defecto) |
| `--sarif ARCHIVO` | Genera también un informe SARIF 2.1.0 |

## Cobertura actual

| Fuente | Método | Confianza |
|---|---|---|
| Python | Árbol sintáctico (AST): llamadas a `cryptography`, PyCryptodome, `hashlib` | alta / media |
| Certificados PEM/DER | Análisis X.509 | alta |
| Configuración (sshd, nginx, YAML, JSON…) | Patrones | media |
| Otros lenguajes | Patrones | baja |
| Servidores TLS 1.2 / 1.3 en vivo | Sondeo de grupos, cifrado negociado y certificado | alta |
| Servidores SSH en vivo | Lectura del KEXINIT | alta |
| Claves privadas en el repositorio | Patrones (siempre ocultadas en la salida) | alta |

## Hoja de ruta

- [x] Análisis sintáctico de Python y niveles de confianza
- [x] Tests automáticos e integración continua
- [x] Escaneo en vivo de servidores TLS/SSH
- [x] Salida SARIF y GitHub Action
- [ ] Análisis sintáctico de Java, Go y JavaScript
- [ ] Caso de estudio sobre proyectos públicos

## Herramientas relacionadas

Cuantario no es la única herramienta de inventario criptográfico. Estas son algunas de las que existen
en Europa, para que puedas elegir la más adecuada:

| Herramienta | Origen | Tipo | Enfoque |
|---|---|---|---|
| CryptoBOM-Forge (Banco Santander) | España | Código abierto | Genera CBOM a partir de análisis de código |
| PCert (Data-Warehouse) | Alemania | Comercial | Servidores, registros y red |
| SSHerlock (SSH.com) | Finlandia | Comercial | Servidores y claves SSH |
| COMPASS (CryptoNext Security) | Francia | Comercial | Descubrimiento e inventario a escala empresarial |

**Qué aporta Cuantario:** es gratuito y de código abierto; combina en una sola herramienta el análisis de
código, de servidores TLS/SSH en vivo y la integración con GitHub; prioriza con la desigualdad de Mosca y
los hitos europeos (con un perfil específico del CCN); y detecta cuándo un servidor admite criptografía
post-cuántica pero no la usa.

## Limitaciones

Cuantario es una herramienta de apoyo al inventario, **no una auditoría ni una certificación**.
Los hallazgos de confianza baja deben revisarse manualmente. Contrasta siempre los resultados con la
versión vigente de CCN-STIC 221 y las recomendaciones de ENISA.

## Desarrollo

```bash
pip install -e ".[dev]"
pytest -q
```

## Licencia

Copyright 2026 Alejandro Garcia Linero. Distribuido bajo la [Apache License 2.0](LICENSE).
