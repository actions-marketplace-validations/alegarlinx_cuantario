# PQC-Radar

**Inventario criptográfico y priorización post-cuántica con políticas europeas.**

PQC-Radar analiza un repositorio (código, configuraciones TLS/SSH y certificados X.509) **y servidores
TLS/SSH en vivo**, detecta la criptografía que usa, la clasifica según su resistencia a un ordenador cuántico y prioriza la migración
según los hitos del **roadmap coordinado de la UE** (2026 / 2030 / 2035) y, opcionalmente, las
autorizaciones del **CCN** español.

Genera un **CBOM** estándar (CycloneDX 1.6) y un **informe de migración en español**.

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
pqc-radar --demo                         # proyecto de ejemplo
pqc-radar ./mi-proyecto --perfil ccn     # con notas del CCN
pqc-radar ./mi-proyecto --vida-datos 20 --anos-migracion 4 --ano-crqc 2033
pqc-radar ./mi-proyecto --confianza-min media --fail-on CRITICO   # para CI
```

### Servidores en vivo

```bash
pqc-radar --tls ejemplo.es                       # puerto 443
pqc-radar --tls ejemplo.es:8443 --ssh ejemplo.es  # varios objetivos a la vez
pqc-radar ./mi-proyecto --tls ejemplo.es         # código y servidor en el mismo informe
```

Para TLS, PQC-Radar detecta qué grupos de intercambio de claves acepta el servidor (incluidos los
híbridos `X25519MLKEM768`, `SecP256r1MLKEM768` y `SecP384r1MLKEM1024`) y **qué obtiene realmente un
cliente moderno**: distingue entre un servidor que prefiere PQC, uno que sigue la preferencia del
cliente y uno que la admite pero siempre elige el grupo clásico. Para SSH, lee los algoritmos que
anuncia el servidor (`mlkem768x25519-sha256`, `sntrup761x25519-sha512`, etc.).

La técnica es pasiva: solo lee lo que el servidor anuncia en el saludo inicial, como un navegador,
sin autenticarse ni enviar datos.

> ⚠️ **Analiza solo servidores propios o para los que tengas autorización.**

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
- [ ] Salida SARIF (GitHub Code Scanning)
- [ ] Análisis sintáctico de Java, Go y JavaScript
- [ ] Caso de estudio sobre proyectos públicos

## Limitaciones

PQC-Radar es una herramienta de apoyo al inventario, **no una auditoría ni una certificación**.
Los hallazgos de confianza baja deben revisarse manualmente. Contrasta siempre los resultados con la
versión vigente de CCN-STIC 221 y las recomendaciones de ENISA.

## Desarrollo

```bash
pip install -e ".[dev]"
pytest -q
```

## Licencia

Copyright 2026 Alejandro Garcia Linero. Distribuido bajo la [Apache License 2.0](LICENSE).
