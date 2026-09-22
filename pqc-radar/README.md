# PQC-Radar

**Inventario criptográfico y priorización post-cuántica con políticas europeas.**

PQC-Radar analiza un repositorio (código, configuraciones TLS/SSH y certificados X.509), detecta la
criptografía que usa, la clasifica según su resistencia a un ordenador cuántico y prioriza la migración
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

```bash
pqc-radar --demo                         # proyecto de ejemplo
pqc-radar ./mi-proyecto --perfil ccn     # con notas del CCN
pqc-radar ./mi-proyecto --vida-datos 20 --anos-migracion 4 --ano-crqc 2033
pqc-radar ./mi-proyecto --confianza-min media --fail-on CRITICO   # para CI
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

## Cobertura actual

| Fuente | Método | Confianza |
|---|---|---|
| Python | Árbol sintáctico (AST): llamadas a `cryptography`, PyCryptodome, `hashlib` | alta / media |
| Certificados PEM/DER | Análisis X.509 | alta |
| Configuración (sshd, nginx, YAML, JSON…) | Patrones | media |
| Otros lenguajes | Patrones | baja |
| Claves privadas en el repositorio | Patrones (siempre ocultadas en la salida) | alta |

## Hoja de ruta

- [x] Análisis sintáctico de Python y niveles de confianza
- [x] Tests automáticos e integración continua
- [ ] Escaneo en vivo de servidores TLS/SSH
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

Apache-2.0
