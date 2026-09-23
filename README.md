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

Para analizar muchos servidores, `--lista fichero.txt` (uno por línea). Para un estudio con estadísticas
agregadas y sin nombres, `--estudio`: ver [ESTUDIO.md](ESTUDIO.md).

`cuantario --help` lista todas las opciones. Las que más se usan:

- `--vida-datos`, `--anos-migracion`, `--ano-crqc`: parámetros de la desigualdad de Mosca. Con los valores
  por defecto (10, 5 y 2035) cualquier intercambio de claves clásico sin respaldo híbrido sale como crítico.
- `--riesgo medio`: para sectores fuera de alto riesgo, las firmas vulnerables bajan de ALTO a MEDIO.
- `--confianza-min media`: descarta los hallazgos que salen de buscar texto en código.
- `--hosts-paralelos` (4) e `--intervalo` (0,1 s): cuántos servidores se analizan a la vez y la pausa mínima
  entre conexiones a un mismo servidor.
- `--sarif archivo.sarif`: salida para GitHub Code Scanning.

Código de salida: `0`, o `1` si se usa `--fail-on` y hay hallazgos de esa prioridad o superior. Los errores
de uso salen con `2`. Los ficheros de salida se sobrescriben.

## Ejemplo de salida

Un servidor OpenSSL 3.0 configurado para aceptar solo TLS 1.0, con un certificado firmado por una CA propia:

```text
$ cuantario --tls localhost:15010 --salida ejemplo
Cuantario 0.7.0 · 7 hallazgos en 'escaneo-remoto'
  Preparación PQC · intercambio de claves: 0/100 · firmas y certificados: 0/100
  CRITICO  3
  ALTO     1
  BAJO     3
Salidas: ejemplo_cbom.json · ejemplo_informe.md
```

Extracto de `ejemplo_informe.md`:

| Activo | Evidencia | Motivo |
|---|---|---|
| Protocolo TLS 1.0/1.1 | `TLS 1.0 aceptado` | Inseguro ya hoy, sin necesidad de un ordenador cuántico. |
| ECDH / X25519 / X448 | `TLS 1.0 · ECDHE-RSA-AES128-SHA · sin TLS 1.3 no es posible el intercambio híbrido post-cuántico` | Mosca: 2026 + 10 años de vida del dato + 5 de migración > 2035. |
| Certificado RSA-2048 (intermedio 1) | `RSA 2048 bits · hash sha256 · caduca 20/09/2036 · CN=CA de prueba` | Caduca después de 2030 con firma vulnerable: incumple el hito UE de alto riesgo. |
| Modo CBC sin autenticación | `TLS 1.0 · ECDHE-RSA-AES128-SHA · …` | CBC no autentica: sin un MAC aparte admite manipulación del mensaje. |
| HMAC con MD5 o SHA-1 | `TLS 1.0 · ECDHE-RSA-AES128-SHA · …` | No está roto: lo que falla en MD5 y SHA-1 son las colisiones. |

## Cómo detecta

| Fuente | Método | Confianza |
|---|---|---|
| Python | AST con ámbitos: sigue alias de importación y reasignaciones (`md5 = hashlib.md5`) | alta / media |
| Certificados PEM/DER | parseo X.509 | alta |
| Configuración (sshd, nginx, YAML, JSON…) | expresiones regulares | media |
| Otros lenguajes | expresiones regulares | baja |
| TLS en vivo | handshakes propios, sin la librería ssl | alta |
| SSH en vivo | lectura del KEXINIT | alta |

**TLS.** Para cada versión antigua (1.0, 1.1, 1.2) se manda un ClientHello propio que solo ofrece esa
versión; así se detectan servidores que OpenSSL 3 ni siquiera deja conectar. Para TLS 1.3 se manda uno por
grupo con el `key_share` vacío: si el servidor lo acepta, responde con un HelloRetryRequest que lo nombra.
Después se ofrecen los grupos clásicos y los post-cuánticos en los dos órdenes para ver cuál elige el
servidor, porque hay servidores que admiten `X25519MLKEM768` pero nunca lo usan. La cadena de certificados se
lee del handshake de TLS 1.2, que va en claro, se comprueba que cada certificado firma al anterior y se
valida contra el almacén de certificados del sistema.

Un reset de conexión (lo típico de un WAF o un rate limit) se reintenta con espera creciente y, si persiste,
se informa como error de red, nunca como "no soportado". Si una sonda no responde, el resultado del host se
marca como incompleto y baja a confianza media.

**Python.** `hashlib.md5()` o `sha1()` salen con prioridad media porque pueden ser un simple checksum; con
`usedforsecurity=False` bajan a baja. HMAC-SHA1 no se trata como roto. Las exclusiones de las listas de
cifrados (`!MD5`) no cuentan como uso.

Solo se lee lo que el servidor anuncia en el saludo, igual que un navegador. Aun así, analiza únicamente
servidores propios o con permiso.

## Validación

| Objetivo | Cómo se comprueba | Esperado | Obtenido |
|---|---|---|---|
| OpenSSL 3.0, solo TLS 1.0 | test automático | TLS 1.0 detectado y cadena de 2 certificados | sí |
| OpenSSL 3.0, solo TLS 1.2 | test automático | aviso de que sin TLS 1.3 no hay PQC | sí |
| OpenSSL 3.0, TLS 1.3 sin PQC | test automático | X25519 y P-256 como críticos; cadena completa | sí |
| OpenSSL 3.0, solo TLS 1.3 | test automático | cadena completa en Python 3.13+, solo hoja antes | sí |
| OpenSSL 3.0 con un intermedio que no es el emisor | test automático | "Cadena rota" en la hoja | sí |
| OpenSSH 9.6 | test automático (si hay `sshd`) | `sntrup761x25519` OK, resto como respaldo, `hmac-sha1` bajo | sí |
| Servidor que responde con RST | test automático | reintento y error de red, nunca "no soportado" | sí |
| Servidor que responde basura | fuzzing (hypothesis) | `ProtocolError`, nunca un fallo sin capturar | sí |
| cloudflare.com | manual, v0.5.2 | `X25519MLKEM768`, preferido por el servidor | sí |
| google.com | manual, v0.5.2 | `X25519MLKEM768` y `MLKEM1024`, preferido por el servidor | sí |

Los tests automáticos se ejecutan en CI con Python 3.10 a 3.13. Los servidores públicos se comprobaron a mano
con la v0.5.2 y no se vuelven a verificar en CI.

## Índice de preparación

El informe da dos índices. El de intercambio de claves es el urgente, porque el tráfico de hoy se puede
guardar y descifrar más adelante. El de firmas y certificados sale bajo casi en cualquier servidor, porque los
certificados post-cuánticos todavía no se usan en la web. Un X25519 que se mantiene como fallback junto a un
grupo híbrido no penaliza.

## Limitaciones conocidas

- Fuera de Python la detección es por texto y da falsos positivos; por eso existe `--confianza-min`.
- El análisis de Python no sigue el flujo de control (se queda con la última asignación vista), ni imports
  entre módulos, ni llamadas dinámicas (`getattr`, `importlib`).
- En servidores que solo hablan TLS 1.3, la cadena completa solo se obtiene con Python 3.13 o superior; antes,
  solo el certificado hoja.
- La validación de la cadena usa el almacén de certificados del equipo donde se ejecuta.
- Solo se sondean los grupos TLS de la tabla de `tls.py` (híbridos ML-KEM, ML-KEM puro, X25519, P-256 y P-384).
- No soporta STARTTLS (SMTP, IMAP, LDAP…), DTLS ni QUIC: solo TLS directo sobre TCP.
- Cada servidor TLS recibe unas 15 conexiones. Los WAF muy estrictos pueden bloquear el análisis; en ese caso
  sube `--intervalo`.
- La imagen Docker solo se publica para amd64.
- No sustituye a una auditoría. Las referencias al CCN y a ENISA conviene contrastarlas con la versión vigente
  de cada guía.

Otras herramientas del mismo espacio: CryptoBOM-Forge (Santander, open source, solo código), PCert
(Data-Warehouse), SSHerlock (SSH.com) y COMPASS (CryptoNext).

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
      - uses: alegarlinx/cuantario@v0.7.0
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

## Desarrollo

```bash
pip install -e ".[dev]"
pytest
ruff check cuantario tests
mypy cuantario
```

Apache 2.0.
