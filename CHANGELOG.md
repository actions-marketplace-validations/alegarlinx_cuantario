# Registro de cambios

## 0.8.0
- Modo estudio (`--estudio lista.txt`): mide una lista de dominios en paralelo y genera un resumen con
  porcentajes y metodología, sin nombres, más un JSON con los datos por dominio para uso privado.
  Distingue los dominios que no se pudieron medir (y por qué) de los que no admiten PQC.
- `--lista` para analizar muchos servidores TLS en el modo normal. Acepta el formato `rango,dominio` de Tranco.
- `scripts/preparar_lista.py` extrae los N primeros dominios de un TLD de una lista de Tranco.
- Guía del estudio en `ESTUDIO.md`.
- La medición TLS se separa en un perfil estructurado (`probe_tls`) y su conversión en hallazgos
  (`tls_detections`).

## 0.7.0
- TLS 1.0 y 1.1 se detectan con un ClientHello propio por versión. Antes, un servidor que solo aceptaba
  TLS 1.0 daba 0 hallazgos sin avisar, porque OpenSSL 3 se niega a negociar esas versiones.
- Un reset de conexión (WAF, rate limit) se reintenta con espera exponencial y, si persiste, se informa como
  error de red en lugar de como "grupo no soportado". Un cierre ordenado sí cuenta como rechazo.
- Se analiza la cadena completa de certificados: se lee del handshake de TLS 1.2, se comprueba que cada
  certificado firma al anterior y se valida contra el almacén del sistema. En servidores solo TLS 1.3 se usa
  `get_unverified_chain()` en Python 3.13+.
- Las sondas de un host se lanzan en paralelo con límite de hilos y pausa mínima entre conexiones; los hosts
  también se analizan en paralelo (`--hosts-paralelos`, `--intervalo`).
- Grupos TLS, suites de cifrado y algoritmos SSH se mapean directamente a reglas, sin pasar por texto.
  La suite negociada en TLS 1.2 y anteriores se lee del ServerHello, sin depender de la librería ssl.
- Análisis de Python con ámbitos: los imports locales no se filtran a otras funciones, los parámetros y las
  reasignaciones tapan a los módulos, los métodos no ven los atributos de su clase, y se siguen las
  reasignaciones de funciones criptográficas (`md5 = hashlib.md5`).
- Los archivos se leen como UTF-8 o UTF-16 con BOM; los que no se pueden decodificar o superan 2 MB se
  listan como omitidos en el informe y se avisa en la consola.
- `Finding` se divide en `Detection` (lo encontrado) y `Assessment` (prioridad y motivo). La evidencia es un
  objeto (`snippet`, `notes`, `server_preference`) en lugar de texto concatenado.
- `SecurityUse`, `Profile` y `ServerPreference` pasan a ser `Enum`. Todos los `Enum` usan identificadores en
  inglés y etiquetas en español para mostrar; el CBOM y el SARIF usan los identificadores.
- Las claves de host RSA de SSH cuentan como firma, no como intercambio de claves.
- La versión se lee de los metadatos del paquete (`importlib.metadata`).
- Tests reorganizados por módulo con fixtures en `conftest.py`; incluyen servidores OpenSSL y OpenSSH reales.
- `probes.py` se divide en `net.py`, `tls.py` y `ssh.py`.

## 0.6.0
- Estados, prioridades, confianza, primitivas y orígenes pasan a ser `Enum`. Los valores en el CBOM,
  el SARIF y el informe no cambian.
- `Finding` es inmutable y solo admite argumentos con nombre. `extra` se sustituye por campos tipados
  (`key_size`, `cert`). `hndl` pasa a llamarse `harvest_risk`.
- La prioridad se calcula en un único sitio (`model.assess`); los detectores solo producen hallazgos.
- La CLI valida hosts, puertos, años y timeout antes de empezar.
- Los parsers de TLS y SSH comprueban longitudes antes de leer: un servidor que responde basura
  produce `ProtocolError` en lugar de tumbar el escaneo. Probado con fuzzing (hypothesis).
- Una sonda TLS que no responde ya no descarta el resto del host: se indica qué grupos quedaron sin
  respuesta y la confianza baja a media. Un puerto cerrado se informa como no accesible en lugar de
  aparecer como analizado sin hallazgos.
- El detector de Python resuelve alias de importación (`import hashlib as h`, `from hashlib import md5`).
- HMAC-SHA1 y HMAC-MD5 salen como prioridad baja con explicación, no como críticos.
- `hashlib.md5`/`sha1` en código: prioridad baja con `usedforsecurity=False` y media si no se sabe el uso.
  En configuración siguen siendo críticos.
- Se detecta el modo CBC sin autenticación.
- Las exclusiones de las listas de cifrados (`!MD5`, `!RC4`) ya no cuentan como usos.
- El código del `--demo` sale de la CLI a `cuantario/demo.py`.
- `ruff` y `mypy --strict` en CI.

## 0.5.3
- El índice de preparación se divide en dos: **intercambio de claves y cifrado** (lo urgente, expuesto a
  "cosechar ahora, descifrar después") y **firmas y certificados**. Antes se mezclaban, y servidores
  punteros como los de Cloudflare o Google obtenían una nota engañosamente baja.
- Los grupos clásicos mantenidos como respaldo junto a uno híbrido ya no restan en el índice.
- El informe explica cómo interpretar ambos índices.

## 0.5.2
- Validado contra servidores reales con criptografía post-cuántica (Cloudflare y Google):
  detecta correctamente `X25519MLKEM768`, `MLKEM1024` y la preferencia del servidor.
- La conclusión de la desigualdad de Mosca ahora depende de lo encontrado: solo avisa de urgencia
  si hay cifrado o intercambio de claves clásico sin protección post-cuántica.
- El informe incluye una sección "Correcto" con la criptografía que no requiere acción.
- `.gitignore` excluye los entornos virtuales de Python.

## 0.5.1
- **Imagen Docker** publicada en `ghcr.io/alegarlinx/cuantario`: se construye y se prueba en cada
  cambio, y solo se publica si supera la prueba. Se ejecuta sin privilegios de administrador.
- Instalación directa desde GitHub (`pip install git+https://github.com/alegarlinx/cuantario.git`).
- Cada release adjunta automáticamente el paquete instalable.
- Publicación en PyPI preparada con Trusted Publishing (sin tokens); se activa con la variable
  del repositorio `PUBLISH_PYPI`.
- Comprobación automática de que la etiqueta de la release coincide con la versión del paquete.
- Metadatos de empaquetado modernizados (licencia SPDX, enlaces del proyecto, clasificadores).
- Compatibilidad verificada con cryptography 50.
- La salida cortada (p. ej. `cuantario ... | head`) ya no muestra un error.

## 0.5.0
- El proyecto pasa a llamarse **Cuantario** (antes PQC-Radar), para evitar confusión con otras
  publicaciones del sector que usan ese nombre. Cambian el paquete (`cuantario`), el comando
  (`cuantario`), el repositorio y la Action (`alegarlinx/cuantario`, "Cuantario PQC Scanner").
- Nombres de salida por defecto: `cuantario_cbom.json` y `cuantario_informe.md`.
- Nueva sección de herramientas relacionadas en el README.

## 0.4.0
- Salida SARIF 2.1.0 (`--sarif`) para GitHub Code Scanning, con huellas estables entre ejecuciones.
- GitHub Action reutilizable (`action.yml`), con el informe en el resumen de la ejecución y
  protección frente a inyección de comandos.
- El CBOM y el SARIF se validan en CI contra los esquemas oficiales de CycloneDX 1.6 y SARIF 2.1.0.
- CI actualizado a acciones con Node.js 24 y Dependabot para mantenerlas al día.

## 0.3.0
- Escaneo en vivo de servidores TLS: grupos aceptados (incluidos híbridos ML-KEM), preferencia del
  servidor, cifrado negociado y certificado.
- Escaneo en vivo de servidores SSH: intercambio de claves, claves de host y cifrados.
- Reconocimiento de `sntrup761x25519-sha512` como híbrido.
- El índice de preparación muestra "sin datos" en lugar de 100/100 cuando no hay nada que evaluar.
- Sección de objetivos no accesibles en el informe.

## 0.2.0
- Análisis sintáctico (AST) para Python y niveles de confianza por hallazgo.
- Tests automáticos, integración continua y estructura de paquete.
- Licencia Apache 2.0.

## 0.1.0
- Primer prototipo: inventario por patrones, certificados, CBOM CycloneDX 1.6 e informe en español.
