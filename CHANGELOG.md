# Registro de cambios

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
