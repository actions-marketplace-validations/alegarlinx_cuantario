# Registro de cambios

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
