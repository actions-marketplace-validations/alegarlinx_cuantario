# Cómo hacer un estudio de preparación post-cuántica

Guía para medir una lista de dominios (por ejemplo, los 200 `.es` más visitados) y publicar solo
estadísticas agregadas.

## 1. Lista de dominios

Descarga la lista del día de [Tranco](https://tranco-list.eu/), la que usan los estudios académicos de
medición web, y apunta su identificador: aparece en la web y permite que otros repitan el estudio con
exactamente la misma lista.

```bash
curl -LO https://tranco-list.eu/top-1m.csv.zip && unzip top-1m.csv.zip
python scripts/preparar_lista.py top-1m.csv --tld es --n 200 > dominios_es.txt
```

## 2. Medición

```bash
cuantario --estudio dominios_es.txt --salida es_2026-09 \
  --fuente "Tranco, lista XXXXX, 200 primeros dominios .es" \
  --hosts-paralelos 4 --intervalo 0.2 --timeout 5
```

Genera dos ficheros:

- `es_2026-09_resumen.md`: porcentajes y metodología, sin nombres. Es lo que se publica.
- `es_2026-09_datos.json`: el resultado de cada dominio. **No se publica**; sirve para revisar los datos y
  para repetir el análisis.

Con esos parámetros, 200 dominios tardan unos minutos. Cada dominio recibe unas 15 conexiones, repartidas en
el tiempo.

## 3. Revisión antes de publicar

- Mira cuántos dominios no se pudieron medir y por qué. Si hay muchos "reset repetido", sube `--intervalo` y
  repite: probablemente un WAF está cortando.
- Repite la medición otro día. Si los porcentajes cambian mucho, dilo en la publicación: los CDN cambian
  de configuración a menudo.
- Busca en el JSON los casos raros (por ejemplo, dominios que aceptan TLS 1.0) y compruébalos a mano con
  `cuantario --tls dominio`.

## 4. Publicación

- Publica el resumen, el comando exacto y el identificador de la lista de Tranco.
- No nombres dominios concretos como vulnerables. Si encuentras algo grave en un servicio concreto, avisa en
  privado a su responsable antes de mencionarlo en ningún sitio.
- Si algún responsable te pide que no midas su dominio, quítalo de la lista.

La medición solo hace lo que haría un navegador al conectarse (el saludo TLS) y no envía datos de
aplicación. Aun así, no es asesoramiento legal: si el estudio va a formar parte de un trabajo académico o
profesional, consúltalo con quien corresponda.
