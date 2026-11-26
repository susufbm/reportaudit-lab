# Laboratorio 1 — Bitácora de auditoría de la cadena de suministro

- **Autor/a:** Jesus Fernandez
- **Repositorio:** https://github.com/susufbm/reportaudit-lab
- **Sistema operativo y versión de Python usados:** Windows 11 + WSL2 con Ubuntu 24.04.5 LTS, Python 3.12.3

- **SonarQube Cloud:** Organization Key `susufbm` · Project Key `susufbm_reportaudit-lab` · Automatic Analysis desactivado · token `reportaudit-ci` guardado como `SONAR_TOKEN` en Actions y en Dependabot

> Completa cada sección en el momento en que la guía te lo pide, no al final.
> Una bitácora escrita "de memoria" al terminar no sirve como evidencia.

---

## Parte B — Auditoría manual (antes de usar ninguna herramienta)

| # | Función | Línea | Qué sospechas | Dato de entrada (*source*) | Destino peligroso (*sink*) |
|---|---|---|---|---|---|
| 1 | `buscar_reportes_cliente` | 41 | Inyección SQL: la consulta se monta concatenando el nombre del cliente dentro del texto SQL | Parámetro `cliente` de la URL (`servicio.py`, línea 41) | `cursor.execute(query)` (línea 42) |
| 2 | `convertir_a_pdf` | 50 | Inyección de comandos: el nombre de archivo se pega en un comando que ejecuta la shell, así que un `;` o un `&` añade órdenes nuevas | Parámetro `archivo` de la URL (`servicio.py`, línea 53) | `os.system(comando)` (línea 51) |
| 3 | `cargar_configuracion` | 33 | Deserialización YAML insegura: `yaml.Loader` puede construir objetos Python arbitrarios a partir de etiquetas `!!python/...` | Contenido de `app/config.yaml` (no viene del usuario, pero quien pueda tocar ese archivo controla lo que se ejecuta) | `yaml.load(f, Loader=yaml.Loader)` (línea 33) |
| 4 | `hash_password_legacy` | 57 | Hash débil: MD5 sin sal ni iteraciones; se rompe con tablas precalculadas o fuerza bruta en muy poco tiempo | Argumento `password` | `hashlib.md5(...)` (línea 57) |
| 5 | Constantes del módulo | 21-22 | Secretos escritos en el código: la clave de la API de notificaciones y la contraseña SMTP están en texto plano y quedan en el historial de Git | El propio código fuente (cualquiera que lea el repositorio) | `NOTIFICATION_API_KEY` (línea 21) y `SMTP_PASSWORD` (línea 22) |

**Impacto en el negocio:** para cada sospecha, explica en una frase qué
consecuencia tendría para ReportAudit y sus clientes si fuera real (qué datos,
qué sistema o qué credencial quedarían expuestos).

1. **SQL:** cualquiera podría leer los reportes de otros clientes (por ejemplo con `' OR '1'='1`) o alterar la base de datos. Es una fuga de datos financieros de clientes.
2. **Comandos:** quien llame a `/convertir` podría ejecutar cualquier orden en el servidor con los permisos del servicio: leer la base de datos, los secretos o instalar algo.
3. **YAML:** si alguien modifica `config.yaml` (otra persona del equipo, un despliegue comprometido), puede ejecutar código al arrancar el servicio.
4. **MD5:** si se filtra la tabla de contraseñas del sistema legado, se recuperarían casi todas las contraseñas de los clientes, que muchos reutilizan en otros sitios.
5. **Secretos:** al estar el repositorio en GitHub, cualquiera puede usar la clave de la API para mandar notificaciones en nombre de ReportAudit y la contraseña SMTP para enviar correos desde nuestra cuenta. Hay que rotarlas, no basta con borrar la línea.

**Síntoma observado (Paso C.2):** al pedir `http://127.0.0.1:8087/reportes?cliente=o'brien_ltd` el servicio devuelve *500 Internal Server Error* y en la terminal aparece:

```
File "/home/susu/reportaudit-lab/app/reporte_auditoria.py", line 42, in buscar_reportes_cliente
    cursor.execute(query)
sqlite3.OperationalError: near "brien_ltd": syntax error
```

El apóstrofo cierra la cadena de la consulta antes de tiempo y `brien_ltd'` se interpreta como SQL. Es el mismo mecanismo que permite la inyección; la solución es una consulta parametrizada, no prohibir apóstrofos.

---

## Matriz de detección (se completa a lo largo del laboratorio)

Marca ✓ (lo detectó, anota la regla) o ✗ (no lo detectó) en cada columna cuando
llegues a la parte correspondiente.

| Hallazgo | Manual (B) | SonarQube for IDE sin conexión (D) | SonarQube for IDE en Connected Mode (E) | SonarQube Cloud (F) | CodeQL (F) | Semgrep (G) | Trivy (K) |
|---|---|---|---|---|---|---|---|
| H1 Inyección SQL en `buscar_reportes_cliente` | ✓ | ✗ | ✓ taint: SQL Injection via URL query parameter | ✓ pythonsecurity:S3649 | ✓ py/sql-injection (high) | ✗ | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` | ✓ | ✗ | ✓ taint: Command Injection via URL query parameter | ✓ pythonsecurity:S2076 | ✓ py/command-line-injection (critical) | ✗ | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` | ✓ | ✗ | ✗ | ✗ | ✗ | ✓ python.lang.security.deserialization.avoid-pyyaml-load | n/a |
| H4 Hash MD5 en `hash_password_legacy` | ✓ | ✓ python:S4790 (hashing data) | ✓ python:S4790 (hotspot) | ✓ python:S4790 | ✓ py/weak-sensitive-data-hashing (high) | ✓ insecure-hash-algorithm-md5 + md5-used-as-password | n/a |
| H5 Clave de API escrita en el código | ✓ | ✗ | ✗ | ✗ | ✗ (solo py/clear-text-logging-sensitive-data en la línea 62, que imprime parte de la clave) | ✗ | ✗ (0 secretos; el formato no coincide con ningún proveedor conocido) |
| H6 Contraseña SMTP escrita en el código | ✓ | ✓ python:S2068 (contraseña en el código) | ✓ python:S2068 + secrets:S7552 (revocar la contraseña SMTP) | ✓ python:S2068 + secrets:S7552 | ✗ | ✗ | ✗ (0 secretos; el formato no coincide con ningún proveedor conocido) |

**Hallazgos de las herramientas que no estaban en mi auditoría manual (Parte G.8, primera auditoría de main):**

- SonarQube Cloud `python:S4502` en `app/servicio.py:25`: la aplicación Flask no tiene protección CSRF.
- SonarQube Cloud `githubactions:S7637` en `.github/workflows/cadena-suministro.yml:27`: la acción `sonarqube-scan-action@v7` no está fijada por hash (reto de la Parte S.3).
- CodeQL `py/clear-text-logging-sensitive-data` en `app/reporte_auditoria.py:62`: `notificar_cliente` escribe en el log los primeros caracteres de la clave de la API.

**Comparación con la auditoría manual:** en la inyección SQL y en la de comandos, el recorrido de *Show paths* de CodeQL y el de SonarQube coinciden con mi source y mi sink (de `request.args.get` en `servicio.py` a `cursor.execute` y `os.system` en `reporte_auditoria.py`). Ninguna de las dos detectó el YAML inseguro: el archivo de configuración no viene del usuario, así que para ellas no hay un dato "contaminado" que seguir. CodeQL no busca secretos escritos en el código; SonarQube solo detectó la contraseña, porque la variable se llama `PASSWORD`.

**Conclusión de la matriz** (Parte K): ¿alguna herramienta lo detectó todo? ¿Qué
te dice eso sobre depender de una sola herramienta?

Ninguna herramienta detectó los seis hallazgos. La que más cubrió fue SonarQube (Connected Mode y SonarQube Cloud: H1, H2, H4 y H6). Semgrep fue la única en encontrar la deserialización YAML (H3), y la clave de API (H5) no la detectó ninguna herramienta, solo la auditoría manual; CodeQL se acercó al marcar la línea que imprime parte de la clave. Trivy encontró las mismas 13 vulnerabilidades de dependencias que Grype y Dependabot, pero 0 secretos, porque las credenciales de ReportAudit no siguen el formato de ningún proveedor conocido: un escaneo limpio de secretos no demuestra que no haya secretos. A la vez, las herramientas encontraron cosas que yo no vi en la Parte C: la falta de protección CSRF (S4502), el registro en claro de datos sensibles (CodeQL) y las acciones del *workflow* sin fijar por SHA (S7637). La conclusión es que depender de una sola herramienta deja huecos: cada una ve una parte distinta, y hacen falta varias capas (SAST, SCA, secretos y revisión humana) que se complementen.

---

## Parte I — Dependabot: primeras alertas

Dependabot se encendió el 25-nov-2026 y abrió **13 alertas** sobre **3 paquetes**:

| Paquete | Versión en `requirements.txt` | ¿Directa o transitiva? (`# via`) | Alertas | Severidad más alta | Versión que corrige todas |
|---|---|---|---|---|---|
| `werkzeug` | 3.0.1 | Transitiva (`via flask`) | 7 (#3, #4, #8, #9, #10, #12, #13) | **High**: CVE-2024-34069 / GHSA-2g68-c3qc-8985, ejecución remota a través del depurador | 3.1.9 |
| `jinja2` | 3.1.2 | Transitiva (`via flask`) | 5 (#1, #2, #5, #6, #7) | Medium: inyección de atributos HTML y salida del *sandbox* | 3.1.6 |
| `flask` | 3.0.0 | **Directa** (`via -r requirements.in`) | 1 (#11) | Low: CVE-2026-27205, falta la cabecera `Vary: Cookie` | 3.1.3 |

**Alerta analizada en detalle: #3 (Werkzeug, High, CVE-2024-34069).** Versiones afectadas: `< 3.0.3`; la primera corregida es la 3.0.3. Está declarada en `requirements.txt`. Afecta al depurador interactivo de Werkzeug, que podría ejecutar código si un atacante consigue que el desarrollador interactúe con un dominio que él controla. En ReportAudit el servicio arranca con `debug=False` (`app/servicio.py`, línea 64), así que el depurador no está activo. Aun así, se corrige actualizando, porque la dependencia sigue siendo vulnerable.

**Lo que enseña:** de las 13 alertas, 12 están en dependencias **transitivas** que el equipo nunca eligió (las trajo Flask). Solo una está en una dependencia directa. Es el iceberg: lo que no ves es lo que más riesgo acumula.

**PRs de Dependabot:** al encenderlo, `dependabot.yml` todavía no estaba en `main` (iba en el PR #17), así que Dependabot usó su comportamiento por defecto: tres PRs separados (#18 jinja2, #19 werkzeug, #20 flask) con prefijo `chore`. No se fusionan todavía; se integran en la Parte M.

---

## Parte J — SBOM: el iceberg medido

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) | 2: `flask==3.0.0` y `pyyaml==6.0.3` |
| Componentes Python en el SBOM | 9 (blinker, click, colorama, flask, itsdangerous, jinja2, markupsafe, pyyaml, werkzeug), todos leídos de `requirements.txt`. 7 de 9 son transitivos: el iceberg es 2 → 9 |
| Otros componentes que aparezcan en el SBOM (si los hay) y de dónde salen | 4 de tipo `github-action` (`actions/checkout@v6`, `SonarSource/sonarqube-scan-action@v7`, `github/codeql-action/init@v4` y `analyze@v4`), que salen de `.github/workflows/cadena-suministro.yml`. Son dependencias del pipeline, no de la aplicación |
| Formato y versión de especificación del SBOM (`bomFormat`, `specVersion`) | `CycloneDX`, `1.7` (generado con Syft 1.52.0, sin `venv/` ni `tools/`): `docs/evidencias/sbom.cyclonedx.json` |

---

## Parte J — Triage de vulnerabilidades de dependencias (Grype)

| Paquete | Versión | ¿Directa o transitiva? (usa `# via`) | CVE / GHSA | Severidad | Corregida en | ¿Explotable en ReportAudit? ¿Por qué? | Decisión |
|---|---|---|---|---|---|---|---|
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2024-34069 / GHSA-2g68-c3qc-8985 | **High** (EPSS 5,4 %, percentil 93) | 3.0.3 | No: afecta al depurador interactivo de Werkzeug y el servicio arranca con `debug=False` (`app/servicio.py`, línea 64) | Actualizar con el PR de Dependabot (Parte M.5) **y** documentado en el VEX |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2024-49767 / GHSA-q34m-jh98-gwm2 | Medium | 3.0.6 | No: agotamiento de recursos al procesar formularios *multipart*; ReportAudit solo expone rutas `GET` y no lee `request.form` ni `request.files` | Actualizar con el PR de Dependabot (Parte M.5) |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2024-49766 / GHSA-f9vj-2wh5-fj8j | Medium | 3.0.6 | No: `safe_join` en Windows; la app no usa `safe_join` ni `send_from_directory` y se ejecuta en Linux | Actualizar con el PR de Dependabot (Parte M.5) |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2025-66221 / GHSA-hgf8-39gv-g3f2 | Medium | 3.1.4 | No: nombres de dispositivo de Windows en `safe_join`; la app no lo usa y se ejecuta en Linux | Actualizar con el PR de Dependabot (Parte M.5) |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2026-27199 / GHSA-29vq-49wr-vm6x | Medium | 3.1.6 | No: misma familia (`safe_join` en Windows); no se usa | Actualizar con el PR de Dependabot (Parte M.5) |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2026-21860 / GHSA-87hc-h4r5-73f7 | Medium | 3.1.5 | No: misma familia (`safe_join` con extensiones compuestas en Windows); no se usa | Actualizar con el PR de Dependabot (Parte M.5) |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2026-102598 / GHSA-g6x2-hccm-hh4m | Medium | 3.1.9 | No: misma familia (`safe_join` en Windows); no se usa | Actualizar con el PR de Dependabot (Parte M.5) |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2024-22195 / GHSA-h5c8-rqwp-cp95 | Medium | 3.1.3 | No: inyección de atributos en el filtro `xmlattr`; ReportAudit no renderiza plantillas, responde con `jsonify` | Actualizar con el PR de Dependabot (Parte M.5) |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2024-34064 / GHSA-h75v-3vvj-5mfj | Medium | 3.1.4 | No: mismo filtro `xmlattr`; no hay plantillas | Actualizar con el PR de Dependabot (Parte M.5) |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2024-56326 / GHSA-q2x7-8rv6-6q7h | Medium | 3.1.5 | No: salida del *sandbox* de plantillas; no hay plantillas ni *sandbox* | Actualizar con el PR de Dependabot (Parte M.5) |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2024-56201 / GHSA-gmj6-6f8f-6699 | Medium | 3.1.5 | No: salida del *sandbox* con nombres de plantilla maliciosos; no hay plantillas | Actualizar con el PR de Dependabot (Parte M.5) |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2025-27516 / GHSA-cpwx-vrp4-4pq7 | Medium | 3.1.6 | No: salida del *sandbox* con el filtro `attr`; no hay plantillas | Actualizar con el PR de Dependabot (Parte M.5) |
| flask | 3.0.0 | **Directa** (`# via -r requirements.in`) | CVE-2026-27205 / GHSA-68rp-wp8r-4726 | Low | 3.1.3 | No: falta la cabecera `Vary: Cookie` al acceder a la sesión; ReportAudit no usa `session` | Actualizar con el PR de Dependabot (Parte M.5) |

**Comparación con Dependabot** (Parte H): ¿las alertas coinciden con Grype? Explica
cualquier diferencia.

Coinciden exactamente: Grype y Dependabot encuentran las mismas 13 vulnerabilidades (werkzeug 7, jinja2 5, flask 1) con los mismos GHSA y las mismas versiones corregidas. Dependabot lee `requirements.txt` desde GitHub; Grype lee el SBOM que generó Syft a partir del mismo archivo, así que ven el mismo inventario. Grype añade EPSS y RISK, que ayudan a priorizar: la alerta High de werkzeug (GHSA-2g68-c3qc-8985) tiene un EPSS del 5,4 % (percentil 93).

**Documento VEX:** copia `plantillas/reportaudit.openvex.json` a
`docs/evidencias/`, rellénalo, enlázalo aquí y resume en una frase la
justificación.

[`docs/evidencias/reportaudit.openvex.json`](evidencias/reportaudit.openvex.json): CVE-2024-34069 (GHSA-2g68-c3qc-8985) en `pkg:pypi/werkzeug@3.0.1` queda como `not_affected` con la justificación `vulnerable_code_not_in_execute_path`, porque la vulnerabilidad está en el depurador interactivo de Werkzeug y ReportAudit lo tiene desactivado (`debug=False` en `app/servicio.py`, línea 64, el único `app.run` del repositorio). Aun así, werkzeug se actualizará a 3.1.9 en la Parte M.5.

---

## Parte M — Corrección

**PR de auditoría:** #22 (`fix/auditoria-seguridad`), dos commits:

1. Las cinco correcciones de la guía: consulta parametrizada, `subprocess.run` con lista de argumentos y lista blanca, `yaml.safe_load`, PBKDF2-HMAC-SHA256 con sal y 600.000 iteraciones, y credenciales leídas del entorno. Además, `notificar_cliente` ya no escribe parte de la clave en el log.
2. Al analizar el PR, SonarQube Cloud marcó `pythonsecurity:S6350` (*argument injection*): la lista blanca de la guía solo validaba `Path(nombre).name`, así que `-x/informe.html` (una opción para `wkhtmltopdf`) y `../../tmp/informe.html` (*path traversal*) devolvían **200**. Ahora se valida el nombre completo con `fullmatch` y los dos devuelven **400**.

**Verificación (M.2):** `acme_corp` → 2 reportes; `o'brien_ltd` → 1 reporte (antes, error 500); `informe.html` → 200; `informe final.html`, `x.html;id`, `-x/informe.html`, `../../tmp/informe.html` y `-informe.html` → 400; `pre-commit run --all-files` → *Passed*.

**Resultado en main (M.4):** CodeQL con 0 alertas abiertas (`py/sql-injection`, `py/command-line-injection`, `py/weak-sensitive-data-hashing` y `py/clear-text-logging-sensitive-data` en *Fixed*). SonarQube Cloud: 0 vulnerabilidades en `app/reporte_auditoria.py` y 0 hotspots. Quedan 2 que no son de este archivo: `githubactions:S7637` (fijar las acciones por SHA, reto de la Parte S.3) y `python:S4502` (CSRF en `servicio.py`; el servicio solo expone rutas `GET` que no cambian estado y no usa cookies de sesión). El Quality Gate del PR falló solo por cobertura (0 %, el proyecto no tiene tests), que no es una condición de seguridad.

**Dependencias (M.5):** los PRs de Dependabot #18, #19 y #20 se crearon antes de que `dependabot.yml` estuviera en `main`. Se fusionó #19 (werkzeug 3.0.1 → 3.1.9, la alerta High). Al pedir `@dependabot rebase`, Dependabot respondió que la entrada que los creó ya no existía y pidió cerrarlos; se cerraron #18 y #20 para que abriera un único PR agrupado (`parches-de-seguridad`) con jinja2 y flask. Como el PR agrupado no llegaba, regeneré el lockfile con `pip-compile --upgrade-package flask==3.1.3 --upgrade-package jinja2==3.1.6 --upgrade-package blinker --upgrade-package itsdangerous` en el PR #23 (`Closes #6`). El resultado es idéntico al que proponía Dependabot. Después de fusionarlo: `git pull` y `python -m pip install -r requirements.txt` para actualizar el entorno local.

**¿Por qué mi PR de código no cerró las alertas de Dependabot, y el de Dependabot no cerró las de CodeQL?** Porque miran cosas distintas. Las alertas de CodeQL (SAST) están en **nuestro código**: desaparecen cuando el análisis de `main` ya no encuentra el patrón en `reporte_auditoria.py`, y eso solo lo cambia mi PR. Las alertas de Dependabot (SCA) están en las **versiones** que declara `requirements.txt`: se cierran cuando el grafo de dependencias ve una versión corregida, y eso solo lo cambia el PR de Dependabot. Cada herramienta se cierra con la corrección de su propia categoría.

---

## Parte L y M — Antes y después

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` | 3 (3 blocking) | 0 (`pre-commit run --all-files` → *Passed*) |
| Alertas abiertas de CodeQL (Security → Code scanning) | 4 | 0 (las 4 en *Closed* con motivo *Fixed*) |
| Vulnerabilidades en SonarQube Cloud (rama main) | 7 (6 en `app/` + 1 en el workflow) | 2, ninguna en `reporte_auditoria.py`: `githubactions:S7637` (acciones sin fijar por SHA, Parte S.3) y `python:S4502` (CSRF en `servicio.py`, que solo expone rutas `GET` sin estado) |
| Security Hotspots por revisar en SonarQube Cloud | 0 | 0 |
| Vulnerabilidades de Grype sobre el SBOM | 13 (werkzeug 7, jinja2 5, flask 1; 1 High, 11 Medium, 1 Low) | 0 (*No vulnerabilities found*, `docs/evidencias/grype-despues.txt`). Trivy: 0 (`trivy-despues.txt`) |
| Alertas abiertas de Dependabot | 13 (werkzeug 7, jinja2 5, flask 1) | 6 abiertas en el panel al medir (jinja2 y flask), 7 en *Fixed*: el grafo de dependencias de GitHub ya ve jinja2 3.1.6 y flask 3.1.3 y Grype da 0, así que se cerrarán solas al recalcular |

---

## Preguntas de comprobación (Sección 7 de la guía)

1. **Windows** tiene VS Code (la ventana), el navegador y la guía. **Ubuntu (WSL2)** tiene el repositorio clonado, Python y el `venv`, las herramientas (`tools/`: Syft, Grype, Trivy), el hook de `pre-commit` y el servicio en marcha; VS Code se conecta a Ubuntu con la extensión WSL. **GitHub** tiene el repositorio remoto, los Issues, los PRs con su protección de rama, GitHub Actions (SonarQube Cloud y CodeQL), Dependabot, Code scanning y los secretos (`SONAR_TOKEN`). Se trabaja en Ubuntu porque es el mismo sistema que usan los *runners* del pipeline (`ubuntu-latest`) y los servidores donde se despliega: lo que funciona en local funciona igual en la nube, sin problemas de rutas ni de finales de línea de Windows.
2. Una dependencia **directa** es la que el equipo elige y escribe en `requirements.in`; una **transitiva** llega porque la necesita otra dependencia. En `requirements.txt`, `flask==3.1.3` tiene `# via -r requirements.in` (directa) y `werkzeug==3.1.9` tiene `# via flask` (transitiva: nadie la eligió, la trajo Flask). En `sbom.cyclonedx.json` las dos aparecen igual, como `library` con su purl (`pkg:pypi/flask@3.0.0`, `pkg:pypi/werkzeug@3.0.1`): de 2 directas salieron 9 componentes Python, y 12 de las 13 vulnerabilidades estaban en transitivas.
3. El **source** es el punto por donde entra un dato que controla el usuario; el **sink** es la operación peligrosa donde ese dato acaba. Ejemplo: `request.args.get("cliente", "")` en `servicio.py` (línea 41) es el source; el valor pasa a `buscar_reportes_cliente()` y terminaba en `cursor.execute(query)` en `reporte_auditoria.py` (línea 42), el sink. La vulnerabilidad existe porque no había nada entre los dos que separara el dato del código SQL.
4. La consulta se montaba pegando el nombre dentro de comillas: `... WHERE cliente = 'o'brien_ltd'`. El apóstrofo de `o'brien` cerraba la cadena antes de tiempo y `brien_ltd'` quedaba como SQL suelto, por eso SQLite daba `syntax error`. Eso demuestra la inyección: un carácter del dato cambió la estructura de la orden. Si un apóstrofo la rompe, un atacante puede escribir algo como `' OR '1'='1` y la base de datos lo ejecutaría como parte de la consulta.
5. El hook de Semgrep actúa **antes de que el commit exista**, en mi máquina y en segundos: el código inseguro ni siquiera llega a GitHub (*shift-left*). Además fue la única herramienta que detectó el YAML inseguro (H3). Pero solo no basta: se puede saltar con `--no-verify`, un compañero puede no tenerlo instalado y solo mira patrones, sin seguir el recorrido de los datos entre archivos. Por eso hace falta también el pipeline en GitHub, que no se puede saltar porque sus checks son obligatorios para fusionar.
6. No es un error: cada herramienta usa una técnica distinta. CodeQL y SonarQube hacen **análisis de flujo** (*taint*): encontraron H1 y H2 porque siguen el dato desde `request.args` hasta el sink, pero no H3, porque `config.yaml` no viene del usuario. Semgrep busca **patrones** y por eso vio `yaml.load` (H3), pero no las inyecciones. Trivy busca secretos con **formatos de proveedores conocidos**, y las credenciales de ReportAudit no coinciden con ninguno. Según mi matriz, ninguna herramienta encontró los seis hallazgos y la clave de API (H5) solo la vi yo en la auditoría manual: por eso se combinan varias capas.
7. Porque miran cosas distintas. Las alertas de CodeQL (SAST) están en **nuestro código**: se cierran cuando el análisis de `main` deja de encontrar el patrón en `reporte_auditoria.py`, y eso solo lo cambió el PR #22. Las de Dependabot (SCA) están en las **versiones** que declara `requirements.txt`: se cierran cuando el grafo de dependencias ve versiones corregidas, y eso solo lo cambiaron los PRs #19 y #23.
8. Borrar el secreto del código solo lo quita de la versión actual: sigue en el historial de Git, en cada clon, en las *forks* y en cualquier copia que se haya hecho, así que hay que darlo por **comprometido**. Corregirlo de verdad es: rotar la credencial en el proveedor (la antigua deja de valer), sacarla del código leyéndola de variables de entorno o de un gestor de secretos, y poner controles que impidan que vuelva a pasar (push protection, Gitleaks).
9. Ignorar una alerta no deja rastro: nadie sabe si alguien la analizó ni por qué, y la próxima herramienta la vuelve a mostrar. Un **VEX** deja la decisión escrita en un formato estándar y legible por máquinas: qué vulnerabilidad, en qué producto exacto (purl), con qué estado y con qué justificación, firmado por un autor y con fecha, para que otro pueda revisarla. En el mío, CVE-2024-34069 en `pkg:pypi/werkzeug@3.0.1` queda como `not_affected` con `vulnerable_code_not_in_execute_path`, porque la vulnerabilidad está en el depurador interactivo de Werkzeug y ReportAudit arranca con `debug=False` (`servicio.py`, línea 64). Aun así se actualizó a 3.1.9.
10. Antes de ejecutar Syft, Grype y Trivy, el instalador fija una **versión concreta** y compara la **suma SHA-256** del archivo descargado con la lista de sumas publicada por el proyecto (`docs/evidencias/j-instalacion-herramientas.txt`). Eso garantiza que el binario es exactamente el que el proyecto publicó para esa versión (no se corrompió ni lo cambió nadie por el camino). Lo que no garantiza es que el propio proyecto no esté comprometido: en el caso de Trivy de marzo de 2026, los atacantes reescribieron 76 de las 77 etiquetas para que apuntaran a código malicioso; si publican también las sumas del binario malicioso, el checksum coincide igual. Fijar una versión que ya se sabe que es buena reduce el riesgo, pero para demostrar quién construyó el binario y desde qué código hacen falta firmas y procedencia (Parte R).
11. *(Se responde en la Parte O, con Gitleaks.)*
12. *(Se responde en la Parte P, al hacer obligatorio el check de SCA.)*

## Backlog del laboratorio (Issues)

| Issue | Título | PR o evidencia de cierre |
|---|---|---|
| #1 | Adopt an international pull request template | PR #14 (aprobado por @Ireneyss, fusionado) |
| #2 | Run SAST (SonarQube Cloud and CodeQL) on every pull request | PR #15 (aprobado por @AlbertoConesaAyala2003, fusionado) |
| #3 | Block insecure commits with a Semgrep pre-commit hook | PR #16 (aprobado por @AlbertoConesaAyala2003, fusionado); commit bloqueado en docs/evidencias/h3-commit-bloqueado.txt |
| #4 | Enable Dependabot alerts and security updates | PR #17 (aprobado por @Ireneyss, fusionado) + alertas y security updates activados; 13 alertas analizadas en la sección Parte I |
| #5 | Remediate the findings of the security audit | PR #22 (aprobado por @Ireneyss, fusionado; se cerró solo con `Closes #5`). CodeQL: las 4 alertas en *Fixed* |
| #6 | Upgrade the vulnerable dependencies | PR #19 de Dependabot (werkzeug 3.1.9) + PR #23 (flask 3.1.3, jinja2 3.1.6; `Closes #6`). Grype sobre el nuevo `requirements.txt`: *No vulnerabilities found* |
| #7 | Publish the audit log and the before/after evidence | PR de documentación (`docs/evidencias-lab1`, `Closes #7`): bitácora + 9 evidencias |
| #8 | Detect ReportAudit credentials in the whole Git history | Pendiente (Parte O) |
| #9 | Make SCA and secret scanning required checks on main | Pendiente (Parte P) |
| #10 | Publish a security policy and a private vulnerability reporting channel | Pendiente (Parte Q) |
| #11 | Release v1.0.0 with an SBOM and signed provenance | Pendiente (Parte R) |
| #12 | Measure supply-chain maturity with OpenSSF Scorecard | Pendiente (Parte S) |
| #13 | Build the CRA evidence index | Pendiente (Parte T) |
