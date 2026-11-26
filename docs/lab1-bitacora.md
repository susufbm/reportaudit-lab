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
| Alertas abiertas de Dependabot | 13 (werkzeug 7, jinja2 5, flask 1) | 0 (las 13 en *Fixed*; al medir en la Parte N aún se veían 6 de jinja2 y flask, que se cerraron al recalcular GitHub) |

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
11. Porque Gitleaks sobre el código mira solo la versión actual, donde las credenciales ya se leen del entorno; sobre el historial recorre todos los commits, y el de importación (`b1e77dd`) aún las contiene. Git no olvida: el commit que las borró es uno más, no reescribe los anteriores. Lo que cierra realmente el riesgo es **rotarlas**, para que las copias que ya circulan no sirvan; la regla propia y la *baseline* evitan que vuelva a pasar sin ocultar secretos nuevos.
12. Porque una puerta obligatoria solo se puede cerrar cuando la casa está limpia. Con las 13 vulnerabilidades de la Parte I, `pip-audit` habría fallado en todos los PRs (también en los que no tocaban dependencias) y nada habría podido entrar en `main` hasta la Parte M. Es el *ratchet* (trinquete): en mi repositorio primero llevé las dependencias a 0 vulnerabilidades con los PRs #19 y #23, y después, en la Parte P, hice obligatorio `SCA - pip-audit` para que no se pueda volver atrás; el PR trampa #29 lo demuestra.
13. Una alerta de Dependabot es un **aviso** sobre lo que ya está en `main`: informa y propone un PR, pero no impide fusionar nada. El check obligatorio `SCA - pip-audit` es una **puerta** en cada PR: si el `requirements.txt` del PR contiene una versión con una vulnerabilidad conocida, el PR queda bloqueado. Dependabot detecta después; pip-audit impide antes.
14. Demuestra que `reportaudit-1.0.0.tar.gz` lo construyó el workflow `publicar-version.yml` de `susufbm/reportaudit-lab` a partir de la etiqueta `v1.0.0`, y que nadie lo ha modificado después: la firma Sigstore está ligada a su huella SHA-256 (el archivo alterado falla con 404). **No** demuestra que el código sea seguro ni que no tenga fallos; eso lo dicen los checks de cada PR y el SBOM. `SHA256SUMS` no basta porque viaja junto al archivo: quien sustituya el `.tar.gz` en la Release o en un espejo puede sustituir también `SHA256SUMS` y `sha256sum -c` seguirá diciendo `OK`. La atestación no se puede falsificar así, porque la firma la emite la identidad OIDC de mi workflow y queda en el registro público de Sigstore.
15. Un Issue es público: publicar el fallo antes de que exista el arreglo es dar las instrucciones del ataque a todo el mundo y dejar expuestos a los clientes. El canal privado (*private vulnerability reporting*) deja que el mantenedor y el investigador trabajen el aviso en un borrador (GHSA-qr5f-pmmw-w92g en el simulacro), preparen la versión corregida y lo publiquen a la vez, con crédito para quien lo encontró. `SECURITY.md` es el cartel que lo explica: dónde se informa, qué versiones tienen soporte (1.x hasta 2031-11-30) y en qué plazos se responde (3/10/90 días); el CRA (art. 13.8 y anexo I) pide justamente ese punto de contacto y ese periodo de soporte.
16. No. Maintained mide la **antigüedad y la actividad** del repositorio: da 0 porque ReportAudit tiene menos de 90 días, aunque hemos hecho commits y PRs todos los días. No mide ningún fallo del código. Enseña que una métrica hay que leerla con su **razón** (Scorecard la escribe al lado de cada nota) y con el contexto: el mismo número puede ser una alerta en una dependencia antigua y nada en un proyecto recién creado. Branch-Protection "sin dato" con `main` protegida es el mismo caso: la nota sirve para priorizar mejoras, no como certificado.
17. En la B5 de la Práctica 2 imaginé seis evidencias. **Ahora existen de verdad:** (1) el «informe de SCA sin hallazgos archivado por versión» son `grype-despues.txt`, `trivy-despues.txt` y el check `SCA - pip-audit` en verde en el commit de `v1.0.0`, más el VEX, que no se me había ocurrido; (2) la «SBOM CycloneDX generada en cada versión» es `reportaudit-sbom.cdx.json` en la Release, y además **atestada** con Sigstore, más de lo que imaginé; (3) el «historial del pipeline que demuestra distribuir un parche rápido» son los PRs #19 y #23 de dependencias y la puerta SCA probada con el PR #29; (4) el «`SECURITY.md` publicado» está en Security → Policy, con canal privado y un simulacro real (GHSA-qr5f-pmmw-w92g). **Siguen sin existir:** la configuración segura por defecto «con Terraform/Ansible» (ReportAudit no tiene despliegue: lo que hay es configuración segura en el código, fila 2) y la «superficie de ataque mínima» con imagen distroless y un informe DAST de OWASP ZAP (no hay contenedor ni análisis dinámico). Tampoco la «quality gate de SonarQube en verde»: los checks obligatorios están verdes, pero la Quality Gate de `main` sigue en rojo por cobertura 0 % porque no hay tests. Y lo que ya sabía que faltaba en ambos casos: evaluación de riesgos, Anexo VII, declaración UE de conformidad y marcado CE. La gran diferencia con la B5 es la columna «Cómo lo verifica un tercero»: en la Práctica 2 una evidencia era un documento que yo decía tener; aquí es un comando que otra persona ejecuta y le da el mismo resultado.

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
| #8 | Detect ReportAudit credentials in the whole Git history | PR #25 (`.gitleaks.toml` + `.gitleaksignore` + `gitleaks-historial.json`) |
| #9 | Make SCA and secret scanning required checks on main | PR #26 (jobs) + PR #28 (pip-audit con `--disable-pip`) + protección de `main` con 4 checks; puerta comprobada en el draft PR #29 (`docs/evidencias/p3-puerta-sca.txt`). Cerrado a mano con comentario |
| #10 | Publish a security policy and a private vulnerability reporting channel | PR #30 (`SECURITY.md`) + *private vulnerability reporting* activado + simulacro: borrador GHSA-qr5f-pmmw-w92g (`docs/evidencias/q3-aviso-borrador.txt`) |
| #11 | Release v1.0.0 with an SBOM and signed provenance | PR #31 (`publicar-version.yml`) + Release v1.0.0 con SBOM, `SHA256SUMS` y 2 atestaciones; verificación en `docs/evidencias/r3-verificacion.txt` |
| #12 | Measure supply-chain maturity with OpenSSF Scorecard | PR #32 (`scorecard.yml`, `Closes #12`): 7.1/10 + reto S.3 en PR #33 (acciones por SHA): 7.6/10, Pinned-Dependencies 0 → 8; evidencias `s2-scorecard-antes.txt` y `s3-scorecard-despues.txt` |
| #13 | Build the CRA evidence index | PR final (`docs/expediente-evidencias`, `Closes #13`): `docs/cra/expediente-evidencias.md` con 12 filas verificables + bitácora O–T + evidencias p3, q3, r3, s2 y s3 |

---

## Bloque final — Publicar y demostrar (Partes O–T)

### O. Secretos en el historial (Gitleaks)

| Escaneo | Comando | N.º de hallazgos | Commit(s) donde aparecen |
|---|---|---|---|
| Código actual, reglas por defecto | `gitleaks dir app` | 0 | — |
| Historial, reglas por defecto | `gitleaks git .` | 1 (`generic-api-key`: solo `NOTIFICATION_API_KEY`, línea 21; la contraseña SMTP no la detectó) | `b1e77dd` (chore: importar repositorio base de ReportAudit) |
| Historial, con regla propia | `gitleaks git . -c .gitleaks.toml` | 2 (`reportaudit-hardcoded-credential`, líneas 21 y 22) | `b1e77dd` (chore: importar repositorio base de ReportAudit) |
| Historial, tras .gitleaksignore | `gitleaks git . -c .gitleaks.toml` | 0 (*no leaks found*) | — |

¿Por qué el código actual está limpio y el historial no? ¿Qué medida de la Parte M cierra el riesgo
y cuál no lo cierra?

Gitleaks 8.30.1 se instaló a mano comprobando la huella SHA-256 con la lista oficial (`gitleaks_8.30.1_linux_x64.tar.gz: OK`). `gitleaks dir app` analiza los archivos tal como están hoy, y en la Parte M las credenciales se sustituyeron por `os.environ.get(...)`, así que no queda nada. `gitleaks git .` recorre los 13 commits uno a uno, y el commit de importación `b1e77dd` sigue teniendo las dos credenciales escritas: borrar la línea creó un commit nuevo, pero no cambió los anteriores, que siguen en GitHub, en cada clon y en cada *fork* (`git log -p` los muestra). Por eso **la medida que cierra el riesgo es la rotación**: las credenciales antiguas ya no sirven. Sacarlas del código y leerlas del entorno evita que se vuelvan a escribir, pero por sí sola no protege lo que ya se publicó.

Las reglas por defecto solo encontraron la clave de API (por su forma de clave larga y aleatoria); la contraseña SMTP no la vio ninguna. La regla propia `reportaudit-hardcoded-credential` (`.gitleaks.toml`, con `useDefault = true`) detecta las dos. Registrar sus dos *fingerprints* en `.gitleaksignore` **no es desactivar la regla**: cada línea apunta a un hallazgo concreto (commit, archivo, regla y línea) de una credencial ya rotada, con el motivo escrito. Lo comprobé con un archivo temporal que contenía una `SMTP_PASSWORD` nueva: Gitleaks dio `leaks found: 1`. Lo ya rotado no hace fallar el análisis, pero cualquier secreto nuevo sí. Evidencia: `docs/evidencias/gitleaks-historial.json` (valores como `REDACTED`). PR #25 (`Closes #8`).

### P. Puertas obligatorias en main

| Check | ¿Exigido en main? | Resultado en el PR de prueba (test/puerta-sca) |
|---|---|---|
| SAST - SonarQube Cloud | Sí (desde la Parte F) | ✓ pass |
| SAST - CodeQL | Sí (desde la Parte F) | ✓ pass |
| SCA - pip-audit | Sí (desde la Parte P) | ✗ **fail**: `Found 13 known vulnerabilities in 1 package` (werkzeug 3.0.1, de PYSEC-2026-2043 → 3.0.3 a PYSEC-2026-4312 → 3.1.9). Draft PR #29, cerrado sin fusionar |
| Secretos - Gitleaks | Sí (desde la Parte P) | ✓ pass |

`main` exige ahora cuatro checks y una aprobación (PR #26 para los jobs, protección actualizada con la API). Secret scanning y push protection ya estaban activados. Evidencia de la puerta: `docs/evidencias/p3-puerta-sca.txt`.

**Lo que salió mal la primera vez:** en el primer PR trampa (#27), `SCA - pip-audit` salió en rojo, pero el registro mostraba `Unexpected input(s) 'disable-pip'` y `ResolutionImpossible`: la acción `pypa/gh-action-pip-audit@v1.1.0` no admite `disable-pip`, la ignoraba e intentaba resolver el lockfile, y como Flask 3.1.3 exige Werkzeug ≥ 3.1 fallaba **sin llegar a auditar**. Un rojo así no demuestra nada. En el PR #28 cambié el job para instalar `pip-audit==2.10.1` (solo *wheels*, `--only-binary=:all:`, por la regla `githubactions:S8541` de SonarQube) y ejecutar `pip-audit -r requirements.txt --no-deps --disable-pip`. Lo probé antes en local: limpio con el lockfile actual y 13 vulnerabilidades con werkzeug 3.0.1. Al repetir el PR trampa (#29) el fallo ya fue por el motivo correcto. Reabrí el issue #9, que había cerrado antes de tiempo, y lo cerré con la evidencia buena.

**Alerta de Dependabot vs. check SCA - pip-audit:** la alerta **avisa** (y propone un PR) cuando aparece una vulnerabilidad en lo que ya está en `main`, pero no impide fusionar nada. El check obligatorio actúa **en cada PR, antes de entrar**: si el lockfile del PR tiene una versión vulnerable, el PR no se puede fusionar.

**¿Por qué no se exigió pip-audit desde la Parte G? (*ratchet*):** porque entonces `main` tenía 13 vulnerabilidades y el check habría salido en rojo en **todos** los PRs, incluidos los de la plantilla, Semgrep o Dependabot, aunque no tocaran las dependencias: nada habría podido fusionarse hasta la Parte M. Primero se limpió (PRs #19 y #23, Grype y pip-audit en 0) y después se cerró la puerta para no retroceder.

### Q. Divulgación coordinada (simulacro)

- Informe recibido de (usuario de GitHub): @JesusFB4, por el canal privado (*Report a vulnerability*); figura en *Credits* como *reporter*
- Identificador del borrador de aviso (GHSA-…): GHSA-qr5f-pmmw-w92g (de *Triage* a *Draft* con *Accept and open as draft*; sin CVE y sin publicar)
- Severidad y vector CVSS: High, 8.2 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` (por red, sin autenticación ni interacción; lectura de los reportes de todos los clientes = C:H; `cursor.execute` no admite varias sentencias, así que la modificación es limitada = I:L)
- CWE: CWE-89 (SQL Injection)
- Versiones afectadas / versión corregida: `< 1.0.0` / `1.0.0` (paquete `pip/reportaudit`, función `buscar_reportes_cliente`). Evidencia: `docs/evidencias/q3-aviso-borrador.txt`

`SECURITY.md` (PR #30) declara soporte de seguridad para la 1.x hasta el **2031-11-30**: al menos 5 años desde la 1.0.0 (26-nov-2026), el mínimo del art. 13.8 de la CRA. La fecha de la plantilla (2031-10-31) se quedaba un mes corta. *Private vulnerability reporting* activado.

**¿Por qué el investigador no debe abrir un Issue?** Porque un Issue es público: cualquiera, también un atacante, conocería la vulnerabilidad antes de que exista el parche y los usuarios quedarían expuestos sin poder hacer nada. **¿Qué gana el responsable con un borrador privado?** Tiempo y control: puede confirmar el fallo, hablar con el investigador, preparar la corrección en una *fork* privada temporal, calcular la severidad y decidir la fecha de publicación, y solo entonces pedir el CVE y publicar el aviso con los créditos. **¿Cuándo se activaría la obligación de notificación de la P2?** Cuando hubiera una vulnerabilidad **explotada activamente** (o un incidente grave) en un producto con elementos digitales comercializado en la UE: el fabricante debe avisar al CSIRT y a ENISA en los plazos de la CRA. Este simulacro no la activa porque la vulnerabilidad ya estaba corregida, nadie la ha explotado y es un aviso responsable de un investigador sobre un producto que no se distribuye fuera de la asignatura.

### R. Versión 1.0.0 verificable

| Comprobación | Comando | Resultado |
|---|---|---|
| Huellas SHA-256 | `sha256sum -c SHA256SUMS` | `reportaudit-1.0.0.tar.gz: OK` y `reportaudit-sbom.cdx.json: OK` |
| Procedencia (SLSA) | `gh attestation verify reportaudit-1.0.0.tar.gz --repo …` | ✓ *Verification succeeded!* — predicado `https://slsa.dev/provenance/v1`, build repo `susufbm/reportaudit-lab`, workflow `.github/workflows/publicar-version.yml@refs/tags/v1.0.0` |
| SBOM atestado | `gh attestation verify … --predicate-type https://cyclonedx.org/bom` | ✓ *Verification succeeded!* — mismo repositorio, workflow y etiqueta |
| Archivo alterado | `gh attestation verify alterado.tar.gz --repo …` | ✗ falla: huella `4390a1e5…` frente a `643dfc4c…` del original; `HTTP 404`, no existe ninguna atestación para ese archivo (exit code 1) |

Workflow `publicar-version.yml` (PR #31). Etiqueta anotada `v1.0.0` sobre `db182cb`; la ejecución terminó en verde y la Release [v1.0.0](https://github.com/susufbm/reportaudit-lab/releases/tag/v1.0.0) tiene los cinco archivos (`reportaudit-1.0.0.tar.gz`, `reportaudit-sbom.cdx.json`, `SHA256SUMS`, `reportaudit-provenance.sigstore.json`, `reportaudit-sbom.sigstore.json`) y dos atestaciones. Evidencia completa: `docs/evidencias/r3-verificacion.txt`.

**Incidencia:** el `gh` de Ubuntu (2.45.0) no tiene el comando `attestation` (llegó en la 2.49). Instalé gh 2.106.0 en `tools/` como en la Parte O: versión fijada, descarga del paquete y de la lista oficial de huellas, `sha256sum -c` → `OK`, y solo entonces extraer el binario.

**Qué demuestra y qué no:** demuestra que `reportaudit-1.0.0.tar.gz` lo construyó el workflow `publicar-version.yml` de mi repositorio a partir de la etiqueta `v1.0.0`, y que nadie lo ha cambiado después (la firma Sigstore va ligada a su huella). No demuestra que el código sea seguro: eso lo cubren los checks obligatorios de cada PR y el SBOM. `SHA256SUMS` solo no basta porque un atacante que sustituya el archivo en la Release o en un espejo puede sustituir también `SHA256SUMS`, y `sha256sum -c` seguiría diciendo `OK`; la atestación no la puede falsificar, porque la firma la emite la identidad OIDC de mi workflow y queda en el registro público de Sigstore.

### S. Madurez (OpenSSF Scorecard)

Workflow `scorecard.yml` (PR #32, copiado tal cual de la guía para que `publish_results` se acepte). Resultados leídos de la API pública (`api.securityscorecards.dev`); evidencias completas en `docs/evidencias/s2-scorecard-antes.txt` y `docs/evidencias/s3-scorecard-despues.txt`.

| Check | Puntuación (0–10) | Qué la explica |
|---|---|---|
| Puntuación global | 7.1 → **7.6** tras el reto S.3 | 7.1 sobre `7986c7f` (fusión del PR #32); 7.6 sobre `8bd3a16` (fusión del PR #33) |
| Branch-Protection | sin dato (−1) | Con reglas clásicas de protección, el `GITHUB_TOKEN` no puede leerlas; haría falta un token de administrador que no creo a propósito. La protección existe (4 checks + 1 aprobación, Parte P), Scorecard simplemente no la ve |
| Maintained | 0 | El repositorio se creó hace menos de 90 días. Mide antigüedad y actividad, no seguridad |
| License | 0 | No hay archivo `LICENSE`. Es un repositorio de laboratorio; para un proyecto real sería obligatorio (sin licencia, nadie puede reutilizarlo legalmente) |
| Fuzzing | 0 | No hay pruebas de *fuzzing* (OSS-Fuzz, Atheris…). Para una app pequeña sin parsers propios no es la prioridad |
| Pinned-Dependencies | 0 → **8** | Antes, todas las acciones se usaban por etiqueta (`@v6`), que el dueño del repositorio de la acción puede mover. Tras el PR #33: 12/12 acciones de GitHub y 4/4 de terceros fijadas por SHA. El 8 (no 10) es por `pip install pip-audit==2.10.1` en `cadena-suministro.yml:71`, que fija versión pero no hash |

Otros ceros que no entran en la tabla: CII-Best-Practices (no hemos pedido la insignia OpenSSF), Contributors (no hay empresas detrás de los colaboradores) y Packaging −1 (no publicamos en PyPI). Las notas altas reflejan el trabajo del laboratorio: Code-Review 10, Token-Permissions 10, Security-Policy 10, Dependency-Update-Tool 10, Vulnerabilities 10, SAST 10 y CI-Tests 10 (el commit de importación de la Parte A les restaba un punto en la primera ejecución), Signed-Releases 8.

**Reto S.3 (PR #33):** las 15 líneas `uses:` de los tres workflows (no solo `publicar-version.yml`) pasan de `@vX` a `@<SHA de 40 caracteres> # vX.Y.Z`. Hashes obtenidos con `git ls-remote --tags` (la línea `^{}` en etiquetas anotadas) y comprobados como commits reales con la API de GitHub. De paso desapareció el aviso S7637 de SonarCloud y su Quality Gate pasó a verde. Dependabot (`github-actions`) entiende este formato y seguirá proponiendo actualizaciones.

**Riesgo aceptado:** SonarCloud marca S8234 en `scorecard.yml` (`permissions: read-all`). Se mantiene porque es la plantilla oficial de Scorecard y `publish_results: true` exige el workflow sin modificar; el job solo añade `security-events: write` e `id-token: write`, y Token-Permissions saca un 10.

**Punto de control:** el check más útil para elegir una dependencia es **Code-Review** (junto a Vulnerabilities): dice si cada cambio lo mira una segunda persona antes de entrar, que es justo lo que habría frenado una puerta trasera; en ReportAudit pasó de 9 a 10 en cuanto todos los cambios entraron por PR aprobado. El más engañoso sin contexto es **Maintained**: nuestro 0 haría pensar en un proyecto abandonado cuando tiene commits todos los días; solo es nuevo. Muy cerca está **Branch-Protection**, que sale "sin dato" aunque `main` está protegida: una ausencia de dato no es un suspenso.


### T. Expediente de evidencias

Ver `docs/cra/expediente-evidencias.md`: 12 filas, cada una con el requisito (Anexo I / art. 13.8), la evidencia real, su enlace y el comando o los clics con los que un tercero la comprueba sin fiarse de mí. Fechado el 2026-11-26 sobre `v1.0.0`. Las evidencias privadas (borrador GHSA, pestañas de Security) se marcan como «visible solo para colaboradores» y llevan una alternativa pública.

Compara el expediente con tu respuesta B5 de la Práctica 2: ver la respuesta 17.
