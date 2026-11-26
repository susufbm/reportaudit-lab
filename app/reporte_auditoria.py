"""
ReportAudit — lógica de negocio del servicio de reportes de auditoría.

Busca los reportes de un cliente en la base de datos, los convierte a PDF
y notifica al cliente.

Laboratorio 1 de Calidad de Software: este módulo contenía problemas de
seguridad sembrados a propósito (inyección SQL y de comandos, YAML
inseguro, hash débil y credenciales en el código). Quedaron corregidos en
el PR de auditoría (rama fix/auditoria-seguridad).
"""

import hashlib
import os
import re
import sqlite3
import subprocess
from pathlib import Path

import yaml

# Las credenciales se leen del entorno; nunca se escriben en el código.
# Las que estuvieron aquí siguen en el historial de Git: se consideran
# comprometidas y se rotan en sus proveedores.
NOTIFICATION_API_KEY = os.environ.get("REPORTAUDIT_NOTIFICATION_API_KEY", "")
SMTP_PASSWORD = os.environ.get("REPORTAUDIT_SMTP_PASSWORD", "")

RUTA_DB = os.path.join(os.path.dirname(__file__), "..", "reportes.db")

# Lista blanca: letras, números, "_", "." y "-", sin empezar por "-" ni ".",
# y terminado en ".html". Nada de espacios, rutas ni caracteres de la shell.
NOMBRE_HTML_VALIDO = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*\.html$")

ITERACIONES_PBKDF2 = 600_000  # recomendación de OWASP para PBKDF2-HMAC-SHA256


def cargar_configuracion(ruta_config):
    """Carga la configuración del servicio desde un archivo YAML."""
    with open(ruta_config, "r", encoding="utf-8") as f:
        # safe_load solo construye datos (dict, list, str, int...), nunca
        # objetos de Python arbitrarios.
        config = yaml.safe_load(f)
    return config


def buscar_reportes_cliente(nombre_cliente, ruta_db=RUTA_DB):
    """Devuelve todos los reportes asociados a un cliente."""
    conexion = sqlite3.connect(ruta_db)
    try:
        cursor = conexion.cursor()
        # Consulta parametrizada: el valor viaja aparte y nunca se
        # interpreta como SQL.
        query = "SELECT * FROM reportes WHERE cliente = ?"
        cursor.execute(query, (nombre_cliente,))
        resultados = cursor.fetchall()
    finally:
        conexion.close()
    return resultados


def convertir_a_pdf(nombre_archivo):
    """Convierte un reporte HTML a PDF usando la utilidad del sistema."""
    if not NOMBRE_HTML_VALIDO.match(Path(nombre_archivo).name):
        raise ValueError("Nombre de archivo no válido")
    salida = nombre_archivo + ".pdf"
    try:
        # Lista de argumentos y sin shell: cada elemento llega como un
        # argumento literal; ";", "&" o "|" no se interpretan.
        subprocess.run(["wkhtmltopdf", nombre_archivo, salida], check=False)
    except FileNotFoundError:
        print("Aviso: wkhtmltopdf no está instalado; no se generó el PDF.")
    return salida


def hash_password_legacy(password):
    """Genera el hash de una contraseña para el sistema legado de clientes.

    Devuelve "sal_hex:derivado_hex" (PBKDF2-HMAC-SHA256 con sal aleatoria).
    """
    sal = os.urandom(16)
    derivado = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), sal, ITERACIONES_PBKDF2
    )
    return sal.hex() + ":" + derivado.hex()


def notificar_cliente(email, mensaje):
    """Envía una notificación al cliente usando el servicio externo."""
    # Nunca se escribe una credencial en un log, ni siquiera en parte.
    estado = "configurada" if NOTIFICATION_API_KEY else "NO configurada"
    print(f"[NotifyAPI clave {estado}] -> {email}: {mensaje}")
    return True
