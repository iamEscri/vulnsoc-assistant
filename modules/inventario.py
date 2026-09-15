"""
Gestion del inventario de activos organizado por equipos.

Modelo de datos (en st.session_state.inventario):

    {
        "equipos": [
            {
                "nombre": "Servidor Web",
                "ip": "192.168.1.10",
                "criticidad": "alta",          # alta | media | baja
                "tecnologias": ["apache", "python", "openssl"],
            },
            ...
        ]
    }

Cada equipo agrupa su stack tecnologico. Asi, ante un CVE, no solo sabemos
SI nos afecta sino EN QUE equipos concretos. La criticidad y exposición contextualizan candidatos con versión compatible;
no se declara afectación confirmada por coincidencias de texto.
"""

import json
import re
from modules.evidencia import normalizar_nombre, partes_cpe, version_en_rango, version_cpe

CRITICIDADES = ["alta", "media", "baja"]


def exportar_inventario(inventario: dict) -> str:
    """Serializa el inventario (por equipos) a JSON indentado para descargar."""
    inventario = normalizar_inventario(inventario)
    return json.dumps(inventario, ensure_ascii=False, indent=2)


def importar_inventario(contenido) -> dict:
    """
    Parsea y valida un inventario desde el contenido de un archivo JSON.

    Acepta tanto bytes (de un file_uploader) como str. Lanza ValueError con
    un mensaje claro si el JSON no es valido o no tiene la estructura esperada.
    Devuelve el inventario normalizado (admite tambien el formato plano antiguo).
    """
    if isinstance(contenido, bytes):
        contenido = contenido.decode("utf-8")

    try:
        datos = json.loads(contenido)
    except json.JSONDecodeError as e:
        raise ValueError(f"El archivo no es un JSON válido: {e}")

    if not isinstance(datos, dict):
        raise ValueError("El JSON debe ser un objeto con la clave 'equipos'.")

    inventario = normalizar_inventario(datos)
    equipos = inventario.get("equipos", [])
    if not isinstance(equipos, list):
        raise ValueError("'equipos' debe ser una lista.")

    # Validar y sanear cada equipo
    equipos_validos = []
    for i, equipo in enumerate(equipos):
        if not isinstance(equipo, dict):
            raise ValueError(f"El equipo nº{i + 1} no tiene el formato correcto.")
        nombre = str(equipo.get("nombre", "")).strip()
        tecnologias = equipo.get("tecnologias", [])
        if not nombre:
            raise ValueError(f"El equipo nº{i + 1} no tiene nombre.")
        if not isinstance(tecnologias, list):
            raise ValueError(f"El equipo «{nombre}» tiene 'tecnologias' inválidas.")
        crit = equipo.get("criticidad", "media")
        equipos_validos.append({
            "nombre": nombre,
            "ip": str(equipo.get("ip", "")).strip(),
            "criticidad": crit if crit in CRITICIDADES else "media",
            "exposicion": equipo.get("exposicion") if equipo.get("exposicion") in ("internet", "interna") else "desconocida",
            "tecnologias": [str(t).strip() for t in tecnologias if str(t).strip()],
        })

    return {"equipos": equipos_validos}


def normalizar_inventario(inventario: dict) -> dict:
    """
    Devuelve el inventario en el formato por equipos.

    Migra automaticamente el formato plano antiguo
    (sistemas_operativos / software / personalizado) a un unico equipo
    "General", de modo que no se pierde el inventario ya guardado.
    """
    inventario = inventario or {}

    if "equipos" in inventario:
        return inventario

    # Migracion desde el formato plano antiguo
    tecnologias = []
    for item in inventario.get("sistemas_operativos", []):
        if item and item not in tecnologias:
            tecnologias.append(item)
    for item in inventario.get("software", []):
        if item and item not in tecnologias:
            tecnologias.append(item)
    for linea in inventario.get("personalizado", "").splitlines():
        linea = linea.strip()
        if linea and linea not in tecnologias:
            tecnologias.append(linea)

    equipos = []
    if tecnologias:
        equipos.append({
            "nombre": "General",
            "ip": "",
            "criticidad": "media",
            "tecnologias": tecnologias,
        })

    return {"equipos": equipos}


def _palabras(textos) -> set:
    """Convierte una lista de tecnologias en un set de palabras en minusculas."""
    palabras = set()
    for t in textos:
        palabras.update(t.lower().split())
    return palabras


def tecnologias_inventario(inventario: dict) -> set:
    """
    Conjunto plano de palabras de todas las tecnologias de todos los equipos.
    Lo usa el scoring para el ajuste +10 / -25 (igual que antes, pero leyendo
    del nuevo modelo por equipos).
    """
    inventario = normalizar_inventario(inventario)
    palabras = set()
    for equipo in inventario.get("equipos", []):
        palabras.update(_palabras(equipo.get("tecnologias", [])))
    return palabras


def _identidad_tecnologia(text):
    parts = partes_cpe(text)
    if parts:
        return normalizar_nombre(f'{parts[3]} {parts[4]}'), version_cpe(parts)
    match = re.fullmatch(r'(.*?)\s+([0-9][0-9a-zA-Z.+_-]*)', text.strip())
    return (normalizar_nombre(match[1]), match[2]) if match else (normalizar_nombre(text), None)


def equipos_afectados(inventario: dict, productos_afectados: list,
                      plataformas_afectadas: list = None, cpe_afectados: list = None) -> list:
    """Candidates, never confirmed affected hosts. Exact product identity first.

    Version compatibility is limited to numeric CPE ranges and recognized release suffixes. Negation,
    environmental AND requirements and special CPE attributes remain unverified.
    """
    catalog = []
    for match in cpe_afectados or []:
        parts = partes_cpe(match.get('criteria', ''))
        if parts:
            catalog.append(({normalizar_nombre(f'{parts[3]} {parts[4]}'), normalizar_nombre(parts[4])}, match))
    if not catalog:
        # Legacy product labels do not carry enough evidence to verify versions.
        catalog = [({normalizar_nombre(p)}, None) for p in productos_afectados]
    platforms = {normalizar_nombre(p) for p in plataformas_afectadas or []}
    result = []
    for asset in normalizar_inventario(inventario).get('equipos', []):
        coincidencias, ecosystem, evidence = [], [], []
        for tech in asset.get('tecnologias', []):
            identity, version = _identidad_tecnologia(tech)
            candidates = [m for names, m in catalog if identity and identity in names]
            if candidates:
                statuses = [version_en_rango(version, m) if m else None for m in candidates]
                state = 'version_compatible' if True in statuses else 'posible' if None in statuses else 'fuera_de_rango'
                coincidencias.append(tech)
                evidence.append({'tecnologia': tech, 'estado': state, 'version': version, 'criterios': [m['criteria'] for m in candidates if m]})
            elif identity in platforms:
                ecosystem.append(tech)
        if coincidencias or ecosystem:
            state = 'version_compatible' if any(e['estado'] == 'version_compatible' for e in evidence) else 'posible' if any(e['estado'] == 'posible' for e in evidence) or ecosystem else 'fuera_de_rango'
            result.append({'nombre': asset.get('nombre', 'Sin nombre'), 'ip': asset.get('ip', ''), 'criticidad': asset.get('criticidad', 'media'), 'exposicion': asset.get('exposicion', 'desconocida'), 'coincidencias': coincidencias, 'coincidencias_plataforma': ecosystem, 'estado': state, 'evidencias': evidence, 'limitacion': 'Compatibilidad de producto/versión; verificar configuración y aplicabilidad. No confirma explotación ni compromiso.'})
    return result
