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
SI nos afecta sino EN QUE equipos concretos. La criticidad es informativa
(se muestra en la notificacion); no altera el score.
"""

import json

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


def equipos_afectados(inventario: dict, productos_afectados: list,
                      plataformas_afectadas: list = None) -> list:
    """
    Cruza el CVE con cada equipo del inventario.

    Devuelve una lista de equipos con coincidencias, cada uno como:
        {
            "nombre": str,
            "ip": str,
            "criticidad": str,
            "coincidencias": [tecnologias del equipo que coinciden con productos],
            "coincidencias_plataforma": [coincidencias a nivel de plataforma],
        }

    Solo se incluyen equipos que tienen alguna coincidencia (directa o de
    plataforma). Un equipo con coincidencia directa de producto es una
    afectacion confirmada; uno con solo coincidencia de plataforma es un
    "componente del ecosistema" (revisar manualmente).
    """
    inventario = normalizar_inventario(inventario)
    plataformas_afectadas = plataformas_afectadas or []

    palabras_productos = _palabras(productos_afectados)
    palabras_plataformas = _palabras(plataformas_afectadas)

    resultado = []
    for equipo in inventario.get("equipos", []):
        tecnologias = equipo.get("tecnologias", [])

        coincidencias = [
            t for t in tecnologias
            if set(t.lower().split()).intersection(palabras_productos)
        ]
        coincidencias_plataforma = [
            t for t in tecnologias
            if set(t.lower().split()).intersection(palabras_plataformas)
            and t not in coincidencias
        ]

        if coincidencias or coincidencias_plataforma:
            resultado.append({
                "nombre": equipo.get("nombre", "Sin nombre"),
                "ip": equipo.get("ip", ""),
                "criticidad": equipo.get("criticidad", "media"),
                "coincidencias": coincidencias,
                "coincidencias_plataforma": coincidencias_plataforma,
            })

    return resultado
