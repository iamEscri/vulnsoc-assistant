import requests
import os
from datetime import datetime, timezone
from modules.http_client import get_json
from modules.evidencia import seleccionar_cvss, extraer_cpes, partes_cpe, numero
from bs4 import BeautifulSoup

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

# --- CAMBIO 1: Headers globales con User-Agent ---
# Cloudflare (que protege NVD) puede bloquear peticiones de Python/requests
# si no incluyen un User-Agent reconocible. Con esto lo evitamos.
HEADERS = {
    "User-Agent": "VulnSOC-Assistant/1.0",
    "Accept": "application/json"
}


def _limpiar_html(texto: str) -> str:
    """Elimina etiquetas HTML de la descripcion del NVD."""
    return BeautifulSoup(texto, "html.parser").get_text(separator=" ").strip()


def obtener_datos_nvd(cve_id: str) -> dict:
    """Consulta la API del NVD y devuelve los datos del CVE."""
    params = {"cveId": cve_id}

    try:
        # --- CAMBIO 2: timeout 10 → 30 segundos ---
        # NVD puede tardar más de 10s en responder bajo carga.
        # Con 30s damos margen suficiente sin colgar la app indefinidamente.
        headers = {**HEADERS, **({"apiKey": os.environ["NVD_API_KEY"]} if os.getenv("NVD_API_KEY") else {})}
        data = get_json(NVD_BASE_URL, params=params, headers=headers, timeout=30)

        if data["totalResults"] == 0:
            return {"error": f"CVE {cve_id} no encontrado en NVD"}

        cve = data["vulnerabilities"][0]["cve"]

        cvss = seleccionar_cvss(cve.get('metrics', {}))
        # Extraer CWE (tipo de vulnerabilidad)
        cwes = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                    cwes.append(desc["value"])

        # Descripcion limpia
        descripcion = ""
        for desc in cve.get("descriptions", []):
            if desc["lang"] == "en":
                descripcion = _limpiar_html(desc["value"])
                break

        # Productos afectados — extraemos vendor y producto de los CPEs vulnerables.
        # Tambien capturamos target_sw (campo 10 del CPE 2.3): la plataforma sobre
        # la que corre el componente, p.ej. "wordpress" para un plugin. Sirve para
        # no descartar plugins/themes cuando el inventario tiene la plataforma base.
        productos_afectados = []
        plataformas_afectadas = []
        cpes = extraer_cpes(cve.get("configurations", []))
        for match in cpes:
            partes = partes_cpe(match['criteria'])
            entrada = f"{partes[3]} {partes[4]}".replace('_', ' ')
            if entrada not in productos_afectados:
                productos_afectados.append(entrada)
            target = partes[10].replace('_', ' ')
            if target not in ('*', '-') and target not in plataformas_afectadas:
                plataformas_afectadas.append(target)

        # Referencias completas con sus etiquetas (patch, vendor advisory, etc.)
        referencias_completas = []
        for r in cve.get("references", []):
            referencias_completas.append({
                "url":  r.get("url", ""),
                "tags": r.get("tags", [])
            })

        # Estado de parche — buscamos referencias con tag Patch, Vendor Advisory o Mitigation
        tags_parche = {"Patch", "Vendor Advisory", "Mitigation"}
        refs_parche = [
            r["url"] for r in referencias_completas
            if tags_parche.intersection(set(r["tags"]))
        ]
        parche_disponible = any("Patch" in r["tags"] for r in referencias_completas)

        return {
            "cve_id": cve_id,
            "descripcion": descripcion,
            **cvss,
            "cpe_afectados": cpes,
            "estado_nvd": cve.get("vulnStatus", ""),
            "consultado_en": datetime.now(timezone.utc).isoformat(),
            "cwes": cwes,
            "fecha_publicacion": cve.get("published", ""),
            "fecha_modificacion": cve.get("lastModified", ""),
            "referencias": [r["url"] for r in referencias_completas[:5]],
            "parche_disponible": parche_disponible,
            "refs_parche": refs_parche[:3],
            "productos_afectados": productos_afectados[:20],
            "plataformas_afectadas": plataformas_afectadas[:10],
        }

    except requests.exceptions.Timeout:
        # --- CAMBIO 3: excepción Timeout separada ---
        # Antes el timeout caía en el RequestException genérico y el mensaje
        # era confuso. Ahora muestra un mensaje claro y accionable.
        return {"error": "NVD tardó demasiado en responder. Inténtalo de nuevo en unos segundos."}

    except (requests.exceptions.RequestException, ValueError, KeyError, TypeError) as e:
        return {"error": f"Error al conectar con NVD: {str(e)}"}


def comprobar_cisa_kev(cve_id: str) -> dict:
    """Comprueba si el CVE esta en el catalogo CISA KEV."""
    try:
        # --- CAMBIO 4: headers añadidos a CISA KEV ---
        data = get_json(CISA_KEV_URL, headers=HEADERS, timeout=15)
        if not isinstance(data.get("vulnerabilities"), list):
            raise ValueError("Formato KEV inválido")

        for vuln in data.get("vulnerabilities", []):
            if vuln.get("cveID") == cve_id:
                return {
                    "en_kev": True,
                    "consultado_en": datetime.now(timezone.utc).isoformat(),
                    "nombre": vuln.get("vulnerabilityName", ""),
                    "fecha_añadido": vuln.get("dateAdded", ""),
                    "accion_requerida": vuln.get("requiredAction", ""),
                    "fecha_limite": vuln.get("dueDate", "")
                }

        return {"en_kev": False, "consultado_en": datetime.now(timezone.utc).isoformat()}

    except (requests.exceptions.RequestException, ValueError, KeyError, TypeError) as e:
        return {"error": f"Error al conectar con CISA KEV: {str(e)}"}


def obtener_epss(cve_id: str) -> dict:
    """Consulta la API de EPSS para obtener la probabilidad de explotacion."""
    try:
        # --- CAMBIO 5: timeout 10 → 20 segundos + headers ---
        data = get_json(EPSS_URL, params={"cve": cve_id}, headers=HEADERS, timeout=20)

        if data.get("data"):
            epss = data["data"][0]
            probability = float(epss['epss'])
            percentile = float(epss['percentile'])
            if not numero(probability, 0, 1) or not numero(percentile, 0, 1):
                raise ValueError('EPSS fuera de rango')
            return {"epss_score": probability, "percentil": percentile, "fecha": epss.get('date'), "estado": "disponible", "consultado_en": datetime.now(timezone.utc).isoformat()}

        return {"epss_score": None, "percentil": None, "estado": "sin_datos"}

    except (requests.exceptions.RequestException, ValueError, KeyError, TypeError) as e:
        return {"epss_score": None, "percentil": None, "estado": "no_disponible", "error": "EPSS no está disponible o ha devuelto datos inválidos."}


def analizar_cve(cve_id: str) -> dict:
    """Funcion principal: obtiene todos los datos de un CVE."""
    print(f"Consultando NVD para {cve_id}...")
    datos_nvd = obtener_datos_nvd(cve_id)

    print(f"Comprobando CISA KEV para {cve_id}...")
    datos_kev = comprobar_cisa_kev(cve_id)

    print(f"Consultando EPSS para {cve_id}...")
    datos_epss = obtener_epss(cve_id)

    return {
        "nvd": datos_nvd,
        "kev": datos_kev,
        "epss": datos_epss
    }


def buscar_cves_por_descripcion(termino: str, max_resultados: int = 20) -> dict:
    """
    Busca CVEs en el NVD por descripcion o termino tecnico.
    Devuelve los CVEs mas relevantes con su informacion basica.
    """
    try:
        params = {
            "keywordSearch": termino,
            "resultsPerPage": max_resultados,
            "startIndex": 0
        }

        # --- CAMBIO 6: timeout 15 → 30 segundos + headers ---
        headers = {**HEADERS, **({"apiKey": os.environ["NVD_API_KEY"]} if os.getenv("NVD_API_KEY") else {})}
        data = get_json(NVD_BASE_URL, params=params, headers=headers, timeout=30)

        total = data.get("totalResults", 0)
        vulnerabilidades = data.get("vulnerabilities", [])

        cves = []
        for vuln in vulnerabilidades:
            cve = vuln["cve"]

            cvss = seleccionar_cvss(cve.get('metrics', {}))
            # Descripcion en ingles
            descripcion = ""
            for desc in cve.get("descriptions", []):
                if desc["lang"] == "en":
                    descripcion = _limpiar_html(desc["value"])
                    break

            cves.append({
                "cve_id": cve["id"],
                "descripcion": descripcion,
                "cvss_score": cvss["cvss_score"],
                "fecha_publicacion": cve.get("published", ""),
            })

        return {
            "total": total,
            "cves": cves
        }

    except requests.exceptions.Timeout:
        return {"error": "NVD tardó demasiado en responder. Inténtalo de nuevo.", "cves": []}

    except (requests.exceptions.RequestException, ValueError, KeyError, TypeError) as e:
        return {"error": f"Error al buscar en NVD: {str(e)}", "cves": []}
