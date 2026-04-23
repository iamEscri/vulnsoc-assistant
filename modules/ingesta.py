import requests
from bs4 import BeautifulSoup

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _limpiar_html(texto: str) -> str:
    """Elimina etiquetas HTML de la descripcion del NVD."""
    return BeautifulSoup(texto, "html.parser").get_text(separator=" ").strip()


def obtener_datos_nvd(cve_id: str) -> dict:
    """Consulta la API del NVD y devuelve los datos del CVE."""
    params = {"cveId": cve_id}

    try:
        response = requests.get(NVD_BASE_URL, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        if data["totalResults"] == 0:
            return {"error": f"CVE {cve_id} no encontrado en NVD"}

        cve = data["vulnerabilities"][0]["cve"]

        # Extraer CVSS score (v3 preferente, v2 como fallback)
        cvss_score = None
        cvss_version = None

        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            cvss_version = "3.1"
        elif "cvssMetricV30" in metrics:
            cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            cvss_version = "3.0"
        elif "cvssMetricV2" in metrics:
            cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            cvss_version = "2.0"

        # Descripcion en ingles — limpia de HTML
        descripcion = ""
        for desc in cve.get("descriptions", []):
            if desc["lang"] == "en":
                descripcion = _limpiar_html(desc["value"])
                break

        return {
            "cve_id": cve_id,
            "descripcion": descripcion,
            "cvss_score": cvss_score,
            "cvss_version": cvss_version,
            "fecha_publicacion": cve.get("published", ""),
            "fecha_modificacion": cve.get("lastModified", ""),
            "referencias": [r["url"] for r in cve.get("references", [])[:5]]
        }

    except requests.exceptions.RequestException as e:
        return {"error": f"Error al conectar con NVD: {str(e)}"}


def comprobar_cisa_kev(cve_id: str) -> dict:
    """Comprueba si el CVE esta en el catalogo CISA KEV."""
    try:
        response = requests.get(CISA_KEV_URL, timeout=15)
        response.raise_for_status()
        data = response.json()

        for vuln in data.get("vulnerabilities", []):
            if vuln.get("cveID") == cve_id:
                return {
                    "en_kev": True,
                    "nombre": vuln.get("vulnerabilityName", ""),
                    "fecha_añadido": vuln.get("dateAdded", ""),
                    "accion_requerida": vuln.get("requiredAction", ""),
                    "fecha_limite": vuln.get("dueDate", "")
                }

        return {"en_kev": False}

    except requests.exceptions.RequestException as e:
        return {"error": f"Error al conectar con CISA KEV: {str(e)}"}


def analizar_cve(cve_id: str) -> dict:
    """Funcion principal: obtiene todos los datos de un CVE."""
    print(f"Consultando NVD para {cve_id}...")
    datos_nvd = obtener_datos_nvd(cve_id)

    print(f"Comprobando CISA KEV para {cve_id}...")
    datos_kev = comprobar_cisa_kev(cve_id)

    return {
        "nvd": datos_nvd,
        "kev": datos_kev
    }