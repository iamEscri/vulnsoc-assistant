import requests
from bs4 import BeautifulSoup

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


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

        # Extraer CVSS score y vector completo
        cvss_score = None
        cvss_version = None
        vector_ataque = {}

        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]
            cvss_score = m["cvssData"]["baseScore"]
            cvss_version = "3.1"
            vector_ataque = {
                "attackVector":       m["cvssData"].get("attackVector", ""),
                "attackComplexity":   m["cvssData"].get("attackComplexity", ""),
                "privilegesRequired": m["cvssData"].get("privilegesRequired", ""),
                "userInteraction":    m["cvssData"].get("userInteraction", ""),
            }
        elif "cvssMetricV30" in metrics:
            m = metrics["cvssMetricV30"][0]
            cvss_score = m["cvssData"]["baseScore"]
            cvss_version = "3.0"
            vector_ataque = {
                "attackVector":       m["cvssData"].get("attackVector", ""),
                "attackComplexity":   m["cvssData"].get("attackComplexity", ""),
                "privilegesRequired": m["cvssData"].get("privilegesRequired", ""),
                "userInteraction":    m["cvssData"].get("userInteraction", ""),
            }
        elif "cvssMetricV2" in metrics:
            m = metrics["cvssMetricV2"][0]
            cvss_score = m["cvssData"]["baseScore"]
            cvss_version = "2.0"

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

        return {
            "cve_id": cve_id,
            "descripcion": descripcion,
            "cvss_score": cvss_score,
            "cvss_version": cvss_version,
            "vector_ataque": vector_ataque,
            "cwes": cwes,
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


def obtener_epss(cve_id: str) -> dict:
    """Consulta la API de EPSS para obtener la probabilidad de explotacion."""
    try:
        response = requests.get(EPSS_URL, params={"cve": cve_id}, timeout=10)
        response.raise_for_status()
        data = response.json()

        if data.get("data"):
            epss = data["data"][0]
            return {
                "epss_score": float(epss.get("epss", 0)),
                "percentil": float(epss.get("percentile", 0))
            }

        return {"epss_score": 0.0, "percentil": 0.0}

    except requests.exceptions.RequestException as e:
        return {"epss_score": 0.0, "percentil": 0.0, "error": str(e)}


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

def buscar_cves_por_descripcion(termino: str, max_resultados: int = 10) -> dict:
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

        response = requests.get(NVD_BASE_URL, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()

        total = data.get("totalResults", 0)
        vulnerabilidades = data.get("vulnerabilities", [])

        cves = []
        for vuln in vulnerabilidades:
            cve = vuln["cve"]

            # CVSS score
            cvss_score = None
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in metrics:
                cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            # Descripcion en ingles
            descripcion = ""
            for desc in cve.get("descriptions", []):
                if desc["lang"] == "en":
                    descripcion = _limpiar_html(desc["value"])
                    break

            cves.append({
                "cve_id": cve["id"],
                "descripcion": descripcion,
                "cvss_score": cvss_score or "N/A",
                "fecha_publicacion": cve.get("published", ""),
            })

        return {
            "total": total,
            "cves": cves
        }

    except requests.exceptions.RequestException as e:
        return {"error": f"Error al buscar en NVD: {str(e)}", "cves": []}