import os
from dotenv import load_dotenv

load_dotenv()

IA_PROVIDER = os.getenv("IA_PROVIDER", "groq").lower()


def _get_groq_client():
    from groq import Groq
    return Groq(api_key=os.getenv("GROQ_API_KEY"))

def _get_gemini_client():
    from google import genai
    return genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

def _get_openai_client():
    from openai import OpenAI
    return OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def _llamar_groq(prompt: str) -> str:
    client = _get_groq_client()
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=1024
    )
    return response.choices[0].message.content

def _llamar_gemini(prompt: str) -> str:
    client = _get_gemini_client()
    response = client.models.generate_content(
        model="gemini-2.0-flash-lite",
        contents=prompt
    )
    return response.text

def _llamar_openai(prompt: str) -> str:
    client = _get_openai_client()
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=1024
    )
    return response.choices[0].message.content


def _llamar_ia(prompt: str) -> str:
    if IA_PROVIDER == "groq":
        return _llamar_groq(prompt)
    elif IA_PROVIDER == "gemini":
        return _llamar_gemini(prompt)
    elif IA_PROVIDER == "openai":
        return _llamar_openai(prompt)
    else:
        raise ValueError(f"Proveedor no reconocido: {IA_PROVIDER}")


def _detectar_alucinacion(texto: str, contexto: str) -> bool:
    """
    Deteccion basica de alucinaciones.
    Comprueba si el modelo añadio informacion no presente en el contexto.
    """
    señales = [
        "windows server 2012",
        "windows server 2016", 
        "windows 10",
        "hkey_local_machine",
        "group policy",
        "kb500"
    ]
    contexto_lower = contexto.lower()
    texto_lower = texto.lower()

    for señal in señales:
        if señal in texto_lower and señal not in contexto_lower:
            return True
    return False


def _construir_contexto(datos_nvd: dict, datos_kev: dict, score: dict) -> str:
    """Construye el contexto con TODOS los datos disponibles."""
    contexto = f"""
=== DATOS DISPONIBLES (USA SOLO ESTOS) ===

CVE ID: {datos_nvd.get('cve_id', 'No disponible')}
Descripcion tecnica: {datos_nvd.get('descripcion', 'No disponible')}
CVSS Score: {datos_nvd.get('cvss_score', 'No disponible')} (version {datos_nvd.get('cvss_version', 'No disponible')})
Fecha publicacion: {datos_nvd.get('fecha_publicacion', 'No disponible')}
Fecha ultima modificacion: {datos_nvd.get('fecha_modificacion', 'No disponible')}
Referencias: {', '.join(datos_nvd.get('referencias', [])) or 'No disponible'}
En CISA KEV (explotacion activa confirmada): {datos_kev.get('en_kev', False)}
Prioridad calculada por el sistema: {score.get('prioridad', 'No disponible')}
Score del sistema: {score.get('score_mostrado', 0)}/100
Score CVSS puro: {score.get('score_cvss_puro', 0)}/100
"""

    if datos_kev.get("en_kev"):
        contexto += f"""
Nombre en KEV: {datos_kev.get('nombre', 'No disponible')}
Accion requerida por CISA: {datos_kev.get('accion_requerida', 'No disponible')}
Fecha limite parche: {datos_kev.get('fecha_limite', 'No disponible')}
"""
    return contexto


INSTRUCCION_BASE = """
INSTRUCCIONES ESTRICTAS:
- Usa EXCLUSIVAMENTE la informacion del bloque de DATOS DISPONIBLES.
- Si un dato no esta presente en ese bloque, escribe literalmente: "No disponible en los datos proporcionados."
- NO añadas conocimiento externo, versiones especificas, claves de registro, ni comandos que no aparezcan en los datos.
- NO inventes sistemas afectados si no aparecen en la descripcion.
- Tu unica fuente de verdad son los DATOS DISPONIBLES.
"""


def generar_analisis(datos_nvd: dict, datos_kev: dict, score: dict) -> dict:
    """
    Genera analisis completo del CVE usando el proveedor configurado.
    Incluye deteccion de alucinaciones para garantizar que la IA
    no añade informacion no presente en los datos reales.
    """

    contexto = _construir_contexto(datos_nvd, datos_kev, score)

    prompt_ejecutivo = f"""
Eres un analista de ciberseguridad experto en SOC.
{INSTRUCCION_BASE}

Escribe un resumen ejecutivo en español de maximo 3 parrafos
para un responsable de seguridad no tecnico.
Explica que es la vulnerabilidad, por que es urgente y que decision hay que tomar.

{contexto}
"""

    prompt_tecnico = f"""
Eres un analista de ciberseguridad experto en SOC.
{INSTRUCCION_BASE}

Escribe un analisis tecnico en español para un analista SOC.
Describe el impacto y el contexto de explotacion basado UNICAMENTE
en los datos disponibles. No inventes sistemas afectados,
versiones especificas ni configuraciones que no aparezcan en los datos.

{contexto}
"""

    prompt_mitigacion = f"""
Eres un analista de ciberseguridad experto en SOC.
{INSTRUCCION_BASE}

Genera un plan de mitigacion en español con pasos ordenados por urgencia.
Basa los pasos UNICAMENTE en la informacion disponible.
Si no hay detalles tecnicos especificos, indica que se deben seguir
las instrucciones del proveedor segun las referencias proporcionadas.

{contexto}
"""

    try:
        print(f"Generando analisis con proveedor: {IA_PROVIDER}...")

        resumen_ejecutivo = _llamar_ia(prompt_ejecutivo)
        analisis_tecnico = _llamar_ia(prompt_tecnico)
        plan_mitigacion = _llamar_ia(prompt_mitigacion)

        # Deteccion de alucinaciones
        alucinacion_detectada = (
            _detectar_alucinacion(resumen_ejecutivo, contexto) or
            _detectar_alucinacion(analisis_tecnico, contexto) or
            _detectar_alucinacion(plan_mitigacion, contexto)
        )

        if alucinacion_detectada:
            print("⚠️  Posible alucinacion detectada — el modelo puede haber añadido informacion externa")

        return {
            "proveedor": IA_PROVIDER,
            "alucinacion_detectada": alucinacion_detectada,
            "resumen_ejecutivo": resumen_ejecutivo,
            "analisis_tecnico": analisis_tecnico,
            "plan_mitigacion": plan_mitigacion
        }

    except Exception as e:
        return {"error": f"Error con proveedor {IA_PROVIDER}: {str(e)}"}

def generar_regla_sigma(datos_nvd: dict, datos_kev: dict) -> dict:
    """
    Genera una regla Sigma para el CVE dado.
    Primero busca en SigmaHQ (reglas validadas por la comunidad).
    Si no existe, la genera con IA marcándola como borrador.
    """
    import requests

    cve_id      = datos_nvd.get("cve_id", "")
    descripcion = datos_nvd.get("descripcion", "")
    cwes        = datos_nvd.get("cwes", [])

    # ── 1. BUSCAR EN SIGNAHQ ───────────────────────────────────────────────
    # Buscamos el CVE ID en el repositorio oficial SigmaHQ/sigma via GitHub API
    try:
        gh_url = "https://api.github.com/search/code"
        headers = {"Accept": "application/vnd.github.v3+json"}
        params  = {"q": f"{cve_id} repo:SigmaHQ/sigma", "per_page": 3}
        resp = requests.get(gh_url, headers=headers, params=params, timeout=10)

        if resp.status_code == 200:
            items = resp.json().get("items", [])
            if items:
                # Descargamos el contenido del primer resultado
                raw_url = items[0]["html_url"].replace(
                    "github.com", "raw.githubusercontent.com"
                ).replace("/blob/", "/")
                raw_resp = requests.get(raw_url, timeout=10)
                if raw_resp.status_code == 200:
                    return {
                        "origen": "sigmaHQ",
                        "url_fuente": items[0]["html_url"],
                        "regla": raw_resp.text,
                        "advertencia": None
                    }
    except Exception:
        pass  # Si falla la búsqueda en GitHub, continuamos con IA

    # ── 2. GENERAR CON IA ──────────────────────────────────────────────────
    prompt_sigma = f"""
Eres un experto en detección de amenazas y formato Sigma.

Genera UNA regla Sigma en formato YAML válido para detectar intentos de explotación
de la siguiente vulnerabilidad. La regla debe seguir estrictamente la especificación
Sigma (https://github.com/SigmaHQ/sigma).

Vulnerabilidad:
- CVE ID: {cve_id}
- Descripción: {descripcion}
- CWEs: {', '.join(cwes) if cwes else 'No disponible'}
- En CISA KEV (explotación activa): {datos_kev.get('en_kev', False)}

INSTRUCCIONES ESTRICTAS:
- Responde ÚNICAMENTE con el bloque YAML de la regla Sigma, sin explicaciones.
- Incluye los campos: title, id, status, description, references, author, date,
  tags (con el CVE), logsource, detection y falsepositives.
- Marca status como: experimental
- El campo id debe ser un UUID v4 generado aleatoriamente.
- No añadas texto fuera del bloque YAML.
"""

    try:
        regla_yaml = _llamar_ia(prompt_sigma)

        # Limpiar posibles bloques de código markdown que el LLM añada
        regla_yaml = regla_yaml.strip()
        if regla_yaml.startswith("```"):
            lineas = regla_yaml.splitlines()
            regla_yaml = "\n".join(
                l for l in lineas if not l.startswith("```")
            ).strip()

        return {
            "origen": "ia_generada",
            "url_fuente": None,
            "regla": regla_yaml,
            "advertencia": (
                "⚠️ Esta regla ha sido generada por IA y NO ha sido validada. "
                "Requiere revisión técnica por un analista antes de desplegarse en producción."
            )
        }

    except Exception as e:
        return {"error": f"Error generando regla Sigma: {str(e)}"}
