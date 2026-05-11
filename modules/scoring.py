from datetime import datetime

# Mapeo de CWEs a tipos de vulnerabilidad y puntuacion
CWE_SCORING = {
    # RCE - Ejecucion remota de codigo
    "CWE-78":  ("RCE",     25),  # OS Command Injection
    "CWE-94":  ("RCE",     25),  # Code Injection
    "CWE-502": ("RCE",     25),  # Deserialization
    "CWE-77":  ("RCE",     25),  # Command Injection
    # Escalada de privilegios
    "CWE-269": ("PrivEsc", 18),  # Improper Privilege Management
    "CWE-732": ("PrivEsc", 18),  # Incorrect Permission Assignment
    "CWE-284": ("PrivEsc", 18),  # Improper Access Control
    # Inyeccion SQL
    "CWE-89":  ("SQLi",    15),  # SQL Injection
    # XSS
    "CWE-79":  ("XSS",     10),  # Cross-site Scripting
    # Path Traversal
    "CWE-22":  ("PathTrav",12),  # Path Traversal
    # DoS
    "CWE-400": ("DoS",      8),  # Resource Exhaustion
    "CWE-20":  ("DoS",      8),  # Improper Input Validation
}


def _detectar_tipo_vulnerabilidad(cwes: list, descripcion: str) -> tuple:
    """
    Detecta el tipo de vulnerabilidad y su puntuacion.
    Primero busca en CWEs oficiales, luego en la descripcion como fallback.
    """
    # Buscar en CWEs oficiales
    mejor_tipo = None
    mejor_puntos = 0

    for cwe in cwes:
        if cwe in CWE_SCORING:
            tipo, puntos = CWE_SCORING[cwe]
            if puntos > mejor_puntos:
                mejor_tipo = tipo
                mejor_puntos = puntos

    if mejor_tipo:
        return mejor_tipo, mejor_puntos

    # Fallback: buscar en la descripcion
    desc_lower = descripcion.lower()
    if any(t in desc_lower for t in ["remote code execution", "arbitrary code", "rce"]):
        return "RCE", 25
    if any(t in desc_lower for t in ["privilege escalation", "escalation of privilege", "system privileges"]):
        return "PrivEsc", 18
    if "sql injection" in desc_lower:
        return "SQLi", 15
    if "cross-site scripting" in desc_lower or "xss" in desc_lower:
        return "XSS", 10
    if any(t in desc_lower for t in ["denial of service", "dos", "crash"]):
        return "DoS", 8

    return "Desconocido", 0


def calcular_score(datos_nvd: dict, datos_kev: dict, datos_epss: dict = None) -> dict:
    """
    Motor de scoring propio para priorizacion de vulnerabilidades.

    Factores:
    1. CVSS base          (0-100)
    2. CISA KEV           (+30)
    3. Reciente < 30 dias (+20)
    4. EPSS               (+25 si >0.7 / +10 si >0.3)
    5. Tipo vulnerabilidad (+8 a +25 segun CWE/descripcion)
    6. Vector de ataque   (+15 red / +10 sin auth / +10 sin interaccion / +10 baja complejidad)

    Diseno:
    - score_interno: puntuacion real sin limite, para ordenar CVEs
    - score_mostrado: capado a 100, estable y comparable con CVSS
    - prioridad: derivada de score_mostrado con umbrales fijos
    """

    if "error" in datos_nvd:
        return {"error": datos_nvd["error"], "score_interno": 0, "score_mostrado": 0}

    if datos_epss is None:
        datos_epss = {}

    puntuacion = 0
    factores = []

    # ── FACTOR 1: CVSS base ───────────────────────────────────────────────────
    cvss = datos_nvd.get("cvss_score")
    if cvss is not None:
        puntos_cvss = round(cvss * 10)
        puntuacion += puntos_cvss
        factores.append({
            "factor": "CVSS base",
            "puntos": puntos_cvss,
            "detalle": f"CVSS {datos_nvd.get('cvss_version')} = {cvss}"
        })

    # ── FACTOR 2: CISA KEV ────────────────────────────────────────────────────
    if datos_kev.get("en_kev"):
        puntuacion += 30
        factores.append({
            "factor": "En CISA KEV",
            "puntos": 30,
            "detalle": f"Explotacion activa confirmada desde {datos_kev.get('fecha_añadido')}"
        })

    # ── FACTOR 3: Recencia ────────────────────────────────────────────────────
    fecha_pub = datos_nvd.get("fecha_publicacion", "")
    if fecha_pub:
        try:
            fecha = datetime.fromisoformat(fecha_pub)
            dias = (datetime.now() - fecha).days
            if dias < 30:
                puntuacion += 20
                factores.append({
                    "factor": "Vulnerabilidad reciente",
                    "puntos": 20,
                    "detalle": f"Publicada hace {dias} dias — ventana de parche abierta"
                })
        except ValueError:
            pass

    # ── FACTOR 4: EPSS ────────────────────────────────────────────────────────
    epss_score = datos_epss.get("epss_score", 0.0)
    if epss_score > 0.7:
        puntuacion += 25
        factores.append({
            "factor": "EPSS alto",
            "puntos": 25,
            "detalle": f"Probabilidad de explotacion: {epss_score:.1%} (top {100 - round(datos_epss.get('percentil', 0) * 100)}%)"
        })
    elif epss_score > 0.3:
        puntuacion += 10
        factores.append({
            "factor": "EPSS moderado",
            "puntos": 10,
            "detalle": f"Probabilidad de explotacion: {epss_score:.1%}"
        })

    # ── FACTOR 5: Tipo de vulnerabilidad ─────────────────────────────────────
    cwes = datos_nvd.get("cwes", [])
    descripcion = datos_nvd.get("descripcion", "")
    tipo_vuln, puntos_tipo = _detectar_tipo_vulnerabilidad(cwes, descripcion)

    if puntos_tipo > 0:
        puntuacion += puntos_tipo
        factores.append({
            "factor": f"Tipo: {tipo_vuln}",
            "puntos": puntos_tipo,
            "detalle": f"CWEs: {', '.join(cwes) if cwes else 'detectado en descripcion'}"
        })

    # ── FACTOR 6: Vector de ataque ────────────────────────────────────────────
    vector = datos_nvd.get("vector_ataque", {})

    if vector.get("attackVector") == "NETWORK":
        puntuacion += 15
        factores.append({
            "factor": "Vector: red",
            "puntos": 15,
            "detalle": "Explotable remotamente sin acceso fisico"
        })

    if vector.get("privilegesRequired") == "NONE":
        puntuacion += 10
        factores.append({
            "factor": "Sin autenticacion",
            "puntos": 10,
            "detalle": "No requiere credenciales para explotar"
        })

    if vector.get("userInteraction") == "NONE":
        puntuacion += 10
        factores.append({
            "factor": "Sin interaccion usuario",
            "puntos": 10,
            "detalle": "No requiere que la victima haga ninguna accion"
        })

    if vector.get("attackComplexity") == "LOW":
        puntuacion += 10
        factores.append({
            "factor": "Baja complejidad",
            "puntos": 10,
            "detalle": "No requiere condiciones especiales para explotar"
        })

    # ── Score final ───────────────────────────────────────────────────────────
    score_interno = round(puntuacion)
    score_mostrado = min(score_interno, 100)

    if score_mostrado >= 80:
        prioridad = "CRÍTICA"
    elif score_mostrado >= 60:
        prioridad = "ALTA"
    elif score_mostrado >= 40:
        prioridad = "MEDIA"
    else:
        prioridad = "BAJA"

    return {
        "score_interno": score_interno,
        "score_mostrado": score_mostrado,
        "score_cvss_puro": round(cvss * 10) if cvss else 0,
        "prioridad": prioridad,
        "tipo_vulnerabilidad": tipo_vuln,
        "epss_score": epss_score,
        "factores": factores
    }