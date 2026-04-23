from datetime import datetime


def calcular_score(datos_nvd: dict, datos_kev: dict) -> dict:
    """
    Motor de scoring propio para priorización de vulnerabilidades.
    
    Diseño:
    - score_interno: puntuación real sin límite, para ordenar y comparar CVEs
    - score_mostrado: capado a 100, estable y comparable con estándares
    - prioridad: derivada del score_mostrado, con umbrales fijos
    
    Se descartó normalización proporcional (MAX_POSIBLE) por ser frágil
    ante cambios en el modelo. Se usa capping por robustez y estabilidad.
    """

    if "error" in datos_nvd:
        return {"error": datos_nvd["error"], "score_interno": 0, "score_mostrado": 0}

    puntuacion = 0
    factores = []

    # --- FACTOR 1: CVSS base (0-100) ---
    cvss = datos_nvd.get("cvss_score")
    if cvss is not None:
        puntos_cvss = round(cvss * 10)
        puntuacion += puntos_cvss
        factores.append({
            "factor": "CVSS base",
            "puntos": puntos_cvss,
            "detalle": f"CVSS {datos_nvd.get('cvss_version')} = {cvss}"
        })

    # --- FACTOR 2: En CISA KEV (+30) ---
    if datos_kev.get("en_kev"):
        puntuacion += 30
        factores.append({
            "factor": "En CISA KEV",
            "puntos": 30,
            "detalle": f"Explotación activa confirmada desde {datos_kev.get('fecha_añadido')}"
        })

    # --- FACTOR 3: Vulnerabilidad reciente < 30 días (+20) ---
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
                    "detalle": f"Publicada hace {dias} días"
                })
        except ValueError:
            pass

    # --- Score interno: sin límite, para ordenar entre CVEs ---
    score_interno = round(puntuacion)

    # --- Score mostrado: capado a 100, estable y comparable ---
    score_mostrado = min(score_interno, 100)

    # --- Prioridad: siempre sobre score_mostrado, umbrales fijos ---
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
        "factores": factores
    }