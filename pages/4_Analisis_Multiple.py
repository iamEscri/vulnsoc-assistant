import time
import streamlit as st
from modules.ingesta import analizar_cve
from modules.scoring import calcular_score
from modules.analisis_ia import generar_analisis

st.set_page_config(
    page_title="Análisis múltiple — VulnSOC Assistant",
    page_icon="📋",
    layout="wide"
)

st.title("📋 Análisis múltiple de CVEs")
st.caption("Introduce varios CVEs para analizarlos y compararlos ordenados por prioridad.")
st.divider()

# ── INICIALIZAR HISTORIAL SI NO EXISTE ─────────────────────────────────────
# Misma lógica que app.py: si el usuario llega aquí sin haber pasado por
# la página principal, nos aseguramos de que historial existe.
if "historial" not in st.session_state:
    st.session_state.historial = []

# ── ENTRADA DEL USUARIO ────────────────────────────────────────────────────
st.subheader("CVEs a analizar")
texto_cves = st.text_area(
    "Introduce los CVEs separados por comas, espacios o saltos de línea",
    placeholder="CVE-2021-44228\nCVE-2021-34527\nCVE-2023-44487",
    height=120,
    help="Puedes pegar una lista directamente desde un informe o ticket."
)

analizar = st.button("🔍 Analizar todos", type="primary")

# ── PARSEAR CVEs DEL INPUT ─────────────────────────────────────────────────
def parsear_cves(texto):
    """Extrae CVE-IDs válidos del texto libre del usuario."""
    import re
    # Buscamos el patrón CVE-AÑO-NÚMERO directamente, ignorando separadores
    encontrados = re.findall(r"CVE-\d{4}-\d+", texto.upper())
    # Eliminamos duplicados manteniendo el orden
    vistos = set()
    unicos = []
    for cve in encontrados:
        if cve not in vistos:
            vistos.add(cve)
            unicos.append(cve)
    return unicos

# ── ANÁLISIS ───────────────────────────────────────────────────────────────
if analizar and texto_cves.strip():
    cves = parsear_cves(texto_cves)

    if not cves:
        st.warning("No se encontraron CVEs válidos. Formato esperado: CVE-AÑO-NÚMERO (ej. CVE-2021-44228)")
        st.stop()

    st.info(f"🔄 Analizando {len(cves)} CVE(s): {', '.join(cves)}")

    resultados_multiple = []
    errores = []

    # Barra de progreso — se actualiza CVE a CVE
    barra = st.progress(0, text="Iniciando análisis...")

    for i, cve_id in enumerate(cves):
        barra.progress(i / len(cves), text=f"Analizando {cve_id}... ({i+1}/{len(cves)})")

        # Pausa entre CVEs para no saturar NVD ni la API de IA con peticiones consecutivas
        if i > 0:
            time.sleep(3)

        # 1. Ingesta de datos
        resultado = analizar_cve(cve_id)

        if "error" in resultado["nvd"]:
            errores.append((cve_id, resultado["nvd"]["error"]))
            continue

        # 2. Scoring
        score = calcular_score(resultado["nvd"], resultado["kev"], resultado["epss"])

        # 3. Análisis IA
        analisis = generar_analisis(resultado["nvd"], resultado["kev"], score)

        # 4. Guardar en historial de sesión (igual que app.py)
        ids_en_historial = [e["cve_id"] for e in st.session_state.historial]
        entrada = {
            "cve_id": cve_id,
            "score_mostrado": score["score_mostrado"],
            "score_interno": score["score_interno"],
            "prioridad": score["prioridad"],
            "tipo": score.get("tipo_vulnerabilidad", "Desconocido"),
            "en_kev": resultado["kev"].get("en_kev", False),
            "epss_score": score.get("epss_score", 0),
            "resultado": resultado,
            "score": score,
            "analisis": analisis,
        }
        if cve_id in ids_en_historial:
            idx = ids_en_historial.index(cve_id)
            st.session_state.historial[idx] = entrada
        else:
            st.session_state.historial.insert(0, entrada)

        resultados_multiple.append(entrada)

    barra.progress(1.0, text="✅ Análisis completado")

    # Guardar en session_state para persistir si el usuario navega y vuelve
    st.session_state.resultados_multiple = resultados_multiple
    st.session_state.errores_multiple = errores

# ── MOSTRAR RESULTADOS ─────────────────────────────────────────────────────
COLOR_PRIORIDAD = {
    "CRÍTICA": "🔴",
    "ALTA":    "🟠",
    "MEDIA":   "🟡",
    "BAJA":    "🟢",
}

resultados_multiple = st.session_state.get("resultados_multiple", [])
errores = st.session_state.get("errores_multiple", [])

if resultados_multiple:
    st.divider()

    # Ordenar por score_interno descendente (más urgente primero)
    resultados_ordenados = sorted(resultados_multiple, key=lambda x: x["score_interno"], reverse=True)

    # ── MÉTRICAS RESUMEN ───────────────────────────────────────────────────
    total    = len(resultados_ordenados)
    criticos = sum(1 for e in resultados_ordenados if e["prioridad"] == "CRÍTICA")
    en_kev   = sum(1 for e in resultados_ordenados if e["en_kev"])

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("CVEs analizados", total)
    with c2:
        st.metric("Prioridad CRÍTICA", criticos)
    with c3:
        st.metric("En CISA KEV", en_kev)

    st.divider()

    # ── TABLA COMPARATIVA ──────────────────────────────────────────────────
    st.subheader("Resultados ordenados por prioridad")

    # Cabecera de la tabla
    h1, h2, h3, h4, h5, h6, h7, h8 = st.columns([2, 1.2, 1.2, 1.5, 1.5, 1, 1, 1.5])
    with h1: st.markdown("**CVE**")
    with h2: st.markdown("**Score**")
    with h3: st.markdown("**Interno**")
    with h4: st.markdown("**Prioridad**")
    with h5: st.markdown("**Tipo**")
    with h6: st.markdown("**EPSS**")
    with h7: st.markdown("**KEV**")
    with h8: st.markdown("**Acción**")
    st.divider()

    for entrada in resultados_ordenados:
        cve_id    = entrada["cve_id"]
        prioridad = entrada["prioridad"]
        icono     = COLOR_PRIORIDAD.get(prioridad, "⚪")
        kev_badge = "⚠️ KEV" if entrada["en_kev"] else ""
        epss_pct  = f"{entrada['epss_score']:.1%}"

        col_cve, col_score, col_interno, col_prio, col_tipo, col_epss, col_kev, col_btn = st.columns(
            [2, 1.2, 1.2, 1.5, 1.5, 1, 1, 1.5]
        )
        with col_cve:
            st.write(f"**{cve_id}**")
        with col_score:
            st.write(f"{entrada['score_mostrado']}/100")
        with col_interno:
            st.write(f"{entrada['score_interno']}")
        with col_prio:
            st.write(f"{icono} {prioridad}")
        with col_tipo:
            st.write(entrada["tipo"])
        with col_epss:
            st.write(epss_pct)
        with col_kev:
            st.write(kev_badge)
        with col_btn:
            # Carga el análisis completo de ese CVE en la página principal
            if st.button("📂 Ver detalle", key=f"multi_{cve_id}"):
                st.session_state.resultado     = entrada["resultado"]
                st.session_state.score         = entrada["score"]
                st.session_state.analisis      = entrada["analisis"]
                st.session_state.cve_analizado = cve_id
                st.switch_page("app.py")

        st.divider()

# ── ERRORES ────────────────────────────────────────────────────────────────
if errores:
    st.subheader("⚠️ CVEs con error")
    for cve_id, msg in errores:
        st.error(f"**{cve_id}**: {msg}")

elif analizar and texto_cves.strip() and not resultados_multiple:
    pass  # Los errores ya se muestran arriba; si no hay nada es porque todos fallaron

elif not analizar and not resultados_multiple:
    st.info("Introduce uno o varios CVEs arriba y pulsa **Analizar todos**.")
