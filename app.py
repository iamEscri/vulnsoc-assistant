import streamlit as st
from modules.ingesta import analizar_cve
from modules.scoring import calcular_score
from modules.analisis_ia import generar_analisis
from modules.exportar_pdf import generar_pdf

# ── RECOGER CVE DESDE URL O SESSION STATE ─────────────────────────────────
params = st.query_params
cve_preseleccionado = params.get("cve", "")

if not cve_preseleccionado:
    cve_preseleccionado = st.session_state.get("cve_desde_busqueda", "")
    if cve_preseleccionado:
        st.session_state.cve_desde_busqueda = None

st.set_page_config(
    page_title="VulnSOC Assistant",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ VulnSOC Assistant")
st.caption("Sistema inteligente de análisis y priorización de vulnerabilidades para SOC")
st.divider()

# ── SESSION STATE ──────────────────────────────────────────────────────────
if "resultado" not in st.session_state:
    st.session_state.resultado = None
    st.session_state.score = None
    st.session_state.analisis = None
    st.session_state.cve_analizado = None

if "historial" not in st.session_state:
    st.session_state.historial = []

# ── ENTRADA DEL USUARIO ────────────────────────────────────────────────────
col1, col2 = st.columns([3, 1])
with col1:
    cve_id = st.text_input(
        "Introduce el CVE a analizar",
        value=cve_preseleccionado,
        placeholder="CVE-2021-44228",
        help="Formato: CVE-AÑO-NÚMERO"
    )
with col2:
    st.write("")
    st.write("")
    analizar = st.button("🔍 Analizar", type="primary", use_container_width=True)

# ── ANALISIS ───────────────────────────────────────────────────────────────
if analizar and cve_id:
    cve_id = cve_id.strip().upper()

    with st.spinner(f"Consultando fuentes de datos para {cve_id}..."):
        resultado = analizar_cve(cve_id)

    if "error" in resultado["nvd"]:
        st.error(f"❌ {resultado['nvd']['error']}")
        st.stop()

    with st.spinner("Calculando scoring..."):
        score = calcular_score(resultado["nvd"], resultado["kev"], resultado["epss"])

    with st.spinner("Generando análisis con IA..."):
        analisis = generar_analisis(resultado["nvd"], resultado["kev"], score)

    st.session_state.resultado = resultado
    st.session_state.score = score
    st.session_state.analisis = analisis
    st.session_state.cve_analizado = cve_id

    # ── GUARDAR EN HISTORIAL DE SESIÓN ─────────────────────────────────────
    # Evitamos duplicados: si el CVE ya está en el historial, lo actualizamos
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
        st.session_state.historial.insert(0, entrada)  # más reciente primero

# ── MOSTRAR RESULTADOS ─────────────────────────────────────────────────────
if st.session_state.resultado:
    resultado = st.session_state.resultado
    score = st.session_state.score
    analisis = st.session_state.analisis
    cve_id = st.session_state.cve_analizado
    kev = resultado["kev"].get("en_kev", False)
    epss = score.get("epss_score", 0)
    prioridad = score["prioridad"]
    color = {"CRÍTICA": "🔴", "ALTA": "🟠", "MEDIA": "🟡", "BAJA": "🟢"}

    st.subheader(f"📊 {cve_id}")
    m1, m2, m3, m4, m5, m6, m7 = st.columns(7)
    with m1:
        st.metric("Score sistema", f"{score['score_mostrado']}/100")
    with m2:
        st.metric("Score interno", score['score_interno'],
                  help="Puntuación real sin límite. Útil para ordenar CVEs con score igual.")
    with m3:
        st.metric("CVSS puro", f"{score['score_cvss_puro']}/100")
    with m4:
        st.metric("Prioridad", f"{color.get(prioridad, '')} {prioridad}")
    with m5:
        st.metric("En CISA KEV", "✅ Sí" if kev else "❌ No")
    with m6:
        st.metric("EPSS", f"{epss:.1%}")
    with m7:
        st.metric("Tipo", score.get("tipo_vulnerabilidad", "Desconocido"))

    if kev:
        st.warning(
            f"⚠️ **Explotación activa confirmada** — "
            f"Añadido a CISA KEV el {resultado['kev'].get('fecha_añadido')} · "
            f"Fecha límite parche: {resultado['kev'].get('fecha_limite')}"
        )

    if analisis.get("alucinacion_detectada"):
        st.warning("⚠️ Se detectó posible información externa en el análisis. Revisa manualmente.")

    st.divider()

    pdf_bytes = generar_pdf(
        resultado["nvd"], resultado["kev"],
        resultado["epss"], score, analisis
    )
    st.download_button(
        label="📥 Descargar informe PDF",
        data=pdf_bytes,
        file_name=f"vulnsoc_{cve_id}.pdf",
        mime="application/pdf"
    )

    st.divider()

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📋 Resumen ejecutivo",
        "🔬 Análisis técnico",
        "🛠️ Plan de mitigación",
        "📊 Scoring detallado",
        "📄 Datos brutos"
    ])

    with tab1:
        st.markdown(analisis.get("resumen_ejecutivo", "No disponible"))

    with tab2:
        st.markdown(analisis.get("analisis_tecnico", "No disponible"))

    with tab3:
        st.markdown(analisis.get("plan_mitigacion", "No disponible"))

    with tab4:
        st.subheader("Puntuaciones")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Score interno", score.get("score_interno", 0),
                      help="Puntuación real acumulada sin límite.")
        with c2:
            st.metric("Score mostrado", f"{score.get('score_mostrado', 0)}/100",
                      help="Score capado a 100. Estable y comparable con CVSS.")
        with c3:
            st.metric("CVSS puro", f"{score.get('score_cvss_puro', 0)}/100",
                      help="Solo el CVSS base sin factores contextuales.")

        st.divider()
        st.subheader("Factores activos")
        for factor in score.get("factores", []):
            col_nombre, col_puntos, col_detalle = st.columns([2, 1, 4])
            with col_nombre:
                st.write(f"**{factor['factor']}**")
            with col_puntos:
                st.write(f"➕ {factor['puntos']} pts")
            with col_detalle:
                st.write(factor['detalle'])

        st.divider()
        st.subheader("Vector de ataque")
        vector = resultado["nvd"].get("vector_ataque", {})
        if vector:
            v1, v2, v3, v4 = st.columns(4)
            with v1:
                av = vector.get("attackVector", "N/A")
                st.metric("Vector", f"{'🔴' if av == 'NETWORK' else '🟡'} {av}")
            with v2:
                ac = vector.get("attackComplexity", "N/A")
                st.metric("Complejidad", f"{'🔴' if ac == 'LOW' else '🟢'} {ac}")
            with v3:
                pr = vector.get("privilegesRequired", "N/A")
                st.metric("Privilegios", f"{'🔴' if pr == 'NONE' else '🟡' if pr == 'LOW' else '🟢'} {pr}")
            with v4:
                ui = vector.get("userInteraction", "N/A")
                st.metric("Interacción", f"{'🔴' if ui == 'NONE' else '🟢'} {ui}")

        st.divider()
        st.subheader("EPSS — Probabilidad de explotación")
        e1, e2 = st.columns(2)
        with e1:
            st.metric("Score EPSS", f"{score.get('epss_score', 0):.1%}")
        with e2:
            percentil = resultado["epss"].get("percentil", 0)
            st.metric("Percentil", f"Top {100 - round(percentil * 100)}%")

    with tab5:
        st.subheader("Datos NVD")
        st.json(resultado["nvd"])
        st.subheader("Datos CISA KEV")
        st.json(resultado["kev"])
        st.subheader("Datos EPSS")
        st.json(resultado["epss"])

elif analizar and not cve_id:
    st.warning("Introduce un CVE antes de analizar.")