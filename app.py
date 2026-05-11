import streamlit as st
from modules.ingesta import analizar_cve
from modules.scoring import calcular_score
from modules.analisis_ia import generar_analisis

# ── CONFIGURACION DE LA PAGINA ─────────────────────────────────────────────
st.set_page_config(
    page_title="VulnSOC Assistant",
    page_icon="🛡️",
    layout="wide"
)

# ── CABECERA ───────────────────────────────────────────────────────────────
st.title("🛡️ VulnSOC Assistant")
st.caption("Sistema inteligente de análisis y priorización de vulnerabilidades para SOC")
st.divider()

# ── ENTRADA DEL USUARIO ────────────────────────────────────────────────────
col1, col2 = st.columns([3, 1])

with col1:
    cve_id = st.text_input(
        "Introduce el CVE a analizar",
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

    # ── FILA DE METRICAS ───────────────────────────────────────────────────
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
        prioridad = score["prioridad"]
        color = {"CRÍTICA": "🔴", "ALTA": "🟠", "MEDIA": "🟡", "BAJA": "🟢"}
        st.metric("Prioridad", f"{color.get(prioridad, '')} {prioridad}")
    with m5:
        kev = resultado["kev"].get("en_kev", False)
        st.metric("En CISA KEV", "✅ Sí" if kev else "❌ No")
    with m6:
        epss = score.get("epss_score", 0)
        st.metric("EPSS", f"{epss:.1%}")
    with m7:
        st.metric("Tipo", score.get("tipo_vulnerabilidad", "Desconocido"))

    # ── ALERTAS ────────────────────────────────────────────────────────────
    if kev:
        st.warning(
            f"⚠️ **Explotación activa confirmada** — "
            f"Añadido a CISA KEV el {resultado['kev'].get('fecha_añadido')} · "
            f"Fecha límite parche: {resultado['kev'].get('fecha_limite')}"
        )

    if analisis.get("alucinacion_detectada"):
        st.warning("⚠️ Se detectó posible información externa en el análisis. Revisa manualmente.")

    st.divider()

    # ── TABS ───────────────────────────────────────────────────────────────
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
        # Scores comparativos
        st.subheader("Puntuaciones")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric(
                "Score interno",
                score.get("score_interno", 0),
                help="Puntuación real acumulada sin límite. Se usa para ordenar CVEs entre sí."
            )
        with c2:
            st.metric(
                "Score mostrado",
                f"{score.get('score_mostrado', 0)}/100",
                help="Score capado a 100. Estable y comparable con el estándar CVSS."
            )
        with c3:
            st.metric(
                "CVSS puro",
                f"{score.get('score_cvss_puro', 0)}/100",
                help="Solo el CVSS base sin ningún factor contextual. Para comparar con el sistema propio."
            )

        st.divider()

        # Factores activos
        st.subheader("Factores activos")
        factores = score.get("factores", [])
        if factores:
            for factor in factores:
                col_nombre, col_puntos, col_detalle = st.columns([2, 1, 4])
                with col_nombre:
                    st.write(f"**{factor['factor']}**")
                with col_puntos:
                    st.write(f"➕ {factor['puntos']} pts")
                with col_detalle:
                    st.write(factor['detalle'])
        else:
            st.write("No hay factores registrados.")

        st.divider()

        # Vector de ataque
        st.subheader("Vector de ataque")
        vector = resultado["nvd"].get("vector_ataque", {})
        if vector:
            v1, v2, v3, v4 = st.columns(4)
            with v1:
                av = vector.get("attackVector", "N/A")
                color_av = "🔴" if av == "NETWORK" else "🟡" if av == "ADJACENT" else "🟢"
                st.metric("Vector", f"{color_av} {av}")
            with v2:
                ac = vector.get("attackComplexity", "N/A")
                color_ac = "🔴" if ac == "LOW" else "🟢"
                st.metric("Complejidad", f"{color_ac} {ac}")
            with v3:
                pr = vector.get("privilegesRequired", "N/A")
                color_pr = "🔴" if pr == "NONE" else "🟡" if pr == "LOW" else "🟢"
                st.metric("Privilegios", f"{color_pr} {pr}")
            with v4:
                ui = vector.get("userInteraction", "N/A")
                color_ui = "🔴" if ui == "NONE" else "🟢"
                st.metric("Interacción", f"{color_ui} {ui}")
        else:
            st.write("Vector de ataque no disponible para este CVE.")

        st.divider()

        # EPSS detalle
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