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
        score = calcular_score(resultado["nvd"], resultado["kev"])

    with st.spinner("Generando análisis con IA..."):
        analisis = generar_analisis(resultado["nvd"], resultado["kev"], score)

    # ── FILA DE METRICAS ───────────────────────────────────────────────────
    st.subheader(f"📊 {cve_id}")
    m1, m2, m3, m4 = st.columns(4)

    with m1:
        st.metric("Score del sistema", f"{score['score_mostrado']}/100")
    with m2:
        st.metric("CVSS puro", f"{score['score_cvss_puro']}/100")
    with m3:
        prioridad = score["prioridad"]
        color = {"CRÍTICA": "🔴", "ALTA": "🟠", "MEDIA": "🟡", "BAJA": "🟢"}
        st.metric("Prioridad", f"{color.get(prioridad, '')} {prioridad}")
    with m4:
        kev = resultado["kev"].get("en_kev", False)
        st.metric("En CISA KEV", "✅ Sí" if kev else "❌ No")

    # ── ALERTA KEV ─────────────────────────────────────────────────────────
    if kev:
        st.warning(
            f"⚠️ **Explotación activa confirmada** — "
            f"Añadido a CISA KEV el {resultado['kev'].get('fecha_añadido')} · "
            f"Fecha límite parche: {resultado['kev'].get('fecha_limite')}"
        )

    # ── ALERTA ALUCINACION ─────────────────────────────────────────────────
    if analisis.get("alucinacion_detectada"):
        st.warning("⚠️ Se detectó posible información externa en el análisis. Revisa manualmente.")

    st.divider()

    # ── TABS CON EL ANALISIS ───────────────────────────────────────────────
    tab1, tab2, tab3, tab4 = st.tabs([
        "📋 Resumen ejecutivo",
        "🔬 Análisis técnico",
        "🛠️ Plan de mitigación",
        "📄 Datos brutos"
    ])

    with tab1:
        st.markdown(analisis.get("resumen_ejecutivo", "No disponible"))

    with tab2:
        st.markdown(analisis.get("analisis_tecnico", "No disponible"))

    with tab3:
        st.markdown(analisis.get("plan_mitigacion", "No disponible"))

    with tab4:
        st.subheader("Factores de scoring")
        for factor in score.get("factores", []):
            st.write(f"**{factor['factor']}** — {factor['puntos']} puntos · {factor['detalle']}")

        st.subheader("Datos NVD")
        st.json(resultado["nvd"])

        st.subheader("Datos CISA KEV")
        st.json(resultado["kev"])

elif analizar and not cve_id:
    st.warning("Introduce un CVE antes de analizar.")