import streamlit as st

st.set_page_config(
    page_title="Historial — VulnSOC Assistant",
    page_icon="🗂️",
    layout="wide"
)

st.title("🗂️ Historial de sesión")
st.caption("CVEs analizados durante esta sesión. El historial se reinicia al cerrar el navegador.")
st.divider()

# ── COMPROBAR SI HAY HISTORIAL ─────────────────────────────────────────────
# session_state es compartido entre páginas dentro de la misma sesión de
# Streamlit, por eso podemos leer "historial" que app.py ha ido rellenando.
historial = st.session_state.get("historial", [])

if not historial:
    st.info("⏳ Todavía no has analizado ningún CVE en esta sesión. Ve a la página principal e introduce un CVE.")
    st.stop()

# ── RESUMEN NUMÉRICO ───────────────────────────────────────────────────────
total    = len(historial)
criticos = sum(1 for e in historial if e["prioridad"] == "CRÍTICA")
en_kev   = sum(1 for e in historial if e["en_kev"])

c1, c2, c3 = st.columns(3)
with c1:
    st.metric("CVEs analizados", total)
with c2:
    st.metric("Prioridad CRÍTICA", criticos)
with c3:
    st.metric("En CISA KEV", en_kev)

st.divider()

# ── TABLA DE CVEs ──────────────────────────────────────────────────────────
COLOR_PRIORIDAD = {
    "CRÍTICA": "🔴",
    "ALTA":    "🟠",
    "MEDIA":   "🟡",
    "BAJA":    "🟢",
}

st.subheader("CVEs de esta sesión")

for entrada in historial:
    cve_id    = entrada["cve_id"]
    prioridad = entrada["prioridad"]
    icono     = COLOR_PRIORIDAD.get(prioridad, "⚪")
    kev_badge = "⚠️ KEV" if entrada["en_kev"] else ""
    epss_pct  = f"{entrada['epss_score']:.1%}"

    col_cve, col_score, col_prio, col_tipo, col_epss, col_kev, col_btn = st.columns(
        [2, 1.2, 1.5, 1.5, 1, 1, 1.5]
    )

    with col_cve:
        st.write(f"**{cve_id}**")
    with col_score:
        st.write(f"{entrada['score_mostrado']}/100")
    with col_prio:
        st.write(f"{icono} {prioridad}")
    with col_tipo:
        st.write(entrada["tipo"])
    with col_epss:
        st.write(epss_pct)
    with col_kev:
        st.write(kev_badge)
    with col_btn:
        # Al pulsar, cargamos ese análisis en session_state y navegamos a app.py
        if st.button("📂 Cargar", key=f"cargar_{cve_id}"):
            st.session_state.resultado     = entrada["resultado"]
            st.session_state.score         = entrada["score"]
            st.session_state.analisis      = entrada["analisis"]
            st.session_state.cve_analizado = cve_id
            st.switch_page("app.py")

    st.divider()

# ── BOTÓN LIMPIAR HISTORIAL ────────────────────────────────────────────────
st.write("")
if st.button("🗑️ Limpiar historial", type="secondary"):
    st.session_state.historial = []
    st.rerun()
