import streamlit as st
from modules.ingesta import buscar_cves_por_descripcion
from modules.ui import badge_cvss, color_cvss

# Inicializar session state
if "resultado" not in st.session_state:
    st.session_state.resultado = None
    st.session_state.score = None
    st.session_state.analisis = None
    st.session_state.cve_analizado = None
    st.session_state.cve_desde_busqueda = None

if "resultados_busqueda" not in st.session_state:
    st.session_state.resultados_busqueda = None

st.title("🔍 Buscar CVEs")
st.caption("Busca por nombre de software, tipo de vulnerabilidad, descripción técnica o cualquier término relacionado.")
st.divider()

col1, col2 = st.columns([3, 1])
with col1:
    termino = st.text_input(
        "Término de búsqueda",
        placeholder="Apache Log4j remote code execution · Windows privilege escalation · OpenSSL buffer overflow",
        help="Ejemplos: 'apache struts rce', 'windows kernel privilege escalation', 'sql injection wordpress', 'openssl heartbleed'"
    )
with col2:
    st.write("")
    st.write("")
    buscar = st.button("🔍 Buscar", type="primary", use_container_width=True)

if buscar and termino:
    with st.spinner(f"Buscando CVEs relacionados con '{termino}'..."):
        st.session_state.resultados_busqueda = buscar_cves_por_descripcion(termino)

# ── RESULTADOS ─────────────────────────────────────────────────────────────
if st.session_state.resultados_busqueda:
    resultados = st.session_state.resultados_busqueda

    if "error" in resultados:
        st.error(f"❌ {resultados['error']}")
    elif not resultados["cves"]:
        st.warning("No se encontraron CVEs para ese término. Prueba con palabras más genéricas.")
    else:
        total = resultados['total']
        mostrados = len(resultados['cves'])
        st.markdown(
            f'<p style="color:rgba(255,255,255,0.45);font-size:0.85rem;margin-bottom:1rem;">'
            f'<b style="color:#3dd68c;">{mostrados}</b> resultados mostrados de {total} encontrados</p>',
            unsafe_allow_html=True
        )

        for cve in resultados["cves"]:
            cvss = cve.get("cvss_score") or 0
            fecha = (cve.get("fecha_publicacion") or "")[:10]
            descripcion = cve.get("descripcion", "")
            desc_corta = descripcion[:300] + ("…" if len(descripcion) > 300 else "")
            c = color_cvss(cvss)

            st.markdown(f"""
            <div style="background:#161b22;border:1px solid rgba(255,255,255,0.08);
                        border-left:3px solid {c};border-radius:8px;
                        padding:1.1rem 1.3rem;margin-bottom:0.6rem;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.65rem;">
                    <span style="font-family:monospace;font-size:1rem;font-weight:700;color:#e6edf3;">
                        {cve['cve_id']}
                    </span>
                    <div style="display:flex;gap:0.5rem;align-items:center;">
                        {badge_cvss(cvss)}
                        <span style="color:rgba(255,255,255,0.3);font-size:0.78rem;">{fecha}</span>
                    </div>
                </div>
                <p style="color:rgba(255,255,255,0.6);font-size:0.875rem;line-height:1.65;margin:0 0 0.9rem;">
                    {desc_corta}
                </p>
                <a href="/?cve={cve['cve_id']}" target="_self"
                   style="background:#4da6ff18;color:#4da6ff;border:1px solid #4da6ff50;
                          border-radius:5px;padding:5px 14px;font-size:0.8rem;
                          font-weight:600;text-decoration:none;">
                    📊 Analizar {cve['cve_id']}
                </a>
            </div>
            """, unsafe_allow_html=True)

elif buscar and not termino:
    st.warning("Introduce un término de búsqueda.")
