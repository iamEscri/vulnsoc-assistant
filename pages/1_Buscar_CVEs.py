import streamlit as st
from modules.ingesta import buscar_cves_por_descripcion

st.set_page_config(
    page_title="VulnSOC Assistant — Buscar CVEs",
    page_icon="🔍",
    layout="wide"
)

# Inicializar session state
if "resultado" not in st.session_state:
    st.session_state.resultado = None
    st.session_state.score = None
    st.session_state.analisis = None
    st.session_state.cve_analizado = None
    st.session_state.cve_desde_busqueda = None

if "resultados_busqueda" not in st.session_state:
    st.session_state.resultados_busqueda = None

st.title("🔍 Buscar CVEs por descripción")
st.caption("Introduce una descripción o término técnico y el sistema buscará CVEs relacionados en el NVD.")
st.divider()

col1, col2 = st.columns([3, 1])
with col1:
    termino = st.text_input(
        "Descripción o término de búsqueda",
        placeholder="Apache Log4j remote code execution",
        help="Puedes buscar por nombre de software, tipo de vulnerabilidad o descripción técnica."
    )
with col2:
    st.write("")
    st.write("")
    buscar = st.button("🔍 Buscar", type="primary", use_container_width=True)

if buscar and termino:
    with st.spinner(f"Buscando CVEs relacionados con '{termino}'..."):
        st.session_state.resultados_busqueda = buscar_cves_por_descripcion(termino)

# Mostrar resultados guardados
if st.session_state.resultados_busqueda:
    resultados = st.session_state.resultados_busqueda

    if "error" in resultados:
        st.error(f"❌ {resultados['error']}")
    elif not resultados["cves"]:
        st.warning("No se encontraron CVEs para ese término.")
    else:
        st.success(f"Se encontraron {resultados['total']} CVEs. Mostrando los {len(resultados['cves'])} más relevantes.")
        st.divider()

        for cve in resultados["cves"]:
            with st.expander(f"**{cve['cve_id']}** — CVSS {cve['cvss_score']} — {cve['fecha_publicacion'][:10]}"):
                st.write(cve["descripcion"])
                cve_url = cve['cve_id']
                st.markdown(
                    f'<a href="/?cve={cve_url}" target="_self" style="'
                    f'background-color:#0f3460; color:white; padding:6px 14px; '
                    f'border-radius:4px; text-decoration:none; font-size:14px;">'
                    f'📊 Analizar {cve_url}</a>',
                    unsafe_allow_html=True
                )

elif buscar and not termino:
    st.warning("Introduce un término de búsqueda.")