import streamlit as st
from modules.ingesta import buscar_cves_por_descripcion

st.set_page_config(
    page_title="VulnSOC Assistant — Buscar CVEs",
    page_icon="🔍",
    layout="wide"
)

# Si hay un CVE seleccionado redirigir a la pagina principal
if "cve_desde_busqueda" in st.session_state and st.session_state.cve_desde_busqueda:
    st.switch_page("app.py")

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
        resultados = buscar_cves_por_descripcion(termino)

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
                if st.button(f"📊 Analizar {cve['cve_id']}", key=cve["cve_id"]):
                    st.session_state.cve_desde_busqueda = cve["cve_id"]
                    st.rerun()

elif buscar and not termino:
    st.warning("Introduce un término de búsqueda.")