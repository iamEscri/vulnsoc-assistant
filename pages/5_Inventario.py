import streamlit as st

st.set_page_config(
    page_title="Inventario — VulnSOC Assistant",
    page_icon="🏢",
    layout="wide"
)

st.title("🏢 Inventario de activos")
st.caption("Define el perfil tecnológico de tu empresa. Se usará para determinar si los CVEs analizados te afectan.")
st.divider()

# ── INICIALIZAR INVENTARIO EN SESSION_STATE ────────────────────────────────
if "inventario" not in st.session_state:
    st.session_state.inventario = {
        "sistemas_operativos": [],
        "software": [],
        "personalizado": ""
    }

# ── SISTEMAS OPERATIVOS ────────────────────────────────────────────────────
st.subheader("🖥️ Sistemas operativos")

so_opciones = [
    "windows", "windows server", "linux", "ubuntu", "debian", "centos",
    "red hat", "suse", "macos", "android", "ios", "vmware esxi"
]

so_seleccionados = st.multiselect(
    "Selecciona los sistemas operativos presentes en tu red",
    options=so_opciones,
    default=st.session_state.inventario["sistemas_operativos"],
    format_func=lambda x: x.title()
)

st.divider()

# ── SOFTWARE Y TECNOLOGÍAS ────────────────────────────────────────────────
st.subheader("📦 Software y tecnologías")

sw_opciones = [
    "apache", "log4j", "nginx", "iis", "tomcat",
    "java", "python", "php", "node", "ruby",
    "spring", "struts", "confluence", "jira",
    "mysql", "postgresql", "mssql", "oracle", "mongodb",
    "exchange", "sharepoint", "office", "outlook",
    "cisco", "fortinet", "palo alto", "checkpoint",
    "vmware", "docker", "kubernetes",
    "openssl", "openssh",
    "wordpress", "drupal", "joomla"
]

sw_seleccionados = st.multiselect(
    "Selecciona el software presente en tu entorno",
    options=sw_opciones,
    default=st.session_state.inventario["software"],
    format_func=lambda x: x.title()
)

st.divider()

# ── CAMPO LIBRE ────────────────────────────────────────────────────────────
st.subheader("✏️ Tecnologías adicionales")

personalizado = st.text_area(
    "Añade tecnologías que no aparecen en la lista (una por línea)",
    value=st.session_state.inventario["personalizado"],
    placeholder="citrix\nf5\nsonicwall\nzabbix",
    height=120
)

st.divider()

# ── GUARDAR ────────────────────────────────────────────────────────────────
if st.button("💾 Guardar inventario", type="primary"):
    st.session_state.inventario = {
        "sistemas_operativos": so_seleccionados,
        "software": sw_seleccionados,
        "personalizado": personalizado
    }
    st.success("✅ Inventario guardado. Se aplicará automáticamente en el análisis de CVEs.")

# ── RESUMEN DEL INVENTARIO ACTUAL ──────────────────────────────────────────
inventario = st.session_state.inventario
total_so = len(inventario["sistemas_operativos"])
total_sw = len(inventario["software"])
lineas_custom = [l.strip() for l in inventario["personalizado"].splitlines() if l.strip()]
total_custom = len(lineas_custom)
total = total_so + total_sw + total_custom

if total > 0:
    st.divider()
    st.subheader("📋 Inventario actual")
    st.caption(f"{total} tecnologías registradas")

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("**Sistemas operativos**")
        for so in inventario["sistemas_operativos"]:
            st.write(f"• {so.title()}")
    with c2:
        st.markdown("**Software**")
        for sw in inventario["software"]:
            st.write(f"• {sw.title()}")
    with c3:
        st.markdown("**Adicionales**")
        for item in lineas_custom:
            st.write(f"• {item.title()}")
else:
    st.info("No hay inventario definido todavía. Selecciona tecnologías arriba y guarda.")
