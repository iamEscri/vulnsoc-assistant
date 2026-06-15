from datetime import datetime
import streamlit as st
from modules.inventario import (
    normalizar_inventario, exportar_inventario, importar_inventario, CRITICIDADES
)

st.title("🏢 Inventario de activos")
st.caption(
    "Define tus equipos y las tecnologías que corre cada uno. "
    "Se usará para determinar en qué equipos te afecta cada CVE analizado."
)
st.divider()

# ── INICIALIZAR / MIGRAR INVENTARIO ────────────────────────────────────────
# normalizar_inventario migra automaticamente el formato plano antiguo
# (sistemas_operativos / software / personalizado) a un equipo "General".
st.session_state.inventario = normalizar_inventario(
    st.session_state.get("inventario", {})
)

# ── IMPORTAR / EXPORTAR ─────────────────────────────────────────────────────
# El inventario vive en session_state y se pierde al recargar. Exportar a JSON
# permite guardarlo en un archivo e importarlo de nuevo en otra sesion.
with st.expander("💾 Importar / Exportar inventario"):
    col_exp, col_imp = st.columns(2)

    with col_exp:
        st.markdown("**Exportar**")
        st.caption("Descarga tus equipos en un archivo JSON para no perderlos.")
        st.download_button(
            "⬇️ Descargar inventario (JSON)",
            data=exportar_inventario(st.session_state.inventario),
            file_name=f"inventario_vulnsoc_{datetime.now():%Y%m%d}.json",
            mime="application/json",
            use_container_width=True,
            disabled=not st.session_state.inventario.get("equipos"),
        )

    with col_imp:
        st.markdown("**Importar**")
        st.caption("Carga un inventario previamente exportado.")
        archivo = st.file_uploader(
            "Archivo JSON", type=["json"], label_visibility="collapsed"
        )
        modo = st.radio(
            "Al importar:",
            ["Reemplazar inventario actual", "Añadir a los equipos actuales"],
            horizontal=False,
        )
        if archivo is not None and st.button("⬆️ Importar", use_container_width=True):
            try:
                importado = importar_inventario(archivo.getvalue())
                if modo.startswith("Reemplazar"):
                    st.session_state.inventario = importado
                else:
                    st.session_state.inventario["equipos"].extend(importado["equipos"])
                n = len(importado["equipos"])
                st.success(f"✅ Importados {n} equipo(s).")
                st.rerun()
            except ValueError as e:
                st.error(f"❌ No se pudo importar: {e}")

st.divider()

# ── CATALOGO DE TECNOLOGIAS SUGERIDAS ──────────────────────────────────────
TECNOLOGIAS_SUGERIDAS = [
    # Sistemas operativos
    "windows", "windows server", "linux", "ubuntu", "debian", "centos",
    "red hat", "suse", "macos", "android", "ios", "vmware esxi",
    # Software y servicios
    "apache", "log4j", "nginx", "iis", "tomcat", "vsftpd", "proftpd",
    "java", "python", "php", "node", "ruby",
    "spring", "struts", "confluence", "jira",
    "mysql", "postgresql", "mssql", "oracle", "mongodb",
    "exchange", "sharepoint", "office", "outlook",
    "cisco", "fortinet", "palo alto", "checkpoint",
    "vmware", "docker", "kubernetes",
    "openssl", "openssh", "nfs", "samba",
    "wordpress", "drupal", "joomla",
]


def _tecnologias_desde_formulario(seleccionadas, texto_libre):
    """Combina el multiselect y el texto libre en una lista sin duplicados."""
    tecnologias = list(seleccionadas)
    for linea in texto_libre.splitlines():
        linea = linea.strip()
        if linea and linea not in tecnologias:
            tecnologias.append(linea)
    return tecnologias


# ── AÑADIR NUEVO EQUIPO ────────────────────────────────────────────────────
st.subheader("➕ Añadir equipo")

with st.form("nuevo_equipo", clear_on_submit=True):
    c1, c2, c3 = st.columns([3, 2, 2])
    with c1:
        nombre = st.text_input("Nombre del equipo", placeholder="Servidor Web")
    with c2:
        ip = st.text_input("IP / Host (opcional)", placeholder="192.168.1.10")
    with c3:
        criticidad = st.selectbox("Criticidad", CRITICIDADES, format_func=str.title)

    tecs_sel = st.multiselect(
        "Tecnologías del equipo",
        options=TECNOLOGIAS_SUGERIDAS,
        format_func=lambda x: x.title(),
    )
    tecs_libre = st.text_area(
        "Otras tecnologías (una por línea, con versión si quieres)",
        placeholder="apache 2.30\npython 4.0\ncitrix",
        height=90,
    )

    if st.form_submit_button("➕ Añadir equipo", type="primary"):
        tecnologias = _tecnologias_desde_formulario(tecs_sel, tecs_libre)
        if not nombre.strip():
            st.warning("El equipo necesita un nombre.")
        elif not tecnologias:
            st.warning("Añade al menos una tecnología al equipo.")
        else:
            st.session_state.inventario["equipos"].append({
                "nombre": nombre.strip(),
                "ip": ip.strip(),
                "criticidad": criticidad,
                "tecnologias": tecnologias,
            })
            st.success(f"✅ Equipo «{nombre.strip()}» añadido.")
            st.rerun()

st.divider()

# ── EQUIPOS REGISTRADOS ────────────────────────────────────────────────────
equipos = st.session_state.inventario["equipos"]

EMOJI_CRIT = {"alta": "🔴", "media": "🟠", "baja": "🟢"}

if not equipos:
    st.info(
        "No hay equipos registrados todavía. Añade uno arriba "
        "(p. ej. «Servidor Web» con apache, python…)."
    )
else:
    total_tecs = sum(len(e.get("tecnologias", [])) for e in equipos)
    st.subheader("📋 Equipos registrados")
    st.caption(f"{len(equipos)} equipos · {total_tecs} tecnologías en total")

    for idx, equipo in enumerate(equipos):
        crit = equipo.get("criticidad", "media")
        cabecera = f"{EMOJI_CRIT.get(crit, '⚪')} {equipo.get('nombre', 'Sin nombre')}"
        if equipo.get("ip"):
            cabecera += f"  ·  {equipo['ip']}"
        cabecera += f"  ·  {len(equipo.get('tecnologias', []))} tecnologías"

        with st.expander(cabecera):
            ce1, ce2, ce3 = st.columns([3, 2, 2])
            with ce1:
                nuevo_nombre = st.text_input(
                    "Nombre", value=equipo.get("nombre", ""), key=f"nom_{idx}"
                )
            with ce2:
                nueva_ip = st.text_input(
                    "IP / Host", value=equipo.get("ip", ""), key=f"ip_{idx}"
                )
            with ce3:
                nueva_crit = st.selectbox(
                    "Criticidad", CRITICIDADES,
                    index=CRITICIDADES.index(crit) if crit in CRITICIDADES else 1,
                    format_func=str.title, key=f"crit_{idx}",
                )

            nuevas_tecs = st.text_area(
                "Tecnologías (una por línea)",
                value="\n".join(equipo.get("tecnologias", [])),
                height=120, key=f"tec_{idx}",
            )

            b1, b2 = st.columns([1, 1])
            with b1:
                if st.button("💾 Guardar cambios", key=f"save_{idx}",
                             type="primary", use_container_width=True):
                    tecnologias = [
                        l.strip() for l in nuevas_tecs.splitlines() if l.strip()
                    ]
                    if not nuevo_nombre.strip():
                        st.warning("El equipo necesita un nombre.")
                    elif not tecnologias:
                        st.warning("El equipo necesita al menos una tecnología.")
                    else:
                        st.session_state.inventario["equipos"][idx] = {
                            "nombre": nuevo_nombre.strip(),
                            "ip": nueva_ip.strip(),
                            "criticidad": nueva_crit,
                            "tecnologias": tecnologias,
                        }
                        st.success("✅ Cambios guardados.")
                        st.rerun()
            with b2:
                if st.button("🗑️ Eliminar equipo", key=f"del_{idx}",
                             use_container_width=True):
                    st.session_state.inventario["equipos"].pop(idx)
                    st.rerun()
