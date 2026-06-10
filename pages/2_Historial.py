import json
from datetime import datetime

import streamlit as st
from modules.ui import badge_prioridad, badge_kev, chip, color_prioridad

st.title("🗂️ Historial de sesión")
st.caption("CVEs analizados durante esta sesión. El historial se reinicia al cerrar el navegador, pero puedes exportarlo a un archivo y volver a importarlo más adelante.")
st.divider()

# ── INICIALIZAR HISTORIAL ──────────────────────────────────────────────────
# Si el usuario abre esta página antes de pasar por app.py, la clave podría no
# existir todavía. La creamos vacía para poder importar sobre ella sin errores.
if "historial" not in st.session_state:
    st.session_state.historial = []

historial = st.session_state.historial

# ── EXPORTAR / IMPORTAR ────────────────────────────────────────────────────
# Esta sección va ANTES del aviso de "historial vacío" a propósito: el caso
# principal de importar es precisamente una sesión nueva (vacía) en la que
# quieres recuperar el historial de otro día.
with st.expander("💾 Exportar / Importar historial", expanded=not historial):

    # --- EXPORTAR ---
    # Cada entrada del historial ya es serializable a JSON (textos, números y
    # diccionarios de las APIs), así que basta con volcarla con json.dumps.
    # - ensure_ascii=False: conserva tildes y la "Í" de CRÍTICA legibles.
    # - default=str: red de seguridad; si algún valor no fuese serializable
    #   (p. ej. una fecha), se convierte a texto en vez de romper la descarga.
    if historial:
        json_historial = json.dumps(
            historial, ensure_ascii=False, indent=2, default=str
        )
        st.download_button(
            label="⬇️ Exportar historial (JSON)",
            data=json_historial,
            file_name=f"historial_vulnsoc_{datetime.now():%Y%m%d}.json",
            mime="application/json",
            help="Descarga todos los CVEs de esta sesión en un archivo.",
        )
    else:
        st.write("ℹ️ No hay nada que exportar todavía.")

    st.divider()

    # --- IMPORTAR ---
    archivo = st.file_uploader(
        "Importar un historial guardado (.json)",
        type=["json"],
        help="Sube un archivo exportado anteriormente para recuperar esos CVEs.",
    )

    if archivo is not None and st.button("📥 Importar", type="primary"):
        try:
            datos = json.loads(archivo.read())

            # Validación mínima: debe ser una lista de entradas (diccionarios).
            if not isinstance(datos, list):
                st.error("❌ El archivo no tiene el formato esperado (se esperaba una lista de CVEs).")
            else:
                # Fusión con deduplicado por cve_id. En caso de empate
                # (mismo CVE en la sesión y en el archivo) conservamos el de
                # la sesión actual, que es el más reciente: solo añadimos los
                # CVEs del archivo que aún no estén en el historial.
                ids_actuales = {e["cve_id"] for e in historial}
                nuevos = [
                    e for e in datos
                    if isinstance(e, dict) and e.get("cve_id") and e["cve_id"] not in ids_actuales
                ]
                st.session_state.historial.extend(nuevos)

                if nuevos:
                    st.success(f"✅ Importados {len(nuevos)} CVE(s). Ya estaban en la sesión: {len(datos) - len(nuevos)}.")
                else:
                    st.info("Todos los CVEs del archivo ya estaban en el historial actual.")

                st.rerun()

        except json.JSONDecodeError:
            st.error("❌ El archivo no es un JSON válido.")

# Si tras esto el historial sigue vacío, no hay tabla que mostrar.
if not historial:
    st.info("⏳ Todavía no has analizado ningún CVE en esta sesión. Ve a la página principal e introduce un CVE, o importa un historial guardado arriba.")
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
st.subheader("CVEs de esta sesión")
st.markdown("<div style='height:0.25rem'></div>", unsafe_allow_html=True)

for entrada in historial:
    cve_id    = entrada["cve_id"]
    prioridad = entrada["prioridad"]
    c         = color_prioridad(prioridad)
    kev_html  = badge_kev() if entrada["en_kev"] else ""
    epss_pct  = f"{entrada['epss_score']:.1%}"

    col_info, col_btn = st.columns([6, 1])

    with col_info:
        st.markdown(f"""
        <div style="background:#161b22;border:1px solid rgba(255,255,255,0.08);
                    border-left:3px solid {c};border-radius:7px;
                    padding:0.75rem 1.1rem;display:flex;align-items:center;
                    gap:1.2rem;flex-wrap:wrap;">
            <span style="font-family:monospace;font-weight:700;color:#e6edf3;
                         font-size:0.95rem;min-width:9rem;">{cve_id}</span>
            {badge_prioridad(prioridad)}
            <span style="color:rgba(255,255,255,0.7);font-size:0.875rem;font-weight:600;">
                {entrada['score_mostrado']}/100
            </span>
            {chip(entrada['tipo'])}
            <span style="color:rgba(255,255,255,0.4);font-size:0.8rem;">EPSS {epss_pct}</span>
            {kev_html}
        </div>
        """, unsafe_allow_html=True)

    with col_btn:
        st.markdown("<div style='height:0.35rem'></div>", unsafe_allow_html=True)
        if st.button("Cargar", key=f"cargar_{cve_id}", use_container_width=True):
            st.session_state.resultado     = entrada["resultado"]
            st.session_state.score         = entrada["score"]
            st.session_state.analisis      = entrada["analisis"]
            st.session_state.cve_analizado = cve_id
            st.switch_page("pages/home.py")

    st.markdown("<div style='height:0.3rem'></div>", unsafe_allow_html=True)

# ── BOTÓN LIMPIAR HISTORIAL ────────────────────────────────────────────────
st.write("")
if st.button("🗑️ Limpiar historial", type="secondary"):
    st.session_state.historial = []
    st.rerun()