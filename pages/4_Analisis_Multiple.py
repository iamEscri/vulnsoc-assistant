import time
import pandas as pd
import altair as alt
import streamlit as st
from modules.ingesta import analizar_cve
from modules.scoring import calcular_score, ajustar_por_inventario
from modules.ui import badge_prioridad, badge_kev, chip, color_prioridad, COLORES_PRIORIDAD
from modules.analisis_ia import generar_analisis

st.title("📋 Análisis múltiple de CVEs")
st.caption("Introduce varios CVEs para analizarlos y compararlos ordenados por prioridad.")
st.divider()

# ── INICIALIZAR HISTORIAL SI NO EXISTE ─────────────────────────────────────
# Misma lógica que app.py: si el usuario llega aquí sin haber pasado por
# la página principal, nos aseguramos de que historial existe.
if "historial" not in st.session_state:
    st.session_state.historial = []

# ── ENTRADA DEL USUARIO ────────────────────────────────────────────────────
st.subheader("CVEs a analizar")
texto_cves = st.text_area(
    "Introduce los CVEs separados por comas, espacios o saltos de línea",
    placeholder="CVE-2021-44228\nCVE-2021-34527\nCVE-2023-44487",
    height=120,
    help="Puedes pegar una lista directamente desde un informe o ticket."
)

analizar = st.button("🔍 Analizar todos", type="primary")

# ── PARSEAR CVEs DEL INPUT ─────────────────────────────────────────────────
def parsear_cves(texto):
    """Extrae CVE-IDs válidos del texto libre del usuario."""
    import re
    # Buscamos el patrón CVE-AÑO-NÚMERO directamente, ignorando separadores
    encontrados = re.findall(r"CVE-\d{4}-\d+", texto.upper())
    # Eliminamos duplicados manteniendo el orden
    vistos = set()
    unicos = []
    for cve in encontrados:
        if cve not in vistos:
            vistos.add(cve)
            unicos.append(cve)
    return unicos

# ── ANÁLISIS ───────────────────────────────────────────────────────────────
if analizar and texto_cves.strip():
    cves = parsear_cves(texto_cves)

    if not cves:
        st.warning("No se encontraron CVEs válidos. Formato esperado: CVE-AÑO-NÚMERO (ej. CVE-2021-44228)")
        st.stop()

    st.info(f"🔄 Analizando {len(cves)} CVE(s): {', '.join(cves)}")

    resultados_multiple = []
    errores = []

    # Barra de progreso — se actualiza CVE a CVE
    barra = st.progress(0, text="Iniciando análisis...")

    for i, cve_id in enumerate(cves):
        barra.progress(i / len(cves), text=f"Analizando {cve_id}... ({i+1}/{len(cves)})")

        # Pausa entre CVEs para no saturar NVD ni la API de IA con peticiones consecutivas
        if i > 0:
            time.sleep(3)

        # 1. Ingesta de datos
        resultado = analizar_cve(cve_id)

        if "error" in resultado["nvd"]:
            errores.append((cve_id, resultado["nvd"]["error"]))
            continue

        # 2. Scoring
        score = calcular_score(resultado["nvd"], resultado["kev"], resultado["epss"])
        score = ajustar_por_inventario(
            score,
            st.session_state.get("inventario", {}),
            resultado["nvd"].get("productos_afectados", [])
        )

        # 3. Análisis IA
        analisis = generar_analisis(resultado["nvd"], resultado["kev"], score)

        # 4. Guardar en historial de sesión (igual que app.py)
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
            st.session_state.historial.insert(0, entrada)

        resultados_multiple.append(entrada)

    barra.progress(1.0, text="✅ Análisis completado")

    # Guardar en session_state para persistir si el usuario navega y vuelve
    st.session_state.resultados_multiple = resultados_multiple
    st.session_state.errores_multiple = errores

# ── MOSTRAR RESULTADOS ─────────────────────────────────────────────────────
resultados_multiple = st.session_state.get("resultados_multiple", [])
errores = st.session_state.get("errores_multiple", [])

if resultados_multiple:
    st.divider()

    resultados_ordenados = sorted(resultados_multiple, key=lambda x: x["score_interno"], reverse=True)

    # ── MÉTRICAS RESUMEN ───────────────────────────────────────────────────
    total    = len(resultados_ordenados)
    criticos = sum(1 for e in resultados_ordenados if e["prioridad"] == "CRÍTICA")
    en_kev   = sum(1 for e in resultados_ordenados if e["en_kev"])

    st.markdown(f"""
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:0.65rem;margin-bottom:1.5rem;">
        <div style="background:#161b22;border:1px solid rgba(255,255,255,0.08);border-top:3px solid #4da6ff;border-radius:7px;padding:0.85rem 1rem;">
            <div style="color:rgba(255,255,255,0.4);font-size:0.67rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.35rem;">CVEs analizados</div>
            <div style="color:#e6edf3;font-size:1.5rem;font-weight:700;">{total}</div>
        </div>
        <div style="background:#161b22;border:1px solid rgba(255,255,255,0.08);border-top:3px solid #ff4444;border-radius:7px;padding:0.85rem 1rem;">
            <div style="color:rgba(255,255,255,0.4);font-size:0.67rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.35rem;">Prioridad CRÍTICA</div>
            <div style="color:#ff4444;font-size:1.5rem;font-weight:700;">{criticos}</div>
        </div>
        <div style="background:#161b22;border:1px solid rgba(255,255,255,0.08);border-top:3px solid #ff8c00;border-radius:7px;padding:0.85rem 1rem;">
            <div style="color:rgba(255,255,255,0.4);font-size:0.67rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.35rem;">En CISA KEV</div>
            <div style="color:#ff8c00;font-size:1.5rem;font-weight:700;">{en_kev}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── GRÁFICO DE BARRAS ──────────────────────────────────────────────────
    st.subheader("Comparativa visual")
    df_chart = pd.DataFrame([{
        "CVE":       e["cve_id"],
        "Score":     e["score_interno"],
        "Prioridad": e["prioridad"],
    } for e in resultados_ordenados])

    chart = (
        alt.Chart(df_chart)
        .mark_bar(cornerRadius=3)
        .encode(
            x=alt.X("Score:Q", title="Score interno", axis=alt.Axis(grid=False, labelColor="#8b949e", titleColor="#8b949e")),
            y=alt.Y("CVE:N", sort="-x", title=None, axis=alt.Axis(labelColor="#c9d1d9")),
            color=alt.Color(
                "Prioridad:N",
                scale=alt.Scale(
                    domain=["CRÍTICA", "ALTA", "MEDIA", "BAJA"],
                    range=["#ff4444", "#ff8c00", "#f0c040", "#3dd68c"],
                ),
                legend=None,
            ),
            tooltip=["CVE:N", "Score:Q", "Prioridad:N"],
        )
        .configure_view(strokeOpacity=0)
        .configure_axis(domainColor="#30363d")
        .properties(height=max(160, len(resultados_ordenados) * 38))
    )
    st.altair_chart(chart, use_container_width=True)

    # ── LISTA DE RESULTADOS ────────────────────────────────────────────────
    st.subheader("Detalle por CVE")
    st.markdown("<div style='height:0.25rem'></div>", unsafe_allow_html=True)

    for entrada in resultados_ordenados:
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
                <span style="font-family:monospace;font-weight:700;color:#e6edf3;font-size:0.95rem;min-width:9rem;">{cve_id}</span>
                {badge_prioridad(prioridad)}
                <span style="color:rgba(255,255,255,0.7);font-size:0.875rem;font-weight:600;">{entrada['score_mostrado']}/100</span>
                <span style="color:rgba(255,255,255,0.4);font-size:0.8rem;">interno: {entrada['score_interno']}</span>
                {chip(entrada['tipo'])}
                <span style="color:rgba(255,255,255,0.4);font-size:0.8rem;">EPSS {epss_pct}</span>
                {kev_html}
            </div>
            """, unsafe_allow_html=True)

        with col_btn:
            st.markdown("<div style='height:0.35rem'></div>", unsafe_allow_html=True)
            if st.button("Ver", key=f"multi_{cve_id}", use_container_width=True):
                st.session_state.resultado     = entrada["resultado"]
                st.session_state.score         = entrada["score"]
                st.session_state.analisis      = entrada["analisis"]
                st.session_state.cve_analizado = cve_id
                st.switch_page("pages/home.py")

        st.markdown("<div style='height:0.3rem'></div>", unsafe_allow_html=True)

# ── ERRORES ────────────────────────────────────────────────────────────────
if errores:
    st.subheader("⚠️ CVEs con error")
    for cve_id, msg in errores:
        st.error(f"**{cve_id}**: {msg}")

elif analizar and texto_cves.strip() and not resultados_multiple:
    pass  # Los errores ya se muestran arriba; si no hay nada es porque todos fallaron

elif not analizar and not resultados_multiple:
    st.info("Introduce uno o varios CVEs arriba y pulsa **Analizar todos**.")
