import streamlit as st

st.set_page_config(
    page_title="VulnSOC Assistant",
    page_icon="🛡️",
    layout="wide"
)

# ── CSS SIDEBAR ────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* Ocultar footer de Streamlit */
footer { visibility: hidden; }

/* ── BOTONES: estilo más sobrio ── */
[data-testid="stButton"] button {
    border-radius: 6px !important;
    font-weight: 600 !important;
    font-size: 0.82rem !important;
    transition: opacity 0.12s ease !important;
}
[data-testid="stButton"] button:not([kind="primary"]):hover {
    opacity: 0.85 !important;
}

/* ── MÉTRICAS nativas (scoring detallado): quitar borde inferior ── */
[data-testid="stMetric"] {
    background: #161b22 !important;
    border: 1px solid rgba(255,255,255,0.08) !important;
    border-radius: 7px !important;
    padding: 0.75rem 1rem !important;
}

/* ── EXPANDERS: más discretos ── */
[data-testid="stExpander"] summary {
    font-weight: 600 !important;
}

/* ── INFO / WARNING / SUCCESS / ERROR: bordes redondeados ── */
[data-testid="stAlert"] {
    border-radius: 7px !important;
}

/* ── INPUTS: borde coherente ── */
[data-testid="stTextInput"] input,
[data-testid="stTextArea"] textarea {
    border-radius: 6px !important;
    border-color: rgba(255,255,255,0.12) !important;
}

/* ── MULTISELECT chips ── */
[data-testid="stMultiSelect"] span[data-baseweb="tag"] {
    border-radius: 4px !important;
}

/* ── CONTENIDO PRINCIPAL: más ancho ── */
.main .block-container {
    padding-left: 1rem !important;
    padding-right: 1rem !important;
    max-width: 100% !important;
}

/* ── TABS: sin padding lateral extra ── */
[data-testid="stTabContent"] {
    padding: 1.5rem 0 !important;
}

/* ── ENCABEZADOS DENTRO DEL CONTENIDO ── */
[data-testid="stMarkdownContainer"] h1,
[data-testid="stMarkdownContainer"] h2,
[data-testid="stMarkdownContainer"] h3,
[data-testid="stMarkdownContainer"] h4 {
    color: #4da6ff !important;
    margin-top: 1.4rem !important;
    margin-bottom: 0.5rem !important;
}

[data-testid="stMarkdownContainer"] h1 {
    font-size: 1.65rem !important;
    font-weight: 700 !important;
    border-bottom: 1px solid rgba(77,166,255,0.2) !important;
    padding-bottom: 0.4rem !important;
}

[data-testid="stMarkdownContainer"] h2 {
    font-size: 1.35rem !important;
    font-weight: 700 !important;
}

[data-testid="stMarkdownContainer"] h3 {
    font-size: 1.15rem !important;
    font-weight: 600 !important;
}

[data-testid="stMarkdownContainer"] h4 {
    font-size: 1rem !important;
    font-weight: 600 !important;
}

/* ── NEGRITA como título de sección en contenido IA ── */
[data-testid="stMarkdownContainer"] p strong:only-child,
[data-testid="stMarkdownContainer"] p > strong:first-child {
    font-size: 1.05rem !important;
    color: #4da6ff !important;
}

/* ── TEXTO CORRIDO: mejor interlineado sin cambiar color ── */
[data-testid="stMarkdownContainer"] p {
    line-height: 1.75 !important;
}

/* ── LISTAS dentro del contenido ── */
[data-testid="stMarkdownContainer"] ul,
[data-testid="stMarkdownContainer"] ol {
    padding-left: 1.4rem !important;
    line-height: 1.8 !important;
}

/* ── SIDEBAR CONTAINER ── */
[data-testid="stSidebar"] {
    background-color: #0e1117 !important;
    border-right: 1px solid rgba(255,255,255,0.06) !important;
}

/* ── LOGO / CABECERA ── */
[data-testid="stSidebarContent"]::before {
    content: "🛡  VulnSOC Assistant";
    display: block;
    font-size: 0.95rem;
    font-weight: 700;
    color: #4da6ff;
    padding: 1.4rem 1.1rem 1.1rem;
    border-bottom: 1px solid rgba(255,255,255,0.07);
    letter-spacing: 0.2px;
    margin-bottom: 0.1rem;
}

/* ── NAV CONTAINER ── */
[data-testid="stSidebarNav"] {
    padding: 0.3rem 0 0.6rem;
}

/* ── CABECERAS DE SECCIÓN ── */
[data-testid="stSidebarNav"] li > span,
[data-testid="stSidebarNav"] ul > li > span {
    font-size: 0.62rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.09em !important;
    color: rgba(255,255,255,0.28) !important;
    text-transform: uppercase !important;
    padding: 0.85rem 1.1rem 0.25rem !important;
    display: block !important;
    margin-top: 0.2rem !important;
}

/* ── ENLACES DE NAVEGACIÓN ── */
[data-testid="stSidebarNavLink"] {
    border-radius: 6px !important;
    margin: 1px 8px !important;
    padding: 0.48rem 0.9rem !important;
    color: rgba(255,255,255,0.58) !important;
    font-size: 0.875rem !important;
    font-weight: 500 !important;
    text-decoration: none !important;
    border-left: 2.5px solid transparent !important;
    transition: background 0.12s ease, color 0.12s ease, border-left-color 0.12s ease !important;
    display: flex !important;
    align-items: center !important;
    gap: 0.5rem !important;
}

[data-testid="stSidebarNavLink"]:hover {
    background: rgba(77,166,255,0.09) !important;
    color: rgba(255,255,255,0.88) !important;
    border-left-color: rgba(77,166,255,0.5) !important;
}

[data-testid="stSidebarNavLink"][aria-current="page"] {
    background: rgba(77,166,255,0.13) !important;
    color: #4da6ff !important;
    border-left-color: #4da6ff !important;
    font-weight: 600 !important;
}

/* ── ICONO dentro del enlace ── */
[data-testid="stSidebarNavLink"] span:first-child {
    font-size: 1rem !important;
    width: 1.25rem !important;
    text-align: center !important;
    flex-shrink: 0 !important;
}

/* ── SEPARADOR ENTRE SECCIONES ── */
[data-testid="stSidebarNav"] ul > li + li > span {
    border-top: 1px solid rgba(255,255,255,0.05) !important;
    margin-top: 0.4rem !important;
    padding-top: 1rem !important;
}
</style>
""", unsafe_allow_html=True)

# ── NAVEGACIÓN ─────────────────────────────────────────────────────────────
pg = st.navigation(
    {
        "Análisis": [
            st.Page("pages/home.py",                title="Analizar CVE",      icon="🛡️", default=True),
            st.Page("pages/1_Buscar_CVEs.py",       title="Buscar CVEs",       icon="🔍"),
            st.Page("pages/4_Analisis_Multiple.py", title="Análisis Múltiple", icon="📊"),
        ],
        "Gestión": [
            st.Page("pages/2_Historial.py",         title="Historial",         icon="🗂️"),
            st.Page("pages/5_Inventario.py",        title="Inventario",        icon="🏢"),
        ],
        "Info": [
            st.Page("pages/3_Acerca_de.py",         title="Acerca de",         icon="ℹ️"),
        ],
    }
)

pg.run()
