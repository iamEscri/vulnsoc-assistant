import streamlit as st

st.set_page_config(
    page_title="VulnSOC Assistant — Acerca de",
    page_icon="ℹ️",
    layout="wide"
)

st.title("ℹ️ Acerca de VulnSOC Assistant")
st.caption("Sistema inteligente de análisis y priorización de vulnerabilidades para SOC")
st.divider()

# ── QUE ES ────────────────────────────────────────────────────────────────
st.header("¿Qué es VulnSOC Assistant?")
st.markdown("""
VulnSOC Assistant es una herramienta de análisis de vulnerabilidades diseñada para 
analistas de SOC. Automatiza el proceso de análisis de CVEs que normalmente puede 
tardar entre 2 y 4 horas, reduciéndolo a segundos.

Dado un CVE, el sistema:
- Obtiene datos reales de fuentes oficiales (NVD y CISA KEV)
- Calcula una puntuación de prioridad propia que supera las limitaciones del CVSS
- Genera un análisis completo en lenguaje natural usando IA
- Exporta el informe completo en PDF
""")

st.divider()

# ── FUENTES DE DATOS ──────────────────────────────────────────────────────
st.header("Fuentes de datos")

col1, col2, col3 = st.columns(3)

with col1:
    st.subheader("🗄️ NVD (NIST)")
    st.markdown("""
    Base de datos oficial del gobierno de EEUU con todos los CVEs registrados.
    Proporciona descripción técnica, puntuación CVSS, fechas y referencias.
    
    **URL:** services.nvd.nist.gov
    """)

with col2:
    st.subheader("🚨 CISA KEV")
    st.markdown("""
    Catálogo de vulnerabilidades con explotación activa confirmada en el mundo real.
    Si un CVE está aquí, es urgente independientemente de su CVSS.
    
    **URL:** cisa.gov/known-exploited-vulnerabilities
    """)

with col3:
    st.subheader("📊 EPSS (FIRST.org)")
    st.markdown("""
    Exploit Prediction Scoring System. Probabilidad real de que un CVE sea 
    explotado en los próximos 30 días, basada en datos de amenazas actuales.
    
    **URL:** api.first.org/data/v1/epss
    """)

st.divider()

# ── SISTEMA DE SCORING ────────────────────────────────────────────────────
st.header("Sistema de scoring propio")
st.markdown("""
El scoring propio supera las limitaciones del CVSS tradicional añadiendo contexto real.
El CVSS mide la gravedad teórica — el sistema propio mide la urgencia real.
""")

factores = [
    ("CVSS base",               "0 – 100",  "Punto de partida. CVSS × 10 para escalar a 0-100."),
    ("En CISA KEV",             "+30",      "Explotación activa confirmada en el mundo real."),
    ("Vulnerabilidad reciente", "+20",      "Publicada hace menos de 30 días. Ventana de parche abierta."),
    ("EPSS > 0.7",              "+25",      "Alta probabilidad de explotación en los próximos 30 días."),
    ("EPSS > 0.3",              "+10",      "Probabilidad moderada de explotación."),
    ("Tipo RCE",                "+25",      "Ejecución remota de código — control total del sistema."),
    ("Tipo PrivEsc",            "+18",      "Escalada de privilegios."),
    ("Tipo SQLi",               "+15",      "Inyección SQL."),
    ("Tipo XSS",                "+10",      "Cross-site scripting."),
    ("Tipo DoS",                "+8",       "Denegación de servicio."),
    ("Vector NETWORK",          "+15",      "Explotable remotamente sin acceso físico."),
    ("Sin autenticación",       "+10",      "No requiere credenciales para explotar."),
    ("Sin interacción usuario", "+10",      "No requiere que la víctima haga ninguna acción."),
    ("Baja complejidad",        "+10",      "No requiere condiciones especiales para explotar."),
]

col_h1, col_h2, col_h3 = st.columns([3, 1, 4])
with col_h1:
    st.markdown("**Factor**")
with col_h2:
    st.markdown("**Puntos**")
with col_h3:
    st.markdown("**Por qué importa**")

st.divider()

for factor, puntos, razon in factores:
    col1, col2, col3 = st.columns([3, 1, 4])
    with col1:
        st.write(factor)
    with col2:
        st.write(f"`{puntos}`")
    with col3:
        st.write(razon)

st.divider()

# ── DISEÑO DEL SCORE ──────────────────────────────────────────────────────
st.header("Diseño del score: interno vs mostrado")

col1, col2 = st.columns(2)

with col1:
    st.subheader("Score interno")
    st.markdown("""
    Puntuación real acumulada **sin límite superior**.
    Se usa para ordenar CVEs entre sí cuando varios 
    alcanzan el máximo en score mostrado.
    
    Ejemplo: dos CVEs con score mostrado 100 pueden 
    tener score interno 203 y 183 — el primero es más urgente.
    """)

with col2:
    st.subheader("Score mostrado (0-100)")
    st.markdown("""
    Score capado a 100 con `min(score_interno, 100)`.
    Estable y directamente comparable con el estándar CVSS.
    
    Se descartó la normalización proporcional (dividir por 
    un máximo teórico) por ser frágil ante cambios en el modelo.
    """)

st.divider()

# ── PRIORIDADES ───────────────────────────────────────────────────────────
st.header("Niveles de prioridad")

p1, p2, p3, p4 = st.columns(4)
with p1:
    st.error("🔴 CRÍTICA\nScore ≥ 80\nAcción inmediata")
with p2:
    st.warning("🟠 ALTA\nScore 60–79\nParchear en 24-48h")
with p3:
    st.info("🟡 MEDIA\nScore 40–59\nSiguiente ciclo")
with p4:
    st.success("🟢 BAJA\nScore < 40\nMonitorizar")

st.divider()

# ── TECNOLOGIAS ───────────────────────────────────────────────────────────
st.header("Stack tecnológico")

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("""
    **Backend**
    - Python 3.12
    - Módulo de ingesta (NVD + KEV + EPSS)
    - Motor de scoring propio
    - Control de alucinaciones IA
    """)

with col2:
    st.markdown("""
    **IA**
    - Groq (Llama 3.3-70b) — activo
    - Gemini (Google)
    - OpenAI (GPT-4o-mini)
    - Sistema agnóstico al proveedor
    """)

with col3:
    st.markdown("""
    **Infraestructura**
    - Streamlit (interfaz web)
    - Streamlit Community Cloud
    - GitHub (control de versiones)
    - ReportLab (exportación PDF)
    """)

st.divider()
st.caption("VulnSOC Assistant · TFM Máster en Ciberseguridad · iamEscri · 2026")