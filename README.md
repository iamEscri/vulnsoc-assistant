<div align="center">

<img src="assets/logo.png" alt="VulnSOC Assistant" width="180"/>

# VulnSOC Assistant

**Sistema inteligente de análisis y priorización de vulnerabilidades para SOC basado en IA Generativa**

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-App-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Demo](https://img.shields.io/badge/Demo-Live-success?logo=streamlit)](https://vulnsoc-assistant.streamlit.app)

[🚀 Demo en vivo](https://vulnsoc-assistant.streamlit.app) · [📋 Características](#-características) · [⚙️ Instalación](#%EF%B8%8F-instalación) · [🧮 Motor de scoring](#-motor-de-scoring-contribución-principal)

</div>

---

## 📌 ¿Qué es VulnSOC Assistant?

En un SOC, analizar una vulnerabilidad de forma manual puede llevar **entre 2 y 4 horas**: consultar el NVD, comprobar si está siendo explotada activamente, interpretar los datos técnicos, decidir la urgencia y redactar un informe.

**VulnSOC Assistant reduce ese proceso a segundos.** El analista introduce un CVE y obtiene:

- ✅ Datos reales y actualizados de **NVD**, **CISA KEV** y **EPSS**
- ✅ Una **puntuación de prioridad contextualizada** calculada con un motor de scoring propio
- ✅ Un **análisis completo generado por IA** (resumen ejecutivo, análisis técnico y plan de mitigación)
- ✅ Un **informe PDF** exportable y listo para compartir

> 🔑 **Principio de diseño:** la IA no inventa datos. Interpreta datos reales obtenidos de fuentes oficiales, lo que elimina el riesgo de alucinaciones en la información técnica.

---

## ✨ Características

| Funcionalidad | Descripción |
|---|---|
| 🔍 **Análisis de CVE** | Introduce un identificador CVE y obtén un análisis completo con datos en tiempo real |
| 🧮 **Scoring contextualizado** | Priorización propia que supera las limitaciones del CVSS puro |
| 🤖 **Análisis con IA** | Resumen ejecutivo, análisis técnico y mitigación generados por LLM con verificación estructural anti-alucinaciones |
| 🔎 **Búsqueda inversa** | Encuentra CVEs a partir de una descripción en lenguaje natural |
| 📊 **Análisis múltiple** | Analiza lotes de CVEs y compáralos en una tabla ordenada por prioridad real |
| 🖥️ **Inventario de activos** | Define tu entorno (SO y software) y detecta automáticamente si un CVE te afecta mediante datos CPE |
| 📜 **Historial de sesión** | Consulta, exporta e importa los análisis realizados (JSON) |
| 📄 **Exportación PDF** | Genera informes profesionales con ReportLab |
| 🔌 **Multi-proveedor de IA** | Compatible con Groq (Llama 3.3 70B), Google Gemini y OpenAI mediante una variable de entorno |

---

## 🧮 Motor de scoring (contribución principal)

El **CVSS mide gravedad teórica, no urgencia real**. Una vulnerabilidad con CVSS 9.8 sin explotación conocida puede ser menos urgente que una de 7.5 que ya está siendo explotada activamente.

El motor de scoring de VulnSOC Assistant parte del CVSS y lo **contextualiza con 7 factores**:

| Factor | Ajuste | Justificación |
|---|---|---|
| CVSS base (× 10) | 0 – 100 | Punto de partida estándar |
| Presente en **CISA KEV** | +30 | Explotación activa confirmada en el mundo real |
| Publicada hace **< 30 días** | +20 | Menor tiempo de parcheo en las organizaciones |
| **EPSS** > 0.7 / > 0.3 | +25 / +10 | Probabilidad real de explotación en 30 días |
| **Tipo de vulnerabilidad** (CWE) | +8 a +25 | RCE > PrivEsc > SQLi > PathTrav > XSS > DoS |
| **Vector de red** | +15 | Explotable remotamente |
| **Sin autenticación / sin interacción / baja complejidad** | +10 c/u | Reduce la barrera de entrada del atacante |

**Diseño de doble puntuación:**

- `score_interno` — puntuación real sin límite, usada para **ordenar** vulnerabilidades entre sí
- `score_mostrado` — capada a 100, **estable y comparable** con la escala CVSS

> 📊 Ejemplo real: **PrintNightmare (CVE-2021-34527)** tiene un CVSS de 8.8 (alta, no crítica). Al estar en CISA KEV, tener EPSS elevado y ser explotable en red, el scoring contextualizado la eleva a prioridad **crítica**, que es como la trató la industria en la práctica.

---

## 🏗️ Arquitectura

El sistema está organizado en módulos independientes que trabajan en secuencia:

```
                ┌─────────────────────────────────────────┐
  CVE-XXXX ───▶ │  1. INGESTA        modules/ingesta.py    │
                │     NVD · CISA KEV · EPSS                │
                └──────────────────┬──────────────────────┘
                                   ▼
                ┌─────────────────────────────────────────┐
                │  2. SCORING        modules/scoring.py    │
                │     Motor propio de 7 factores           │
                └──────────────────┬──────────────────────┘
                                   ▼
                ┌─────────────────────────────────────────┐
                │  3. ANÁLISIS IA    modules/analisis_ia.py│
                │     Groq / Gemini / OpenAI · temp 0.1    │
                └──────────────────┬──────────────────────┘
                                   ▼
                ┌─────────────────────────────────────────┐
                │  4. OUTPUT         app.py + exportar_pdf │
                │     Dashboard Streamlit · Informe PDF    │
                └─────────────────────────────────────────┘
```

### Fuentes de datos

| Fuente | Qué aporta |
|---|---|
| [NVD](https://nvd.nist.gov/) | Datos oficiales del CVE: descripción, CVSS, CWE, CPE, referencias |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Catálogo de vulnerabilidades con explotación activa confirmada |
| [EPSS](https://www.first.org/epss/) | Probabilidad estadística de explotación en los próximos 30 días |

---

## ⚙️ Instalación

### Requisitos

- Python 3.12+
- Una API key de al menos un proveedor de IA ([Groq](https://console.groq.com/) es gratuito y es el proveedor recomendado)

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/iamEscri/vulnsoc-assistant.git
cd vulnsoc-assistant

# 2. Crear y activar un entorno virtual
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Configurar variables de entorno
cp .env.example .env
# Edita .env y añade tu API key
```

### Configuración (`.env`)

```env
IA_PROVIDER=groq          # groq | gemini | openai
GROQ_API_KEY=tu_api_key
GEMINI_API_KEY=
OPENAI_API_KEY=
```

### Ejecución

```bash
streamlit run app.py
```

La aplicación estará disponible en `http://localhost:8501`.

> 💡 También puedes analizar un CVE directamente por URL: `http://localhost:8501/?cve=CVE-2021-34527`

---

## 📁 Estructura del proyecto

```
vulnsoc-assistant/
├── app.py                      # Página principal: análisis de CVE, métricas y exportación PDF
├── main.py                     # Ejemplo de uso de los módulos por línea de comandos
├── modules/
│   ├── ingesta.py              # Conexión con las APIs de NVD, CISA KEV y EPSS
│   ├── scoring.py              # Motor de priorización contextualizada (7 factores)
│   ├── analisis_ia.py          # Análisis con IA multi-proveedor y detección de alucinaciones
│   └── exportar_pdf.py         # Generación de informes PDF con ReportLab
├── pages/
│   ├── 1_Buscar_CVEs.py        # Búsqueda inversa de CVEs por descripción
│   ├── 2_Historial.py          # Historial de sesión con exportación/importación
│   ├── 3_Acerca_de.py          # Documentación del sistema
│   ├── 4_Analisis_Multiple.py  # Análisis por lotes con tabla comparativa
│   └── 5_Inventario.py         # Inventario de activos y correlación con CPE
├── requirements.txt
├── .env.example
└── LICENSE
```

---

## 🎓 Contexto académico

Este proyecto se ha desarrollado como **Trabajo Fin de Máster en Ciberseguridad**, dentro del área *IA Generativa en la gestión de vulnerabilidades*.

Su aportación académica central es demostrar, con CVEs reales, que un **scoring contextualizado** (explotación activa, probabilidad de explotación, tipo de vulnerabilidad y vector de ataque) **reordena la priorización** respecto al CVSS puro, acercándola a la urgencia operativa real de un SOC.

---

## 📄 Licencia

Este proyecto está bajo la licencia [MIT](LICENSE).

---

<div align="center">

Desarrollado por **[iamEscri](https://github.com/iamEscri)**

⭐ Si este proyecto te resulta útil, considera darle una estrella

</div>
