from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER
from datetime import datetime
import io

W = A4[0] - 4*cm

DARK  = colors.HexColor("#1a1a2e")
BLUE  = colors.HexColor("#0f3460")
GREEN = colors.HexColor("#0d7377")
LIGHT = colors.HexColor("#f5f5f5")
RED   = colors.HexColor("#c0392b")
ORANGE= colors.HexColor("#e67e22")

def _estilos():
    styles = getSampleStyleSheet()
    titulo = ParagraphStyle("titulo",
        fontSize=22, textColor=colors.white, leading=28,
        fontName="Helvetica-Bold", alignment=TA_CENTER)
    subtitulo = ParagraphStyle("subtitulo",
        fontSize=11, textColor=colors.HexColor("#a0c4ff"), leading=16,
        fontName="Helvetica", alignment=TA_CENTER)
    h1 = ParagraphStyle("h1",
        fontSize=14, textColor=colors.white, leading=20,
        fontName="Helvetica-Bold", backColor=BLUE,
        leftIndent=-10, rightIndent=-10, borderPad=6, spaceBefore=14, spaceAfter=6)
    h2 = ParagraphStyle("h2",
        fontSize=11, textColor=BLUE, leading=16,
        fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4)
    body = ParagraphStyle("body",
        fontSize=9, textColor=colors.HexColor("#222222"), leading=14,
        fontName="Helvetica", spaceAfter=5, alignment=TA_JUSTIFY)
    return titulo, subtitulo, h1, h2, body

def _hr():
    return HRFlowable(width="100%", thickness=0.5, color=GREEN, spaceAfter=6, spaceBefore=4)

def _sp(h=8):
    return Spacer(1, h)

def _prioridad_color(prioridad):
    return {
        "CRÍTICA": RED,
        "ALTA": ORANGE,
        "MEDIA": colors.HexColor("#f39c12"),
        "BAJA": GREEN,
    }.get(prioridad, BLUE)


def generar_pdf(datos_nvd: dict, datos_kev: dict, datos_epss: dict,
                score: dict, analisis: dict) -> bytes:
    """
    Genera un PDF completo con el analisis del CVE.
    Devuelve los bytes del PDF para descarga directa desde Streamlit.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )

    TITULO, SUBTITULO, H1, H2, BODY = _estilos()
    story = []

    # ── PORTADA ───────────────────────────────────────────────────────────
    cve_id = datos_nvd.get("cve_id", "")
    prioridad = score.get("prioridad", "")

    portada = Table([[f"VulnSOC Assistant\n{cve_id}"]], colWidths=[W])
    portada.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), DARK),
        ("TEXTCOLOR",     (0,0), (-1,-1), colors.white),
        ("FONTNAME",      (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 20),
        ("LEADING",       (0,0), (-1,-1), 28),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("TOPPADDING",    (0,0), (-1,-1), 40),
        ("BOTTOMPADDING", (0,0), (-1,-1), 40),
    ]))
    story.append(portada)
    story.append(_sp(6))

    fecha = datetime.now().strftime("%d/%m/%Y %H:%M")
    story.append(Paragraph(f"Generado el {fecha} · Proveedor IA: {analisis.get('proveedor', 'N/A')}", SUBTITULO))
    story.append(_sp(16))

    # ── METRICAS PRINCIPALES ──────────────────────────────────────────────
    story.append(Paragraph("  Resumen de métricas", H1))
    story.append(_sp(6))

    color_prior = _prioridad_color(prioridad)
    metricas = [
        ["Score sistema", "Score interno", "CVSS puro", "Prioridad", "EPSS", "Tipo"],
        [
            f"{score.get('score_mostrado', 0)}/100",
            str(score.get('score_interno', 0)),
            f"{score.get('score_cvss_puro', 0)}/100",
            prioridad,
            f"{score.get('epss_score', 0):.1%}",
            score.get('tipo_vulnerabilidad', 'N/A'),
        ]
    ]
    col_w = [W/6] * 6
    t = Table(metricas, colWidths=col_w)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), BLUE),
        ("TEXTCOLOR",     (0,0), (-1,0), colors.white),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTNAME",      (0,1), (-1,1), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("LEADING",       (0,0), (-1,-1), 14),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("BACKGROUND",    (3,1), (3,1), color_prior),
        ("TEXTCOLOR",     (3,1), (3,1), colors.white),
        ("GRID",          (0,0), (-1,-1), 0.4, colors.HexColor("#dddddd")),
    ]))
    story += [t, _sp(8)]

    # KEV
    if datos_kev.get("en_kev"):
        kev_info = Table([[
            f"⚠ EXPLOTACIÓN ACTIVA CONFIRMADA — Añadido a CISA KEV el "
            f"{datos_kev.get('fecha_añadido')} · Fecha límite parche: {datos_kev.get('fecha_limite')}"
        ]], colWidths=[W])
        kev_info.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#7d6608")),
            ("TEXTCOLOR",     (0,0), (-1,-1), colors.white),
            ("FONTNAME",      (0,0), (-1,-1), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 9),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ]))
        story += [kev_info, _sp(8)]

    # ── FACTORES DE SCORING ───────────────────────────────────────────────
    story.append(Paragraph("  Factores de scoring", H1))
    story.append(_sp(6))

    factores = score.get("factores", [])
    if factores:
        rows = [["Factor", "Puntos", "Detalle"]]
        for f in factores:
            rows.append([f["factor"], f"+{f['puntos']}", f["detalle"]])
        col_w2 = [3.5*cm, 1.5*cm, W-5*cm]
        t2 = Table(rows, colWidths=col_w2)
        t2.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), BLUE),
            ("TEXTCOLOR",     (0,0), (-1,0), colors.white),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
            ("FONTNAME",      (1,1), (1,-1), "Helvetica-Bold"),
            ("TEXTCOLOR",     (1,1), (1,-1), GREEN),
            ("FONTSIZE",      (0,0), (-1,-1), 9),
            ("LEADING",       (0,0), (-1,-1), 13),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 7),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, LIGHT]),
            ("GRID",          (0,0), (-1,-1), 0.4, colors.HexColor("#dddddd")),
            ("ALIGN",         (1,0), (1,-1), "CENTER"),
        ]))
        story += [t2, _sp(8)]

    # ── VECTOR DE ATAQUE ──────────────────────────────────────────────────
    story.append(Paragraph("  Vector de ataque", H1))
    story.append(_sp(6))

    vector = datos_nvd.get("vector_ataque", {})
    if vector:
        vec_rows = [["Campo", "Valor", "Significado"]]
        significados = {
            "attackVector":       {"NETWORK": "Explotable por red", "LOCAL": "Requiere acceso local", "PHYSICAL": "Requiere acceso fisico"},
            "attackComplexity":   {"LOW": "Baja — facil de explotar", "HIGH": "Alta — requiere condiciones especiales"},
            "privilegesRequired": {"NONE": "Sin credenciales", "LOW": "Cuenta basica", "HIGH": "Cuenta privilegiada"},
            "userInteraction":    {"NONE": "Sin interaccion del usuario", "REQUIRED": "Requiere accion del usuario"},
        }
        nombres = {
            "attackVector": "Vector", "attackComplexity": "Complejidad",
            "privilegesRequired": "Privilegios", "userInteraction": "Interaccion usuario"
        }
        for campo, valor in vector.items():
            sig = significados.get(campo, {}).get(valor, valor)
            vec_rows.append([nombres.get(campo, campo), valor, sig])

        col_w3 = [3.5*cm, 3*cm, W-6.5*cm]
        t3 = Table(vec_rows, colWidths=col_w3)
        t3.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), BLUE),
            ("TEXTCOLOR",     (0,0), (-1,0), colors.white),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTNAME",      (0,1), (-1,-1), "Helvetica"),
            ("FONTSIZE",      (0,0), (-1,-1), 9),
            ("LEADING",       (0,0), (-1,-1), 13),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 7),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, LIGHT]),
            ("GRID",          (0,0), (-1,-1), 0.4, colors.HexColor("#dddddd")),
        ]))
        story += [t3, _sp(8)]

    # ── RESUMEN EJECUTIVO ─────────────────────────────────────────────────
    story.append(Paragraph("  Resumen ejecutivo", H1))
    story.append(_sp(6))
    for parrafo in analisis.get("resumen_ejecutivo", "").split("\n"):
        if parrafo.strip():
            story.append(Paragraph(parrafo.strip(), BODY))

    story.append(_sp(8))

    # ── ANALISIS TECNICO ──────────────────────────────────────────────────
    story.append(Paragraph("  Análisis técnico", H1))
    story.append(_sp(6))
    for parrafo in analisis.get("analisis_tecnico", "").split("\n"):
        if parrafo.strip():
            story.append(Paragraph(parrafo.strip(), BODY))

    story.append(_sp(8))

    # ── PLAN DE MITIGACION ────────────────────────────────────────────────
    story.append(Paragraph("  Plan de mitigación", H1))
    story.append(_sp(6))
    for parrafo in analisis.get("plan_mitigacion", "").split("\n"):
        if parrafo.strip():
            story.append(Paragraph(parrafo.strip(), BODY))

    # ── PIE ───────────────────────────────────────────────────────────────
    story.append(_sp(16))
    story.append(_hr())
    story.append(Paragraph(
        f"VulnSOC Assistant · Generado el {fecha} · "
        f"Fuentes: NVD (NIST), CISA KEV, EPSS (FIRST.org)",
        ParagraphStyle("pie", fontSize=7, textColor=LIGHT,
                       fontName="Helvetica", alignment=TA_CENTER)
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()