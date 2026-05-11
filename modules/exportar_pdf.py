from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER, TA_LEFT
from datetime import datetime
import io
import re

W = A4[0] - 4*cm

DARK   = colors.HexColor("#1a1a2e")
BLUE   = colors.HexColor("#0f3460")
GREEN  = colors.HexColor("#0d7377")
LIGHT  = colors.HexColor("#f5f5f5")
MUTED  = colors.HexColor("#666666")
RED    = colors.HexColor("#c0392b")
ORANGE = colors.HexColor("#e67e22")
AMBER  = colors.HexColor("#7d6608")


def _limpiar_markdown(texto: str) -> list:
    """
    Convierte texto con formato Markdown en lista de parrafos limpios.
    Elimina **, ##, *, URLs sueltas y titulos redundantes.
    """
    lineas = texto.split("\n")
    resultado = []
    titulos_ignorar = {
        "resumen ejecutivo", "análisis técnico", "analisis tecnico",
        "plan de mitigación", "plan de mitigacion", "resumen", "conclusion",
        "conclusión", "urgencia: crítica", "urgencia: alta",
        "urgencia: media", "urgencia: baja", "importante", "nota",
        "pasos ordenados por urgencia", "recomendaciones",
        "decisiones a tomar", "urgencia y prioridad", "decisión a tomar",
        "contexto de explotación", "contexto de explotacion",
        "impacto", "acción requerida", "accion requerida",
        "fecha límite de parche", "fecha limite de parche",
        "vector de ataque", "sistemas afectados"
    }
    for linea in lineas:
        linea = linea.strip()
        if not linea:
            continue
        # Saltar URLs sueltas
        if re.search(r'https?://', linea) and len(linea.split()) <= 3:
            continue
        # Quitar ** negrita
        linea = re.sub(r'\*\*(.*?)\*\*', r'\1', linea)
        # Quitar * cursiva
        linea = re.sub(r'\*(.*?)\*', r'\1', linea)
        # Quitar ## headings
        linea = re.sub(r'^#{1,6}\s+', '', linea)
        # Quitar bullets - y *
        linea = re.sub(r'^[-*]\s+', '', linea)
        # Saltar titulos redundantes
        if linea.lower().strip(":").strip() in titulos_ignorar:
            continue
        # Saltar lineas que contienen solo una URL
        if re.match(r'^https?://\S+$', linea):
            continue
        # Saltar titulos generados por la IA al inicio de secciones
        if linea.lower().startswith("plan de mitigación para") or \
           linea.lower().startswith("plan de mitigacion para") or \
           linea.lower().startswith("plan de mitigación:") or \
           linea.lower().startswith("análisis técnico:") or \
           linea.lower().startswith("resumen ejecutivo:"):
            continue
        if linea:
            resultado.append(linea)
    return resultado


def _prioridad_color(prioridad):
    return {
        "CRÍTICA": RED,
        "ALTA":    ORANGE,
        "MEDIA":   colors.HexColor("#f39c12"),
        "BAJA":    GREEN,
    }.get(prioridad, BLUE)


def generar_pdf(datos_nvd: dict, datos_kev: dict, datos_epss: dict,
                score: dict, analisis: dict) -> bytes:

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )

    # ── ESTILOS ───────────────────────────────────────────────────────────
    TITULO = ParagraphStyle("titulo",
        fontSize=11, textColor=colors.white, leading=16,
        fontName="Helvetica-Bold", alignment=TA_CENTER)

    SECCION = ParagraphStyle("seccion",
        fontSize=11, textColor=colors.white, leading=16,
        fontName="Helvetica-Bold", backColor=BLUE,
        leftIndent=-10, rightIndent=-10, borderPad=7,
        spaceBefore=14, spaceAfter=8)

    SUBSECCION = ParagraphStyle("subseccion",
        fontSize=10, textColor=BLUE, leading=14,
        fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=4)

    CUERPO = ParagraphStyle("cuerpo",
        fontSize=9, textColor=colors.HexColor("#1a1a1a"), leading=15,
        fontName="Helvetica", spaceAfter=5, alignment=TA_JUSTIFY)

    ITEM = ParagraphStyle("item",
        fontSize=9, textColor=colors.HexColor("#1a1a1a"), leading=14,
        fontName="Helvetica", leftIndent=12, spaceAfter=3)

    PIE = ParagraphStyle("pie",
        fontSize=7, textColor=MUTED,
        fontName="Helvetica", alignment=TA_CENTER)

    def sp(h=8):
        return Spacer(1, h)

    story = []
    cve_id    = datos_nvd.get("cve_id", "")
    prioridad = score.get("prioridad", "")
    fecha     = datetime.now().strftime("%d/%m/%Y %H:%M")

    # ── PORTADA ───────────────────────────────────────────────────────────
    portada = Table([[
        Paragraph(f"VulnSOC Assistant  ·  {cve_id}", TITULO)
    ]], colWidths=[W])
    portada.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), DARK),
        ("TOPPADDING",    (0,0), (-1,-1), 28),
        ("BOTTOMPADDING", (0,0), (-1,-1), 28),
        ("LEFTPADDING",   (0,0), (-1,-1), 12),
    ]))
    story.append(portada)
    story.append(sp(4))

    sub_portada = Table([[
        Paragraph(
            f"Informe de análisis de vulnerabilidad  ·  Generado el {fecha}  ·  "
            f"Proveedor IA: {analisis.get('proveedor', 'N/A').upper()}",
            PIE
        )
    ]], colWidths=[W])
    sub_portada.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#0a0a1a")),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(sub_portada)
    story.append(sp(14))

    # ── METRICAS ──────────────────────────────────────────────────────────
    story.append(Paragraph("  Resumen de métricas", SECCION))

    color_prior = _prioridad_color(prioridad)
    metricas = [
        ["Score sistema", "Score interno", "CVSS puro", "Prioridad", "EPSS", "Tipo vuln."],
        [
            f"{score.get('score_mostrado', 0)}/100",
            str(score.get('score_interno', 0)),
            f"{score.get('score_cvss_puro', 0)}/100",
            prioridad,
            f"{score.get('epss_score', 0):.1%}",
            score.get('tipo_vulnerabilidad', 'N/A'),
        ]
    ]
    t_met = Table(metricas, colWidths=[W/6]*6)
    t_met.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0), BLUE),
        ("TEXTCOLOR",     (0,0), (-1,0), colors.white),
        ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTNAME",      (0,1), (-1,1), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 9),
        ("ALIGN",         (0,0), (-1,-1), "CENTER"),
        ("LEADING",       (0,0), (-1,-1), 14),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("BACKGROUND",    (3,1), (3,1), color_prior),
        ("TEXTCOLOR",     (3,1), (3,1), colors.white),
        ("GRID",          (0,0), (-1,-1), 0.4, colors.HexColor("#cccccc")),
    ]))
    story += [t_met, sp(8)]

    # Alerta KEV
    if datos_kev.get("en_kev"):
        alerta = Table([[
            Paragraph(
                f"EXPLOTACIÓN ACTIVA CONFIRMADA  —  Añadido a CISA KEV el "
                f"{datos_kev.get('fecha_añadido')}  ·  "
                f"Fecha límite parche: {datos_kev.get('fecha_limite')}",
                ParagraphStyle("kev", fontSize=8, textColor=colors.white,
                               fontName="Helvetica-Bold", leading=13)
            )
        ]], colWidths=[W])
        alerta.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), AMBER),
            ("TOPPADDING",    (0,0), (-1,-1), 7),
            ("BOTTOMPADDING", (0,0), (-1,-1), 7),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ]))
        story += [alerta, sp(8)]

    # ── FACTORES DE SCORING ───────────────────────────────────────────────
    story.append(Paragraph("  Factores de scoring", SECCION))

    factores = score.get("factores", [])
    if factores:
        rows = [[
            Paragraph("Factor", ParagraphStyle("th", fontSize=9, textColor=colors.white, fontName="Helvetica-Bold")),
            Paragraph("Pts", ParagraphStyle("th2", fontSize=9, textColor=colors.white, fontName="Helvetica-Bold", alignment=TA_CENTER)),
            Paragraph("Detalle", ParagraphStyle("th3", fontSize=9, textColor=colors.white, fontName="Helvetica-Bold")),
        ]]
        for f in factores:
            rows.append([
                Paragraph(f["factor"], ParagraphStyle("td", fontSize=9, fontName="Helvetica-Bold", textColor=BLUE, leading=13)),
                Paragraph(f"+{f['puntos']}", ParagraphStyle("pts", fontSize=9, fontName="Helvetica-Bold", textColor=GREEN, alignment=TA_CENTER, leading=13)),
                Paragraph(f["detalle"], ParagraphStyle("det", fontSize=9, fontName="Helvetica", leading=13)),
            ])
        t_fact = Table(rows, colWidths=[3.5*cm, 1.2*cm, W-4.7*cm])
        t_fact.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), BLUE),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, LIGHT]),
            ("GRID",          (0,0), (-1,-1), 0.3, colors.HexColor("#dddddd")),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 7),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ]))
        story += [t_fact, sp(8)]

    # ── VECTOR DE ATAQUE ──────────────────────────────────────────────────
    story.append(Paragraph("  Vector de ataque", SECCION))

    vector = datos_nvd.get("vector_ataque", {})
    significados = {
        "attackVector": {
            "NETWORK":  "Explotable por red — sin acceso físico",
            "LOCAL":    "Requiere acceso local al sistema",
            "PHYSICAL": "Requiere acceso físico al dispositivo"
        },
        "attackComplexity": {
            "LOW":  "Baja complejidad — fácil de explotar",
            "HIGH": "Alta complejidad — requiere condiciones especiales"
        },
        "privilegesRequired": {
            "NONE": "Sin credenciales — cualquier atacante puede explotar",
            "LOW":  "Cuenta básica suficiente",
            "HIGH": "Requiere cuenta privilegiada"
        },
        "userInteraction": {
            "NONE":     "Sin interacción del usuario",
            "REQUIRED": "Requiere acción de la víctima"
        },
    }
    nombres = {
        "attackVector":       "Vector",
        "attackComplexity":   "Complejidad",
        "privilegesRequired": "Privilegios requeridos",
        "userInteraction":    "Interacción usuario"
    }
    if vector:
        vec_rows = [[
            Paragraph("Campo", ParagraphStyle("th", fontSize=9, textColor=colors.white, fontName="Helvetica-Bold")),
            Paragraph("Valor", ParagraphStyle("th", fontSize=9, textColor=colors.white, fontName="Helvetica-Bold")),
            Paragraph("Significado", ParagraphStyle("th", fontSize=9, textColor=colors.white, fontName="Helvetica-Bold")),
        ]]
        for campo, valor in vector.items():
            sig = significados.get(campo, {}).get(valor, valor)
            vec_rows.append([
                Paragraph(nombres.get(campo, campo), ParagraphStyle("td", fontSize=9, fontName="Helvetica-Bold", textColor=BLUE, leading=13)),
                Paragraph(valor, ParagraphStyle("val", fontSize=9, fontName="Helvetica-Bold", leading=13)),
                Paragraph(sig, ParagraphStyle("sig", fontSize=9, fontName="Helvetica", leading=13)),
            ])
        t_vec = Table(vec_rows, colWidths=[3.5*cm, 2.5*cm, W-6*cm])
        t_vec.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), BLUE),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, LIGHT]),
            ("GRID",          (0,0), (-1,-1), 0.3, colors.HexColor("#dddddd")),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 7),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ]))
        story += [t_vec, sp(8)]

    # ── RESUMEN EJECUTIVO ─────────────────────────────────────────────────
    story.append(Paragraph("  Resumen ejecutivo", SECCION))
    for linea in _limpiar_markdown(analisis.get("resumen_ejecutivo", "")):
        if len(linea) < 45 and not linea.endswith(".") and not linea[0].isdigit():
            story.append(Paragraph(linea, SUBSECCION))
        else:
            story.append(Paragraph(linea, CUERPO))
    story.append(sp(6))

    # ── ANALISIS TECNICO ──────────────────────────────────────────────────
    story.append(Paragraph("  Análisis técnico", SECCION))
    for linea in _limpiar_markdown(analisis.get("analisis_tecnico", "")):
        if len(linea) < 45 and not linea.endswith(".") and not linea[0].isdigit():
            story.append(Paragraph(linea, SUBSECCION))
        else:
            story.append(Paragraph(linea, CUERPO))
    story.append(sp(6))

    # ── PLAN DE MITIGACION ────────────────────────────────────────────────
    story.append(Paragraph("  Plan de mitigación", SECCION))
    for linea in _limpiar_markdown(analisis.get("plan_mitigacion", "")):
        if re.match(r'^\d+\.', linea):
            story.append(Paragraph(f"  {linea}", ITEM))
        elif len(linea) < 45 and not linea.endswith("."):
            story.append(Paragraph(linea, SUBSECCION))
        else:
            story.append(Paragraph(linea, CUERPO))
    story.append(sp(12))

    # ── PIE ───────────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=MUTED,
                             spaceAfter=6, spaceBefore=4))
    story.append(Paragraph(
        f"VulnSOC Assistant  ·  Informe generado el {fecha}  ·  "
        f"Fuentes: NVD (NIST) · CISA KEV · EPSS (FIRST.org)  ·  "
        f"Uso interno — no distribuir sin autorización",
        PIE
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()