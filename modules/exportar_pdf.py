from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from datetime import datetime
import io, re

# ── Paleta ───────────────────────────────────────────────────────────────────
NAVY   = colors.HexColor("#0f2744")
SURF   = colors.HexColor("#f8fafc")
SURF2  = colors.HexColor("#f1f5f9")
BORDER = colors.HexColor("#e2e8f0")
TXT    = colors.HexColor("#0f172a")
TMID   = colors.HexColor("#334155")
MUTED  = colors.HexColor("#64748b")
WHITE  = colors.white

P_HEX = {
    "CRITICA":  "#dc2626",
    "CRÍTICA":  "#dc2626",
    "ALTA":     "#ea580c",
    "MEDIA":    "#d97706",
    "BAJA":     "#16a34a",
}

PAGE_W, PAGE_H = A4
MH = 1.8 * cm
MV = 2.2 * cm
CW = PAGE_W - 2 * MH


# ── Helpers ───────────────────────────────────────────────────────────────────
def _x(t):
    return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _inline(t):
    s = _x(t)
    s = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', s)
    s = re.sub(r'\*(.+?)\*',     r'<i>\1</i>', s)
    s = re.sub(r'`(.+?)`', r'<font name="Courier" size="8">\1</font>', s)
    return s


def _p_hex(prior):
    return P_HEX.get(prior, "#1e40af")


def _section_bar(title, hex_color="#0f2744"):
    lbl = ParagraphStyle("_sl", fontSize=9, fontName="Helvetica-Bold",
                          textColor=TXT, leading=13)
    t = Table([[None, Paragraph(title.upper(), lbl)]],
              colWidths=[5, CW - 5], rowHeights=[21])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, 0),  colors.HexColor(hex_color)),
        ("BACKGROUND",    (1, 0), (1, 0),  SURF2),
        ("LEFTPADDING",   (1, 0), (1, 0),  9),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


# ── Markdown parser ───────────────────────────────────────────────────────────
_SKIP = {
    "resumen ejecutivo", "análisis técnico", "analisis tecnico",
    "plan de mitigación", "plan de mitigacion", "resumen",
    "conclusión", "conclusion", "importante", "nota",
    "recomendaciones", "decisiones a tomar", "urgencia y prioridad",
    "decisión a tomar", "contexto de explotación",
    "contexto de explotacion", "impacto", "acción requerida",
    "sistemas afectados", "vector de ataque",
}


def _md(text, S):
    out = []
    for raw in text.split("\n"):
        ln = raw.strip()
        if not ln:
            continue
        m = re.match(r'^#{1,6}\s+(.+)$', ln)
        if m:
            h = m.group(1).strip().rstrip(":")
            if h.lower() not in _SKIP:
                out.append(Paragraph(_inline(h), S["sub"]))
            continue
        if re.match(r'^[-*]\s+', ln):
            body = re.sub(r'^[-*]\s+', '', ln)
            out.append(Paragraph(f"  -  {_inline(body)}", S["bul"]))
            continue
        m2 = re.match(r'^(\d+)\.\s+(.+)$', ln)
        if m2:
            out.append(Paragraph(
                f"<b>{m2.group(1)}.</b>  {_inline(m2.group(2))}", S["num"]))
            continue
        if re.match(r'^https?://\S+$', ln):
            continue
        if ln.lower().rstrip(":") in _SKIP:
            continue
        out.append(Paragraph(_inline(ln), S["body"]))
    return out


# ── Header / footer por página ────────────────────────────────────────────────
def _page_fn(cve_id, fecha):
    def fn(c, doc):
        c.saveState()
        c.setFillColor(NAVY)
        c.rect(MH, PAGE_H - MV + 4, CW, 0.6, fill=1, stroke=0)
        c.setFont("Helvetica", 6.5)
        c.setFillColor(MUTED)
        c.drawString(MH, PAGE_H - MV + 6,
                     "VulnSOC Assistant  -  Informe de vulnerabilidad")
        c.drawRightString(PAGE_W - MH, PAGE_H - MV + 6,
                          "CONFIDENCIAL  |  Uso interno")
        c.setFillColor(NAVY)
        c.rect(MH, MV - 8, CW, 0.6, fill=1, stroke=0)
        c.setFont("Helvetica", 6.5)
        c.setFillColor(MUTED)
        c.drawString(MH, MV - 14,
                     f"{cve_id}  |  NVD (NIST)  -  CISA KEV  -  EPSS (FIRST.org)")
        c.drawRightString(PAGE_W - MH, MV - 14, f"Pag. {doc.page}")
        c.restoreState()
    return fn


# ── Función principal ─────────────────────────────────────────────────────────
def generar_pdf(datos_nvd, datos_kev, datos_epss, score, analisis):
    buf   = io.BytesIO()
    fecha = datetime.now().strftime("%d %b %Y  %H:%M")
    cve   = datos_nvd.get("cve_id", "N/A")
    prior = score.get("prioridad", "")
    p_hex = _p_hex(prior)
    p_col = colors.HexColor(p_hex)

    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=MH, rightMargin=MH,
                            topMargin=MV, bottomMargin=MV)

    S = {
        "h1":  ParagraphStyle("h1",  fontSize=20, fontName="Helvetica-Bold",
                              textColor=WHITE, leading=24),
        "sh2": ParagraphStyle("sh2", fontSize=9,  fontName="Helvetica",
                              textColor=colors.HexColor("#93c5fd"), leading=13),
        "sh3": ParagraphStyle("sh3", fontSize=8,  fontName="Helvetica",
                              textColor=colors.HexColor("#94a3b8"), leading=12),
        "sub": ParagraphStyle("sub", fontSize=9,  fontName="Helvetica-Bold",
                              textColor=TMID, leading=13,
                              spaceBefore=7, spaceAfter=3),
        "body": ParagraphStyle("body", fontSize=8.5, fontName="Helvetica",
                               textColor=TXT, leading=14, spaceAfter=4,
                               alignment=TA_JUSTIFY),
        "bul": ParagraphStyle("bul", fontSize=8.5, fontName="Helvetica",
                              textColor=TXT, leading=13,
                              leftIndent=8, spaceAfter=2),
        "num": ParagraphStyle("num", fontSize=8.5, fontName="Helvetica",
                              textColor=TXT, leading=14,
                              leftIndent=8, spaceAfter=3),
        "th":  ParagraphStyle("th",  fontSize=8,   fontName="Helvetica-Bold",
                              textColor=WHITE, leading=12),
        "ml":  ParagraphStyle("ml",  fontSize=6,   fontName="Helvetica-Bold",
                              textColor=MUTED, leading=9,  alignment=TA_CENTER),
        "mv":  ParagraphStyle("mv",  fontSize=11,  fontName="Helvetica-Bold",
                              textColor=TXT,   leading=15, alignment=TA_CENTER),
    }

    def sp(h=8): return Spacer(1, h)
    story = []

    # ── 1. Banner ─────────────────────────────────────────────────────────
    pill_st = ParagraphStyle("pill", fontSize=7.5, fontName="Helvetica-Bold",
                              textColor=WHITE, alignment=TA_CENTER, leading=11)
    pill = Table([[Paragraph(prior, pill_st)]],
                 colWidths=[2.4 * cm], rowHeights=[15])
    pill.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), p_col),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))

    r1 = Table([[Paragraph(_x(cve), S["h1"]), pill]],
               colWidths=[CW - 3.2 * cm, 3.2 * cm])
    r1.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (1, 0), (1, 0),   "RIGHT"),
        ("RIGHTPADDING",  (1, 0), (1, 0),   0),
        ("LEFTPADDING",   (0, 0), (0, 0),   0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    banner = Table([
        [r1],
        [Paragraph("Informe de inteligencia de vulnerabilidad", S["sh2"])],
        [Paragraph(f"Generado: {fecha}", S["sh3"])],
    ], colWidths=[CW])
    banner.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), NAVY),
        ("LEFTPADDING",   (0, 0), (-1, -1), 16),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
        ("TOPPADDING",    (0, 0), (0, 0),   22),
        ("BOTTOMPADDING", (0, 0), (0, 0),   6),
        ("TOPPADDING",    (0, 1), (0, 1),   4),
        ("BOTTOMPADDING", (0, 1), (0, 1),   2),
        ("TOPPADDING",    (0, 2), (0, 2),   2),
        ("BOTTOMPADDING", (0, 2), (0, 2),   18),
    ]))
    story += [banner, sp(4)]

    # ── 2. Descripción NVD ────────────────────────────────────────────────
    desc = datos_nvd.get("descripcion", "")
    if desc:
        short = desc[:600] + ("..." if len(desc) > 600 else "")
        dbox = Table(
            [[Paragraph(_x(short),
                         ParagraphStyle("ds", fontSize=8.5, fontName="Helvetica",
                                         textColor=TMID, leading=14))]],
            colWidths=[CW]
        )
        dbox.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), SURF),
            ("LEFTPADDING",   (0, 0), (-1, -1), 12),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LINEABOVE",     (0, 0), (-1,  0),  2, p_col),
        ]))
        story += [dbox, sp(10)]

    # ── 3. Métricas ───────────────────────────────────────────────────────
    story.append(_section_bar("Metricas de riesgo", p_hex))
    story.append(sp(6))

    kev_on  = datos_kev.get("en_kev", False)
    epss_v  = score.get("epss_score", 0.0)
    cvss_p  = score.get("score_cvss_puro", 0)

    kev_h   = "#dc2626" if kev_on else "#16a34a"
    kev_txt = "ACTIVA"  if kev_on else "No"
    epss_h  = ("#dc2626" if epss_v > 0.7 else "#ea580c" if epss_v > 0.3 else "#16a34a")
    cvss_h  = ("#dc2626" if cvss_p >= 90 else "#ea580c" if cvss_p >= 70
               else "#d97706" if cvss_p >= 40 else "#16a34a")

    def _lbl(t): return Paragraph(_x(t), S["ml"])
    def _val(t, h="#0f172a"):
        return Paragraph(f'<font color="{h}">{_x(str(t))}</font>', S["mv"])

    labels = [_lbl("SCORE SISTEMA"), _lbl("SCORE INTERNO"), _lbl("CVSS PURO"),
              _lbl("PRIORIDAD"),     _lbl("CISA KEV"),       _lbl("EPSS"),
              _lbl("TIPO")]
    values = [
        _val(f"{score.get('score_mostrado', 0)}/100", p_hex),
        _val(score.get("score_interno", 0),            p_hex),
        _val(f"{cvss_p}/100",                          cvss_h),
        _val(prior,                                    p_hex),
        _val(kev_txt,                                  kev_h),
        _val(f"{epss_v:.1%}",                          epss_h),
        _val(score.get("tipo_vulnerabilidad", "-"),    "#334155"),
    ]

    mt = Table([labels, values], colWidths=[CW / 7] * 7)
    mt.setStyle(TableStyle([
        ("GRID",          (0, 0), (-1, -1), 0.4, BORDER),
        ("BACKGROUND",    (0, 0), (-1, -1), WHITE),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING",   (0, 0), (-1, -1), 3),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 3),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW",     (0, 1), (-1, 1),  2, p_col),
    ]))
    story += [mt, sp(10)]

    # ── 4. Alerta KEV ────────────────────────────────────────────────────
    if kev_on:
        kev_msg = (
            f"EXPLOTACION ACTIVA CONFIRMADA  -  "
            f"Incluido en CISA KEV el {datos_kev.get('fecha_añadido', 'N/A')}  |  "
            f"Fecha limite de parche: {datos_kev.get('fecha_limite', 'N/A')}"
        )
        kab = Table(
            [[Paragraph(_x(kev_msg),
                         ParagraphStyle("kev", fontSize=8, fontName="Helvetica-Bold",
                                         textColor=WHITE, leading=13))]],
            colWidths=[CW]
        )
        kab.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#7f1d1d")),
            ("LEFTPADDING",   (0, 0), (-1, -1), 12),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LINEABOVE",     (0, 0), (-1,  0), 2, colors.HexColor("#dc2626")),
        ]))
        story += [kab, sp(10)]

    # ── 5. Resumen ejecutivo ──────────────────────────────────────────────
    if analisis.get("resumen_ejecutivo"):
        story.append(_section_bar("Resumen ejecutivo"))
        story.append(sp(6))
        story.extend(_md(analisis["resumen_ejecutivo"], S))
        story.append(sp(10))

    # ── 6. Factores de scoring ────────────────────────────────────────────
    factores = score.get("factores", [])
    if factores:
        story.append(_section_bar("Factores de scoring"))
        story.append(sp(6))

        th_st = ParagraphStyle("fth", fontSize=8, fontName="Helvetica-Bold",
                                textColor=WHITE, leading=12)
        rows = [[
            Paragraph("Factor",   th_st),
            Paragraph("Puntos",   th_st),
            Paragraph("Detalle",  th_st),
        ]]
        for f in factores:
            pts     = f["puntos"]
            pts_hex = "#16a34a" if pts >= 0 else "#dc2626"
            pts_str = f"+{pts}" if pts > 0 else str(pts)
            rows.append([
                Paragraph(_x(f["factor"]),
                    ParagraphStyle("fn", fontSize=8, fontName="Helvetica-Bold",
                                    textColor=colors.HexColor("#1e40af"), leading=12)),
                Paragraph(f'<font color="{pts_hex}">{pts_str}</font>',
                    ParagraphStyle("fp", fontSize=8, fontName="Helvetica-Bold",
                                    textColor=TXT, leading=12, alignment=TA_CENTER)),
                Paragraph(_x(f["detalle"]),
                    ParagraphStyle("fd", fontSize=8, fontName="Helvetica",
                                    textColor=TXT, leading=12)),
            ])

        ft = Table(rows, colWidths=[3.8 * cm, 1.4 * cm, CW - 5.2 * cm])
        ft.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1,  0), NAVY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, SURF2]),
            ("GRID",           (0, 0), (-1, -1), 0.3, BORDER),
            ("TOPPADDING",     (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
            ("LEFTPADDING",    (0, 0), (-1, -1), 8),
            ("VALIGN",         (0, 0), (-1, -1), "TOP"),
            ("ALIGN",          (1, 0), (1,  -1), "CENTER"),
        ]))
        story += [ft, sp(10)]

    # ── 7. Vector de ataque ───────────────────────────────────────────────
    vector = datos_nvd.get("vector_ataque", {})
    if vector:
        story.append(_section_bar("Vector de ataque"))
        story.append(sp(6))

        MEANINGS = {
            "attackVector":       {
                "NETWORK":  "Explotable remotamente por red",
                "ADJACENT": "Requiere acceso a red adyacente",
                "LOCAL":    "Requiere acceso local al sistema",
                "PHYSICAL": "Requiere acceso fisico al dispositivo",
            },
            "attackComplexity":   {
                "LOW":  "Baja — no se requieren condiciones especiales",
                "HIGH": "Alta — requiere condiciones especificas",
            },
            "privilegesRequired": {
                "NONE": "Sin credenciales — cualquier atacante puede explotarlo",
                "LOW":  "Cuenta de usuario basica suficiente",
                "HIGH": "Requiere privilegios de administrador",
            },
            "userInteraction":    {
                "NONE":     "Sin interaccion del usuario — totalmente automatizado",
                "REQUIRED": "La victima debe realizar una accion",
            },
        }
        NAMES = {
            "attackVector":       "Vector de acceso",
            "attackComplexity":   "Complejidad",
            "privilegesRequired": "Privilegios necesarios",
            "userInteraction":    "Interaccion del usuario",
        }
        HIGH_RISK = {
            "attackVector":       ["NETWORK"],
            "attackComplexity":   ["LOW"],
            "privilegesRequired": ["NONE"],
            "userInteraction":    ["NONE"],
        }

        th_st = ParagraphStyle("vth", fontSize=8, fontName="Helvetica-Bold",
                                textColor=WHITE, leading=12)
        vrows = [[
            Paragraph("Parametro",      th_st),
            Paragraph("Valor",          th_st),
            Paragraph("Interpretacion", th_st),
        ]]
        for campo, valor in vector.items():
            meaning = MEANINGS.get(campo, {}).get(valor, valor)
            bad     = valor in HIGH_RISK.get(campo, [])
            v_hex   = "#dc2626" if bad else "#16a34a"
            vrows.append([
                Paragraph(_x(NAMES.get(campo, campo)),
                    ParagraphStyle("vn", fontSize=8, fontName="Helvetica-Bold",
                                    textColor=colors.HexColor("#1e40af"), leading=12)),
                Paragraph(f'<font color="{v_hex}">{_x(valor)}</font>',
                    ParagraphStyle("vv", fontSize=8, fontName="Helvetica-Bold",
                                    textColor=TXT, leading=12)),
                Paragraph(_x(meaning),
                    ParagraphStyle("vm", fontSize=8, fontName="Helvetica",
                                    textColor=TXT, leading=12)),
            ])

        vt = Table(vrows, colWidths=[3.8 * cm, 2.6 * cm, CW - 6.4 * cm])
        vt.setStyle(TableStyle([
            ("BACKGROUND",     (0, 0), (-1,  0), NAVY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, SURF2]),
            ("GRID",           (0, 0), (-1, -1), 0.3, BORDER),
            ("TOPPADDING",     (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
            ("LEFTPADDING",    (0, 0), (-1, -1), 8),
            ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ]))
        story += [vt, sp(10)]

    # ── 8. Analisis tecnico ───────────────────────────────────────────────
    if analisis.get("analisis_tecnico"):
        story.append(_section_bar("Analisis tecnico"))
        story.append(sp(6))
        story.extend(_md(analisis["analisis_tecnico"], S))
        story.append(sp(10))

    # ── 9. Plan de mitigacion ─────────────────────────────────────────────
    if analisis.get("plan_mitigacion"):
        story.append(_section_bar("Plan de mitigacion", "#16a34a"))
        story.append(sp(6))
        story.extend(_md(analisis["plan_mitigacion"], S))
        story.append(sp(12))

    cb = _page_fn(cve, fecha)
    doc.build(story, onFirstPage=cb, onLaterPages=cb)
    buf.seek(0)
    return buf.read()
