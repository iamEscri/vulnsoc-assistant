"""VulnSOC Intelligence Brief: evidence first, reproducible scoring, optional AI appendix."""
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
from pathlib import Path
import io
import json
import math

import reportlab
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                               PageBreak, Flowable, CondPageBreak)
from modules.pdf_markdown import markdown_flowables, safe_url

FONT_DIR = Path(reportlab.__file__).parent / 'fonts'
for name, file in [('VS-Italic', 'VeraIt.ttf'), ('VS-BoldItalic', 'VeraBI.ttf')]:
    pdfmetrics.registerFont(TTFont(name, str(FONT_DIR / file)))
for name, file in [('VS', 'DejaVuSans.ttf'), ('VS-Bold', 'DejaVuSans-Bold.ttf'), ('VS-Mono', 'DejaVuSansMono.ttf')]:
    pdfmetrics.registerFont(TTFont(name, str(Path(__file__).parent / 'report_fonts' / file)))
pdfmetrics.registerFontFamily('VS', normal='VS', bold='VS-Bold', italic='VS-Italic', boldItalic='VS-BoldItalic')

NAVY = colors.HexColor('#15354e')
TEAL = colors.HexColor('#247889')
INK = colors.HexColor('#203c50')
MUTED = colors.HexColor('#596e7c')
PALE = colors.HexColor('#edf3f6')
LINE = colors.HexColor('#cddce3')
WHITE = colors.white
PRIORITY = {'CRÍTICA':'#b53f56', 'CRITICA':'#b53f56', 'ALTA':'#ae5425', 'MEDIA':'#886410', 'BAJA':'#287354'}
PAGE_W, PAGE_H = A4
MARGIN = 42
WIDTH = PAGE_W - MARGIN*2


def _x(value): return escape(str(value if value is not None else ''), quote=True)
def _number(value): return type(value) in (int, float) and math.isfinite(value)
def _date(value):
    if not value: return 'No registrada'
    try:
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        if parsed.tzinfo:
            return parsed.astimezone(timezone.utc).strftime('%d/%m/%Y %H:%M UTC')
        return parsed.strftime('%d/%m/%Y')
    except (ValueError, TypeError): return str(value)


def _styles():
    body = ParagraphStyle('body', fontName='VS', fontSize=9.3, leading=14.5, textColor=INK, spaceAfter=8, splitLongWords=True)
    return {
        'body': body,
        'small': ParagraphStyle('small', parent=body, fontSize=8, leading=12, textColor=MUTED, spaceAfter=5),
        'cell': ParagraphStyle('cell', parent=body, fontSize=8.3, leading=12.5, spaceAfter=0),
        'th': ParagraphStyle('th', parent=body, fontName='VS-Bold', fontSize=8, leading=12, textColor=WHITE, spaceAfter=0),
        'sub': ParagraphStyle('sub', parent=body, fontName='VS-Bold', fontSize=11, leading=16, spaceBefore=14, spaceAfter=8, keepWithNext=True),
        'section': ParagraphStyle('section', parent=body, fontName='VS-Bold', fontSize=19, leading=25, spaceAfter=16, keepWithNext=True),
        'kicker': ParagraphStyle('kicker', parent=body, fontName='VS-Bold', fontSize=8, leading=12, textColor=TEAL, spaceBefore=4, spaceAfter=7, keepWithNext=True),
        'code': ParagraphStyle('code', parent=body, fontName='VS-Mono', fontSize=8, leading=11, backColor=PALE, spaceAfter=0),
        'hero': ParagraphStyle('hero', parent=body, fontName='VS-Bold', fontSize=23, leading=30, textColor=WHITE, spaceAfter=8),
        'light': ParagraphStyle('light', parent=body, fontSize=8, leading=12, textColor=colors.HexColor('#bcd8e3'), spaceAfter=4),
    }


class ReportDocument(SimpleDocTemplate):
    def afterFlowable(self, flowable):
        if getattr(flowable, 'report_bookmark', None):
            key, label = flowable.report_bookmark
            self.report_ai = key == 'chapter-04'
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(label, key, level=0, closed=False)


def _page(cve, reference):
    def draw(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(NAVY)
        canvas.rect(0, PAGE_H-8, PAGE_W, 8, fill=1, stroke=0)
        # A compact shield echoes the web identity without a raster background.
        canvas.setStrokeColor(TEAL); canvas.setLineWidth(1.2)
        p = canvas.beginPath(); x, y = MARGIN, PAGE_H-37
        p.moveTo(x, y+8); p.lineTo(x+6, y+11); p.lineTo(x+12, y+8); p.lineTo(x+12, y+1)
        p.curveTo(x+12, y-4, x+6, y-7, x+6, y-7); p.curveTo(x+6, y-7, x, y-4, x, y+1); p.close()
        canvas.drawPath(p)
        canvas.setFont('VS-Bold', 12); canvas.setFillColor(NAVY)
        canvas.drawString(MARGIN+20, PAGE_H-39, 'VulnSOC')
        canvas.setFont('VS', 7); canvas.setFillColor(MUTED)
        canvas.drawRightString(PAGE_W-MARGIN, PAGE_H-37, 'ANÁLISIS ASISTIDO POR IA / REVISIÓN TÉCNICA' if getattr(doc, 'report_ai', False) else 'VULNERABILITY INTELLIGENCE / INFORME TÉCNICO')
        canvas.setStrokeColor(LINE); canvas.setLineWidth(.5)
        canvas.line(MARGIN, 39, PAGE_W-MARGIN, 39)
        canvas.setFont('VS', 7)
        canvas.drawString(MARGIN, 25, f'iamEscri · vulnsoc.iamescri.es · {reference}')
        canvas.drawRightString(PAGE_W-MARGIN, 25, f'{cve}   /   {doc.page:02d}')
        canvas.linkURL('https://vulnsoc.iamescri.es', (MARGIN, 20, MARGIN+220, 34), relative=0, thickness=0)
        canvas.restoreState()
    return draw


class ContributionBar(Flowable):
    def __init__(self, start, end, low, high, width):
        super().__init__(); self.start, self.end, self.low, self.high = start, end, low, high
        self.width, self.height = width, 22
    def draw(self):
        c = self.canv
        pos = lambda n: (n-self.low)/(self.high-self.low)*self.width
        c.setFillColor(PALE); c.roundRect(0, 7, self.width, 7, 3, fill=1, stroke=0)
        c.setFillColor(TEAL if self.end >= self.start else colors.HexColor('#9a596b'))
        if self.end == self.start: c.circle(pos(self.end), 10.5, 2.5, fill=1, stroke=0)
        else: c.rect(pos(min(self.start, self.end)), 7, abs(pos(self.end)-pos(self.start)), 7, fill=1, stroke=0)


def generar_pdf(datos_nvd, datos_kev, datos_epss, score, analisis, equipos_afectados=None, fecha_analisis=None):
    """Export the supplied snapshot unchanged; no network access or score recalculation."""
    buf = io.BytesIO(); S = _styles()
    cve = str(datos_nvd.get('cve_id', 'Sin identificador'))
    prior = str(score.get('prioridad') or 'SIN DETERMINAR')
    tone = colors.HexColor(PRIORITY.get(prior, '#526a81'))
    points = score.get('score_interno', score.get('score_mostrado'))
    points_text = str(points) if _number(points) and prior != 'SIN DETERMINAR' else 'Sin determinar'
    version = str(score.get('metodologia_version') or 'histórica / sin versión')
    known_kev = type(datos_kev.get('en_kev')) is bool and not datos_kev.get('error')
    kev = known_kev and datos_kev['en_kev']
    epss = datos_epss.get('epss_score')
    known_epss = _number(epss) and 0 <= epss <= 1 and not datos_epss.get('error')
    cvss = datos_nvd.get('cvss_score')
    known_cvss = _number(cvss) and 0 <= cvss <= 10 and not datos_nvd.get('error')
    warnings = list(score.get('advertencias') or [])
    snapshot = [datos_nvd, datos_kev, datos_epss, score, analisis, equipos_afectados, fecha_analisis]
    reference = sha256(json.dumps(snapshot, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()[:12].upper()
    generated = datetime.now(timezone.utc).strftime('%d/%m/%Y %H:%M UTC')
    doc = ReportDocument(buf, pagesize=A4, leftMargin=MARGIN-6, rightMargin=MARGIN-6,
                         topMargin=64, bottomMargin=52, title=f'{cve} | VulnSOC Intelligence Brief',
                         author='iamEscri · VulnSOC Assistant', subject='Evidencias y priorización contextual de vulnerabilidades')
    story = []
    p = lambda text, style='body': Paragraph(_x(text), S[style])

    def section(number, title, note=None):
        story.append(p(number+' / VULNSOC INTELLIGENCE BRIEF', 'kicker'))
        heading = p(title, 'section'); heading.report_bookmark = ('chapter-'+number, title); story.append(heading)
        if note: story.append(p(note))

    def table(headers, rows, widths):
        cells = [[p(h, 'th') for h in headers]] + [[p(v, 'cell') for v in row] for row in rows]
        t = Table(cells, colWidths=widths, repeatRows=1, splitByRow=1, splitInRow=1, hAlign='LEFT')
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), NAVY), ('ROWBACKGROUNDS',(0,1),(-1,-1),[WHITE,PALE]),
            ('LINEBELOW',(0,0),(-1,-1),.4,LINE), ('VALIGN',(0,0),(-1,-1),'TOP'),
            ('LEFTPADDING',(0,0),(-1,-1),9), ('RIGHTPADDING',(0,0),(-1,-1),9),
            ('TOPPADDING',(0,0),(-1,-1),9), ('BOTTOMPADDING',(0,0),(-1,-1),9),
        ])); return t

    # Page one is a concise decision brief, with all source text preserved later.
    left = [p('INFORME DE PRIORIZACIÓN', 'light'), p(cve, 'hero'), p('Evidencias · contexto · decisión', 'light')]
    score_style = ParagraphStyle('score', parent=S['hero'], fontSize=32 if _number(points) and prior != 'SIN DETERMINAR' else 16, leading=38 if _number(points) and prior != 'SIN DETERMINAR' else 23)
    right = [p('VULNSOC SCORE', 'light'), Paragraph(_x(points_text), score_style), p('puntos · '+prior, 'light')]
    hero = Table([[left,right]], colWidths=[WIDTH*.65, WIDTH*.35], hAlign='LEFT')
    hero.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),NAVY),('BACKGROUND',(1,0),(1,0),tone),
        ('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),18),('RIGHTPADDING',(0,0),(-1,-1),18),
        ('TOPPADDING',(0,0),(-1,-1),18),('BOTTOMPADDING',(0,0),(-1,-1),16)]))
    story.extend([hero,Spacer(1,12),p(f'Exportado: {generated}', 'small'),
                  p(f'Análisis guardado: {_date(fecha_analisis)}   ·   Referencia: {reference}', 'small'),Spacer(1,12)])
    section('01','Decisión y alcance')
    action = score.get('accion_recomendada') or 'Revisar evidencias y aplicabilidad. El informe conserva la metodología original.'
    story.append(p(action,'sub'))
    story.append(p('Evaluación provisional: hay datos o contexto pendientes.' if score.get('provisional', True) else 'Priorización orientativa basada en la instantánea disponible.', 'small'))
    metric_rows = [[f'{cvss:g}/10' if known_cvss else 'Sin datos', f'{epss:.1%}' if known_epss else 'Sin datos', 'Incluida' if kev else 'No listada' if known_kev else 'Sin verificar'],
                   [f"CVSS {datos_nvd.get('cvss_version') or 'sin versión'}", 'Predicción a 30 días', 'Explotación documentada' if kev else 'Ausencia de listado no implica seguridad']]
    metric_style = ParagraphStyle('metric_value', parent=S['body'], fontName='VS-Bold', fontSize=16, leading=22, textColor=NAVY, spaceAfter=0)
    metrics = Table([[p(label,'th') for label in ['SEVERIDAD CVSS','PROBABILIDAD EPSS','CISA KEV']],
                     [Paragraph(_x(value),metric_style) for value in metric_rows[0]],
                     [p(value,'small') for value in metric_rows[1]]],colWidths=[WIDTH/3]*3,hAlign='LEFT')
    metrics.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),NAVY),('BACKGROUND',(0,1),(-1,-1),PALE),
        ('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),10),('RIGHTPADDING',(0,0),(-1,-1),10),
        ('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8)]))
    story.extend([metrics,Spacer(1,12)])
    context = {
        'sin_inventario':'Sin inventario: este resultado no evalúa el riesgo de un entorno concreto.',
        'version_compatible':'Hay compatibilidad de versión. Verifica la configuración; no confirma compromiso.',
        'pendiente_verificacion':'Aplicabilidad pendiente: revisa producto, versión y configuración.',
        'sin_coincidencias':'Sin coincidencias verificadas. No demuestra ausencia de riesgo en el entorno.',
    }.get(score.get('contexto_inventario'), 'El informe no registra un estado de aplicabilidad al inventario.')
    story.extend([p('Aplicabilidad al entorno','sub'),p(context)])
    desc = str(datos_nvd.get('descripcion') or 'Descripción no disponible en esta instantánea.')
    excerpt = desc if len(desc) <= 470 else desc[:470].rsplit(' ',1)[0]+'…'
    story.extend([p('Descripción de la fuente · NVD','sub'),p(excerpt),p('Descripción completa y referencias en Evidencias técnicas.','small')])
    if warnings: story.append(p(f'Hay {len(warnings)} advertencia(s). Consulta el detalle en Trazabilidad del score.', 'small'))
    story.append(p('Lectura del informe: 02 Scoring · 03 Evidencias · 04 Análisis asistido', 'small'))
    story.append(PageBreak())

    section('02','Trazabilidad del score','La puntuación explica una política de priorización. No es un porcentaje ni una probabilidad de compromiso.')
    if version == '2.0':
        story.append(table(['BAJA','MEDIA','ALTA','CRÍTICA'],[['0–54 puntos','55–89 puntos','90–129 puntos','Desde 130 puntos']],[WIDTH/4]*4))
        story.append(Spacer(1,12))
        story.append(p('CVSS se incorpora una sola vez. KEV aporta +60 y tiene precedencia sobre EPSS; sin KEV confirmado, EPSS aplica un único tramo (+0 / +10 / +20 / +30). KEV garantiza al menos 90 puntos antes del contexto de activos.'))
        story.append(p('El contexto utiliza un solo activo compatible: +5 por versión, +0 / +5 / +15 por criticidad y +15 por exposición declarada a Internet. Sin coincidencia verificable no resta puntos. Crítica comienza en 130; el máximo actual por las reglas es 195.','small'))
    else: story.append(p('Informe histórico: no se aplican los umbrales actuales ni se recalcula el resultado. Compara únicamente informes de la misma metodología.'))
    factors = score.get('factores') or []
    running = 0; rows = []
    for factor in factors:
        value = factor.get('puntos')
        if not _number(value): raise ValueError('Puntos de factor no válidos')
        rows.append((factor,running,running+value)); running += value
    low = min([0]+[min(a,b) for _,a,b in rows]); high = max([1]+[max(a,b) for _,a,b in rows])
    span = high-low; low -= span*.015; high += span*.015
    for i,(factor,start,end) in enumerate(rows,1):
        val = factor['puntos']; label = ('+' if val>0 else '')+str(val)+' pts'
        chart = Table([[p(f'{i:02d}  {factor.get("factor", "Factor")}', 'cell'), ContributionBar(start,end,low,high,WIDTH*.29-18),p(label,'cell'),p(f'Σ {end:g}','cell')],
                       [p(factor.get('detalle') or 'Detalle no registrado.','small'),'','','']],
                      colWidths=[WIDTH*.41,WIDTH*.29,WIDTH*.15,WIDTH*.15], splitByRow=1,splitInRow=1,hAlign='LEFT')
        chart.setStyle(TableStyle([('SPAN',(0,1),(-1,1)),('BACKGROUND',(0,0),(-1,-1),PALE),('VALIGN',(0,0),(-1,-1),'TOP'),
            ('LINEBEFORE',(0,0),(0,-1),2,TEAL),('LEFTPADDING',(0,0),(-1,-1),9),('RIGHTPADDING',(0,0),(-1,-1),9),
            ('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),7)]))
        story.extend([chart,Spacer(1,8)])
    if not rows: story.append(p('Este informe no incluye el desglose de factores.'))
    if rows and _number(points) and abs(running-points)>.01:
        story.append(p(f'Desglose parcial: los factores suman {running:g}, pero el informe registra {points:g}. Se conserva el resultado original.'))
    story.append(p(f'Resultado registrado: {points_text} · {prior}', 'sub'))
    if prior=='SIN DETERMINAR' and _number(points):story.append(p(f'Puntos parciales registrados: {points:g}. No permiten asignar una prioridad definitiva.'))
    story.append(p('Calidad de la evidencia','sub'))
    if warnings:
        for warning in warnings: story.append(p('• '+str(warning)))
    else: story.append(p('La instantánea no registra advertencias. Esto no sustituye la revisión de aplicabilidad ni acredita seguridad del entorno.'))
    story.append(p('Las barras muestran aportaciones acumuladas; el punto indica una aportación de cero.', 'small'))
    story.append(p('Metodología propia de VulnSOC, no calibrada estadísticamente. Las fuentes no avalan sus pesos.','small'))
    story.append(Paragraph('<a href="https://github.com/iamEscri/vulnsoc-assistant/blob/main/docs-methodology.md" color="#176477">Consultar metodología y límites del motor</a>',S['small']))
    story.append(PageBreak())

    section('03','Evidencias técnicas','Datos de la instantánea utilizada para el análisis. Exportar este documento no actualiza las fuentes.')
    story.append(table(['FUENTE / DATO','ESTADO','FECHA DISPONIBLE'],[
        ['NVD / CVSS','Disponible' if known_cvss else 'Severidad sin datos',_date(datos_nvd.get('consultado_en'))],
        ['CISA KEV','Incluida' if kev else 'No listada' if known_kev else 'Sin verificar',_date(datos_kev.get('consultado_en'))],
        ['FIRST EPSS','Disponible' if known_epss else 'Sin datos',_date(datos_epss.get('fecha') or datos_epss.get('date') or datos_epss.get('consultado_en'))],
    ],[WIDTH*.3,WIDTH*.3,WIDTH*.4]))
    story.extend([Spacer(1,10),p(f"Publicación NVD: {_date(datos_nvd.get('fecha_publicacion'))} · Modificación: {_date(datos_nvd.get('fecha_modificacion'))}",'small'),
                  p('Descripción completa · NVD','sub')])
    # Paragraphs split across pages, including very long descriptions from imported records.
    for paragraph in desc.split('\n\n'): story.append(p(paragraph))
    story.append(p('Clasificación y condiciones técnicas','sub'))
    story.append(p(f"Tipo registrado: {score.get('tipo_vulnerabilidad') or 'No disponible'} · CWE: {', '.join(datos_nvd.get('cwes') or []) or 'No disponible'}"))
    vector=datos_nvd.get('vector_ataque') or {}
    if vector:
        names={'attackVector':'Vector de acceso','attackComplexity':'Complejidad','privilegesRequired':'Privilegios requeridos','userInteraction':'Interacción de usuario'}
        story.append(table(['ATRIBUTO CVSS','VALOR REGISTRADO'],[[names.get(k,k),v] for k,v in vector.items()],[WIDTH*.5]*2))
        story.append(p('El vector describe condiciones técnicas; por sí solo no demuestra exposición a Internet ni explotación del activo.','small'))
    if kev:
        story.append(p('Acción publicada por CISA','sub'))
        story.append(p(datos_kev.get('accion_requerida') or 'No consta una acción en esta instantánea.'))
        story.append(p(f"Incluida en KEV: {_date(datos_kev.get('fecha_añadido'))}. Fecha de directiva: {_date(datos_kev.get('fecha_limite'))}. Su obligatoriedad depende del ámbito de la directiva; no es un plazo universal.",'small'))
    story.append(p('Contexto de activos','sub')); story.append(p(context))
    if equipos_afectados:
        for asset in equipos_afectados:
            story.append(table(['ACTIVO RELACIONADO','ESTADO DECLARADO / OBSERVADO'],[
                [asset.get('nombre','Sin nombre'),asset.get('estado','Sin estado registrado')],
                ['Criticidad / exposición',f"{asset.get('criticidad','desconocida')} / {asset.get('exposicion','desconocida')}"],
                ['Coincidencias',', '.join(asset.get('coincidencias') or []) or 'Sin detalle'],
            ],[WIDTH*.35,WIDTH*.65]))
            story.append(p(asset.get('limitacion') or 'Revisar configuración. No confirma compromiso.','small'))
    else: story.append(p('No se adjuntan activos relacionados en esta exportación.','small'))
    story.append(p('Referencias para contrastar el análisis','sub'))
    refs=[f'https://nvd.nist.gov/vuln/detail/{cve}','https://www.cisa.gov/known-exploited-vulnerabilities-catalog','https://www.first.org/epss/']
    refs.extend(datos_nvd.get('referencias') or [])
    seen=set()
    for ref in refs:
        if isinstance(ref,dict):ref=ref.get('url')
        url=safe_url(ref)
        if not url or url in seen:continue
        seen.add(url)
        story.append(Paragraph(f'<b>{len(seen):02d}.</b> <a href="{_x(url)}" color="#176477">{_x(url)}</a>',S['small']))
    story.append(p('Referencia documental '+reference+': identificador derivado del contenido exportado; no es una firma digital.','small'))
    story.append(CondPageBreak(250))
    section('04','Análisis asistido','Contenido generado por IA, separado de las evidencias y del cálculo del motor. Requiere revisión técnica antes de utilizarlo para decidir o actuar.')
    if analisis.get('error'): story.append(p('Estado de la generación: '+str(analisis['error'])))
    if analisis.get('alucinacion_detectada'): story.append(p('Advertencia registrada: posibles afirmaciones no respaldadas. Contrasta el texto con las fuentes.','sub'))
    found=False
    for title,key in [('Resumen ejecutivo','resumen_ejecutivo'),('Análisis técnico','analisis_tecnico'),('Plan de mitigación','plan_mitigacion')]:
        if analisis.get(key):
            found=True
            story.append(p(title,'sub'))
            story.extend(markdown_flowables(analisis[key],S,WIDTH,skip_title=title))
            story.append(Spacer(1,12))
    if not found:
        story.append(p('No se ha generado análisis con IA para esta instantánea. El score, sus factores y las evidencias anteriores pueden utilizarse independientemente del proveedor de IA.'))
    story.append(p('Revisión antes de actuar','sub'))
    for text in ['Verifica producto, versión y configuración de los activos.',
                 'Contrasta versiones corregidas y medidas con los avisos originales del proveedor.',
                 'Valida las medidas en tu entorno y registra la decisión de remediación.']:
        story.append(p('• '+text))
    draw=_page(cve,reference)
    doc.build(story,onFirstPage=draw,onLaterPages=draw)
    return buf.getvalue()
