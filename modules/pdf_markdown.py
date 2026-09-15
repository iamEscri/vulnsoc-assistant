"""Markdown to ReportLab flowables. Never interpret supplied HTML or fetch resources."""
from html import escape
from urllib.parse import urlsplit

import mistune
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib import colors


def safe_url(value):
    value = str(value or '')
    try:
        parts = urlsplit(value)
        return value if parts.scheme.lower() in ('http', 'https') and parts.netloc and not any(ord(c) < 32 for c in value) else None
    except ValueError:
        return None


def inline(tokens):
    result = []
    for token in tokens:
        kind = token['type']
        body = inline(token.get('children', []))
        raw = escape(str(token.get('raw', '')), quote=True)
        if kind == 'strong': result.append(f'<b>{body}</b>')
        elif kind == 'emphasis': result.append(f'<i>{body}</i>')
        elif kind == 'strikethrough': result.append(f'<strike>{body}</strike>')
        elif kind == 'codespan': result.append(f'<font name="VS-Mono">{raw}</font>')
        elif kind == 'link':
            url = safe_url(token.get('attrs', {}).get('url'))
            result.append(f'<a href="{escape(url, quote=True)}" color="#176477">{body}</a>' if url else body)
        elif kind == 'image': result.append(body)  # Keep alt text without downloading images.
        elif kind == 'linebreak': result.append('<br/>')
        elif kind == 'softbreak': result.append(' ')
        else: result.append(body or raw)  # Includes escaped raw HTML, never ReportLab markup.
    return ''.join(result)


def markdown_flowables(text, styles, width, skip_title=None):
    parser = mistune.create_markdown(renderer='ast', plugins=['table', 'strikethrough'])
    tokens = parser(str(text or ''))
    def plain(items):
        return ''.join(plain(t['children']) if 'children' in t else t.get('raw', '') for t in items)

    # AI often repeats the section title as a bold paragraph rather than a heading.
    first = next((i for i, token in enumerate(tokens) if token['type'] != 'blank_line'), None)
    if first is not None and skip_title and tokens[first]['type'] in ('heading', 'paragraph'):
        label = plain(tokens[first].get('children', [])).casefold().strip().rstrip(':')
        if label == skip_title.casefold().strip().rstrip(':'):
            tokens = tokens[:first] + tokens[first+1:]

    def walk(items, depth=0):
        out = []
        body_style = ParagraphStyle('md_body', parent=styles['body'], leftIndent=min(depth, 8)*12)
        for token in items:
            kind = token['type']
            children = token.get('children', [])
            if kind in ('paragraph', 'block_text'):
                out.append(Paragraph(inline(children), body_style))
            elif kind == 'heading':
                out.append(Paragraph(inline(children), styles['sub']))
            elif kind == 'list':
                start = token.get('attrs', {}).get('start', 1)
                for i, item in enumerate(children):
                    bullet = f'{start+i}.' if token.get('attrs', {}).get('ordered') else '•'
                    flows = walk(item.get('children', []), depth+1)
                    if flows and isinstance(flows[0], Paragraph):
                        first = flows[0]
                        flows[0] = Paragraph(first.text, first.style, bulletText=bullet)
                    out.extend(flows)
            elif kind == 'block_quote':
                out.extend(walk(children, depth+1))
            elif kind == 'block_code':
                # Individual paragraphs let long code split between pages without truncation.
                out.append(Spacer(1, 5))
                for line in token.get('raw', '').expandtabs(4).splitlines():
                    out.append(Paragraph(escape(line, quote=True).replace(' ', '&#160;') or '&#160;', styles['code']))
                out.append(Spacer(1, 8))
            elif kind == 'table':
                head = children[0].get('children', [])
                rows = [head] + [row.get('children', []) for group in children[1:] for row in group.get('children', [])]
                count = max((len(row) for row in rows), default=1)
                if count <= 5:
                    cells = [[Paragraph(inline(cell.get('children', [])), styles['th'] if i == 0 else styles['cell']) for cell in row] for i, row in enumerate(rows)]
                    cells = [row + ['']*(count-len(row)) for row in cells]
                    table = Table(cells, colWidths=[width/count]*count, repeatRows=1, splitByRow=1, splitInRow=1)
                    table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#27485f')),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f1f5f7'), colors.white]),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('LINEBELOW', (0, 0), (-1, -1), .4, colors.HexColor('#d6e0e5')),
                        ('LEFTPADDING', (0, 0), (-1, -1), 8), ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                        ('TOPPADDING', (0, 0), (-1, -1), 8), ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ]))
                    out.extend([Spacer(1, 6), table, Spacer(1, 12)])
                else:
                    # Wide tables become labelled records to retain readable type on A4.
                    out.append(Paragraph('Tabla extensa · lectura por registros', styles['sub']))
                    for i, row in enumerate(rows[1:], 1):
                        out.append(Paragraph(f'Registro {i}', styles['sub']))
                        for j, cell in enumerate(row):
                            label = inline(head[j].get('children', [])) if j < len(head) else str(j+1)
                            out.append(Paragraph(f'<b>{label}:</b> {inline(cell.get("children", []))}', styles['body']))
            elif kind == 'thematic_break':
                out.extend([Spacer(1, 8), HRFlowable(width='100%', color=colors.HexColor('#c9d9e0')), Spacer(1, 8)])
            elif kind in ('block_html', 'text'):
                out.append(Paragraph(escape(token.get('raw', ''), quote=True), body_style))
            elif children:
                out.extend(walk(children, depth))
        return out
    return walk(tokens)
