COLORES_PRIORIDAD = {
    "CRÍTICA": "#ff4444",
    "ALTA":    "#ff8c00",
    "MEDIA":   "#f0c040",
    "BAJA":    "#3dd68c",
}


def color_prioridad(prioridad: str) -> str:
    return COLORES_PRIORIDAD.get(prioridad, "#888888")


def color_cvss(score: float) -> str:
    if score >= 9.0:
        return "#ff4444"
    elif score >= 7.0:
        return "#ff8c00"
    elif score >= 4.0:
        return "#f0c040"
    return "#3dd68c"


def badge_prioridad(prioridad: str) -> str:
    c = color_prioridad(prioridad)
    return (
        f'<span style="background:{c}20;color:{c};border:1px solid {c}55;'
        f'border-radius:4px;padding:3px 10px;font-size:0.73rem;font-weight:700;'
        f'letter-spacing:0.05em;white-space:nowrap;">{prioridad}</span>'
    )


def badge_cvss(score: float) -> str:
    c = color_cvss(score)
    return (
        f'<span style="background:{c}20;color:{c};border:1px solid {c}55;'
        f'border-radius:4px;padding:3px 8px;font-size:0.73rem;font-weight:700;'
        f'white-space:nowrap;">CVSS {score}</span>'
    )


def badge_kev() -> str:
    return (
        '<span style="background:#ff444420;color:#ff4444;border:1px solid #ff444455;'
        'border-radius:4px;padding:3px 8px;font-size:0.73rem;font-weight:700;'
        'white-space:nowrap;">⚡ KEV</span>'
    )


def chip(texto: str) -> str:
    return (
        f'<span style="background:rgba(255,255,255,0.07);color:rgba(255,255,255,0.55);'
        f'border-radius:4px;padding:2px 8px;font-size:0.75rem;white-space:nowrap;">{texto}</span>'
    )


def _color_epss(epss: float) -> str:
    if epss > 0.7:
        return "#ff4444"
    if epss > 0.3:
        return "#ff8c00"
    return "#3dd68c"


def metricas_cve_html(score: dict, kev: bool, epss: float) -> str:
    prioridad = score["prioridad"]
    c = color_prioridad(prioridad)
    kev_color = "#ff4444" if kev else "#3dd68c"
    kev_texto = "⚡ Activa" if kev else "✓ No"
    cvss_puro = score.get("score_cvss_puro", 0)

    def _card(label, valor, border_color=None, tooltip=""):
        bc = border_color or "rgba(255,255,255,0.15)"
        return (
            f'<div title="{tooltip}" style="background:#161b22;border:1px solid rgba(255,255,255,0.08);'
            f'border-top:3px solid {bc};border-radius:7px;padding:0.85rem 1rem;">'
            f'<div style="color:rgba(255,255,255,0.4);font-size:0.67rem;font-weight:600;'
            f'text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.35rem;">{label}</div>'
            f'<div style="color:#e6edf3;font-size:1.3rem;font-weight:700;">{valor}</div>'
            f'</div>'
        )

    card_prioridad = (
        f'<div style="background:#161b22;border:1px solid rgba(255,255,255,0.08);'
        f'border-top:3px solid {c};border-radius:7px;padding:0.85rem 1rem;">'
        f'<div style="color:rgba(255,255,255,0.4);font-size:0.67rem;font-weight:600;'
        f'text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.5rem;">Prioridad</div>'
        f'{badge_prioridad(prioridad)}</div>'
    )

    card_kev = (
        f'<div style="background:#161b22;border:1px solid rgba(255,255,255,0.08);'
        f'border-top:3px solid {kev_color};border-radius:7px;padding:0.85rem 1rem;">'
        f'<div style="color:rgba(255,255,255,0.4);font-size:0.67rem;font-weight:600;'
        f'text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.35rem;">CISA KEV</div>'
        f'<div style="color:{kev_color};font-size:1.1rem;font-weight:700;">{kev_texto}</div>'
        f'</div>'
    )

    cards = "".join([
        _card("Score sistema",  f"{score['score_mostrado']}/100", c),
        _card("Score interno",  score['score_interno'], c,
              "Puntuación real sin límite. Útil para ordenar CVEs con score igual."),
        _card("CVSS puro",      f"{cvss_puro}/100",    color_cvss(cvss_puro / 10)),
        card_prioridad,
        card_kev,
        _card("EPSS",           f"{epss:.1%}",         _color_epss(epss)),
        _card("Tipo",           score.get("tipo_vulnerabilidad", "—")),
    ])

    return (
        f'<div style="display:grid;grid-template-columns:repeat(7,1fr);'
        f'gap:0.65rem;margin:0.75rem 0 1.25rem;">{cards}</div>'
    )
