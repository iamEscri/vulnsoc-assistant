"""VulnSOC methodology 2.0: explicit policy, not calibrated risk probability."""
import re
from datetime import datetime, timezone
from modules.evidencia import numero

VERSION = '2.0'
THRESHOLDS = {'MEDIA': 55, 'ALTA': 90, 'CRÍTICA': 130}
ACTIONS = {
    'CRÍTICA': 'Revisar con urgencia la aplicabilidad y priorizar mitigación o parche.',
    'ALTA': 'Revisar la aplicabilidad y planificar la remediación con prioridad.',
    'MEDIA': 'Evaluar en el ciclo de gestión y seguir nuevas evidencias.',
    'BAJA': 'Mantener seguimiento; baja prioridad no implica ausencia de riesgo.',
    'SIN DETERMINAR': 'Completar la información antes de asignar una prioridad definitiva.',
}


def _detectar_tipo_vulnerabilidad(cwes, descripcion):
    # CWE describes a weakness; deserialization/access control are not proof of RCE.
    mapping = {'CWE-78': 'Inyección de comandos', 'CWE-77': 'Inyección de comandos', 'CWE-94': 'Inyección de código', 'CWE-502': 'Deserialización', 'CWE-269': 'Gestión de privilegios', 'CWE-732': 'Permisos incorrectos', 'CWE-284': 'Control de acceso', 'CWE-89': 'SQLi', 'CWE-79': 'XSS', 'CWE-22': 'Path traversal', 'CWE-400': 'Consumo de recursos', 'CWE-20': 'Validación de entrada'}
    for cwe in cwes:
        if cwe in mapping:
            return mapping[cwe], 0
    patterns = [('RCE (inferido)', r'\b(remote code execution|arbitrary code execution|rce)\b'), ('PrivEsc (inferido)', r'\b(privilege escalation|escalation of privilege)\b'), ('SQLi (inferido)', r'\bsql injection\b'), ('XSS (inferido)', r'\b(cross[- ]site scripting|xss)\b'), ('DoS (inferido)', r'\b(denial of service|dos)\b')]
    for label, pattern in patterns:
        if re.search(pattern, descripcion, re.I):
            return label, 0
    return 'Desconocido', 0


def _finalize(score):
    points = sum(f['puntos'] for f in score['factores'])
    if score['calidad_datos']['cvss'] != 'disponible' and not score['kev_confirmado']:
        priority = 'SIN DETERMINAR'
    else:
        priority = next((p for p in ['CRÍTICA', 'ALTA', 'MEDIA'] if points >= THRESHOLDS[p]), 'BAJA')
    return {**score, 'score_interno': points, 'score_mostrado': min(points, 100), 'prioridad': priority, 'accion_recomendada': ACTIONS[priority], 'provisional': bool(score['advertencias'])}


def calcular_score(datos_nvd, datos_kev, datos_epss=None):
    epss = datos_epss or {}
    cvss = datos_nvd.get('cvss_score')
    cvss_ok = not datos_nvd.get('error') and numero(cvss, 0, 10)
    kev_ok = not datos_kev.get('error') and isinstance(datos_kev.get('en_kev'), bool)
    kev = kev_ok and datos_kev['en_kev']
    probability = epss.get('epss_score')
    epss_ok = not epss.get('error') and numero(probability, 0, 1)
    warnings = []
    factors = []
    def add(name, points, detail):
        factors.append({'factor': name, 'puntos': points, 'detalle': detail})
    if cvss_ok:
        add('Severidad CVSS', round(cvss * 10), f"CVSS {datos_nvd.get('cvss_version', '')}: {cvss}/10. Vector y CWE no reciben puntos adicionales.")
    else:
        warnings.append('CVSS no disponible: faltan datos de severidad. No equivale a severidad cero.')
        add('CVSS desconocido', 0, 'No se puede estimar la severidad a partir de los datos disponibles.')
    if kev:
        add('Explotación documentada · KEV', 60, f"Inclusión en CISA KEV desde {datos_kev.get('fecha_añadido', 'fecha no disponible')}. No prueba explotación de tus activos.")
        if sum(f['puntos'] for f in factors) < 90:
            add('Mínimo operativo por KEV', 90-sum(f['puntos'] for f in factors), 'Política VulnSOC: una explotación documentada requiere al menos prioridad alta, incluso con severidad incompleta.')
    elif not kev_ok:
        warnings.append('CISA KEV no verificado: no se puede descartar explotación documentada.')
        add('KEV sin verificar', 0, 'Fuente no disponible o respuesta incompleta; no se interpreta como ausencia del catálogo.')
    else:
        add('No incluida en KEV', 0, 'No listada en la consulta; no significa que no exista explotación.')
    if epss_ok:
        points = 0 if kev else 30 if probability >= .7 else 20 if probability >= .1 else 10 if probability >= .01 else 0
        add('EPSS · señal predictiva', points, f"Probabilidad {probability:.2%} a 30 días." + (' KEV tiene precedencia; EPSS no suma otra bonificación.' if kev else ' Política: ≥1% +10; ≥10% +20; ≥70% +30. No es una probabilidad de riesgo del activo.'))
    else:
        warnings.append('EPSS sin datos: probabilidad desconocida, no 0%.')
        add('EPSS desconocido', 0, 'No existe un dato utilizable para esta consulta.')
    published = datos_nvd.get('fecha_publicacion')
    if published:
        try:
            date = datetime.fromisoformat(published.replace('Z', '+00:00'))
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            if date > datetime.now(timezone.utc):
                warnings.append('Fecha de publicación futura: revisar el dato de origen.')
        except (ValueError, TypeError):
            warnings.append('Fecha de publicación inválida: revisar el dato de origen.')
    score = {'metodologia_version': VERSION, 'umbrales': THRESHOLDS, 'factores': factors, 'advertencias': warnings, 'calidad_datos': {'cvss': 'disponible' if cvss_ok else 'desconocido', 'kev': 'disponible' if kev_ok else 'desconocido', 'epss': 'disponible' if epss_ok else 'desconocido'}, 'kev_confirmado': kev, 'score_cvss_puro': round(cvss*10) if cvss_ok else 0, 'epss_score': probability if epss_ok else None, 'tipo_vulnerabilidad': _detectar_tipo_vulnerabilidad(datos_nvd.get('cwes', []), datos_nvd.get('descripcion', ''))[0], 'contexto_inventario': 'sin_inventario'}
    return _finalize(score)


def ajustar_por_inventario(score, inventario, productos_afectados, plataformas_afectadas=None, cpe_afectados=None):
    from modules.inventario import equipos_afectados, normalizar_inventario
    if not normalizar_inventario(inventario).get('equipos'):
        return score
    assets = equipos_afectados(inventario, productos_afectados, plataformas_afectadas, cpe_afectados)
    compatible = [a for a in assets if a['estado'] == 'version_compatible']
    result = {**score, 'factores': list(score['factores']), 'advertencias': list(score['advertencias'])}
    if not compatible:
        state = 'pendiente_verificacion' if assets else 'sin_coincidencias'
        result['contexto_inventario'] = state
        result['factores'].append({'factor': 'Inventario · sin ajuste', 'puntos': 0, 'detalle': 'No se ha establecido compatibilidad de producto y versión. No se resta prioridad ni se declara el entorno seguro.'})
        result['advertencias'].append('Aplicabilidad al inventario pendiente: verifica producto, versión y configuración.')
    else:
        def contribution(asset):
            return 5 + {'alta': 15, 'media': 5, 'baja': 0}.get(asset['criticidad'], 0) + (15 if asset['exposicion'] == 'internet' else 0)
        asset = max(compatible, key=contribution)
        result['contexto_inventario'] = 'version_compatible'
        result['factores'].append({'factor': 'Contexto de activo compatible', 'puntos': contribution(asset), 'detalle': f"{asset['nombre']}: versión compatible +5; criticidad {asset['criticidad']} +{ {'alta':15,'media':5,'baja':0}.get(asset['criticidad'],0) }; exposición {asset['exposicion']} +{15 if asset['exposicion']=='internet' else 0}. Se usa un único activo, el de mayor contribución. Verificar configuración; no confirma compromiso."})
        if asset['exposicion'] == 'desconocida':
            result['advertencias'].append('Exposición del activo desconocida: no se ha asumido que sea interna.')
    return _finalize(result)
