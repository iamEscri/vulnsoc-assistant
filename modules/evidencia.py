"""Conservative source parsing shared by search, analysis and inventory."""
import math
import re


def numero(value, minimum, maximum):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and minimum <= value <= maximum


def seleccionar_cvss(metrics):
    for key, version in [('cvssMetricV40', '4.0'), ('cvssMetricV31', '3.1'), ('cvssMetricV30', '3.0'), ('cvssMetricV2', '2.0')]:
        candidates = sorted(metrics.get(key, []), key=lambda m: (m.get('type') != 'Primary', m.get('source') != 'nvd@nist.gov'))
        for metric in candidates:
            data = metric.get('cvssData', {})
            if not numero(data.get('baseScore'), 0, 10):
                continue
            vector = {k: str(data.get(k, '')) for k in ['attackVector', 'attackComplexity', 'privilegesRequired', 'userInteraction', 'attackRequirements']}
            if version == '2.0':
                vector.update(attackVector=data.get('accessVector', ''), attackComplexity=data.get('accessComplexity', ''), privilegesRequired=data.get('authentication', ''), userInteraction='No disponible en CVSS 2.0')
            return {'cvss_score': data['baseScore'], 'cvss_version': version, 'vector_ataque': vector, 'cvss_fuente': metric.get('source', ''), 'cvss_vector': data.get('vectorString', '')}
    return {'cvss_score': None, 'cvss_version': None, 'vector_ataque': {}, 'cvss_fuente': '', 'cvss_vector': ''}


def partes_cpe(value):
    # Escaped delimiters cannot be split with str.split(':').
    parts = re.split(r'(?<!\\):', value)
    return parts if len(parts) == 13 and parts[:2] == ['cpe', '2.3'] else None


def extraer_cpes(configurations):
    result = []
    def walk(node, conditional=False):
        conditional = conditional or node.get('negate', False) or node.get('operator') == 'AND'
        for match in node.get('cpeMatch', []):
            if match.get('vulnerable') is True:
                parts = partes_cpe(match.get('criteria', ''))
                if parts:
                    result.append({**match, 'condicional': conditional})
        for key in ['nodes', 'children']:
            for child in node.get(key, []):
                walk(child, conditional)
    for config in configurations:
        walk(config)
    return result


def normalizar_nombre(value):
    return ' '.join(re.sub(r'[^\w]+', ' ', value.casefold().replace('_', ' ')).split())


def version_numerica(value):
    if not re.fullmatch(r'\d+(?:\.\d+)*', value):
        return None
    parts = [int(p) for p in value.split('.')]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def comparar_version(a, b):
    a, b = version_numerica(a), version_numerica(b)
    if a is None or b is None:
        return None
    size = max(len(a), len(b))
    a, b = a + (0,) * (size-len(a)), b + (0,) * (size-len(b))
    return (a > b) - (a < b)


def version_en_rango(installed, match):
    """True/False/None: compatible / outside / cannot establish. No safe claim."""
    parts = partes_cpe(match.get('criteria', ''))
    if not parts or not installed or installed in ('*', '-') or match.get('condicional'):
        return None
    # Other constrained CPE attributes need configuration evidence we do not have.
    if any(p not in ('*', '-') for p in parts[6:]):
        return None
    exact = parts[5]
    if exact not in ('*', '-'):
        # Non-numeric vendor versions are not ordered or assumed equivalent.
        relation = comparar_version(installed, exact)
        if relation is None:
            return None
        if relation != 0:
            return False
    elif exact == '-':
        return None
    has_bound = exact != '*'
    for key, reject in [('versionStartIncluding', lambda c: c < 0), ('versionStartExcluding', lambda c: c <= 0), ('versionEndIncluding', lambda c: c > 0), ('versionEndExcluding', lambda c: c >= 0)]:
        if key in match:
            has_bound = True
            relation = comparar_version(installed, match[key])
            if relation is None:
                return None
            if reject(relation):
                return False
    return True if has_bound else None
