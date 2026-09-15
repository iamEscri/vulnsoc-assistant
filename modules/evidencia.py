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


def _version_ordenable(value):
    """Conventional release stages only; unknown vendor schemes stay unverified."""
    match = re.fullmatch(r'(\d+(?:\.\d+)*)(?:[-._]?(alpha|a|beta|b|rc|p|patch|post)[-._]?(\d+))?', value, re.I)
    if not match:
        return None
    stage = {None: 0, 'alpha': -3, 'a': -3, 'beta': -2, 'b': -2, 'rc': -1,
             'p': 1, 'patch': 1, 'post': 1}[match[2].lower() if match[2] else None]
    return version_numerica(match[1]), stage, int(match[3] or 0)


def version_cpe(parts):
    """Join a recognized CPE update with its base version without discarding it."""
    version, update = (re.sub(r'\\([._-])', r'\1', part) for part in parts[5:7])
    if update in ('*', '-'):
        return version
    if version_numerica(version) is None:
        return None
    combined = f'{version}-{update}'
    return combined if _version_ordenable(combined) else None


def comparar_version(a, b):
    a, b = _version_ordenable(a), _version_ordenable(b)
    if a is None or b is None:
        return None
    size = max(len(a[0]), len(b[0]))
    a = (a[0] + (0,) * (size-len(a[0])), *a[1:])
    b = (b[0] + (0,) * (size-len(b[0])), *b[1:])
    return (a > b) - (a < b)


def version_en_rango(installed, match):
    """True/False/None: compatible / outside / cannot establish. No safe claim."""
    parts = partes_cpe(match.get('criteria', ''))
    if not parts or not installed or installed in ('*', '-') or match.get('condicional'):
        return None
    # Other constrained CPE attributes need configuration evidence we do not have.
    if any(p not in ('*', '-') for p in parts[7:]):
        return None
    exact = version_cpe(parts)
    if exact is None:
        return None
    if exact not in ('*', '-'):
        # Recognized suffixes preserve prerelease / release / patch ordering.
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
