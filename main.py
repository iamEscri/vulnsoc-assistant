import json
from modules.ingesta import analizar_cve
from modules.scoring import calcular_score

resultado = analizar_cve("CVE-2023-44487")
score = calcular_score(resultado["nvd"], resultado["kev"], resultado["epss"])

print(json.dumps(score, indent=2, ensure_ascii=False))