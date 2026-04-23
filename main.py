import json
from modules.ingesta import analizar_cve
from modules.scoring import calcular_score
from modules.analisis_ia import generar_analisis

cve_id = "CVE-2021-34527"

resultado = analizar_cve(cve_id)
score = calcular_score(resultado["nvd"], resultado["kev"])
analisis = generar_analisis(resultado["nvd"], resultado["kev"], score)

print(json.dumps(analisis, indent=2, ensure_ascii=False))