import json
from modules.ingesta import analizar_cve
from modules.scoring import calcular_score

cve_id = "CVE-2021-34527"

resultado = analizar_cve(cve_id)
score = calcular_score(resultado["nvd"], resultado["kev"])

print("=== DATOS DEL CVE ===")
print(json.dumps(resultado, indent=2, ensure_ascii=False))
print("\n=== SCORING ===")
print(json.dumps(score, indent=2, ensure_ascii=False))