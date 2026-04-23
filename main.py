import json
from modules.ingesta import analizar_cve

# Log4Shell — famoso CVE que está en CISA KEV
cve_id = "CVE-2021-44228"

resultado = analizar_cve(cve_id)
print(json.dumps(resultado, indent=2, ensure_ascii=False))