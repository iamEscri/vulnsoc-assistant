import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Annotated

import requests
from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field, ConfigDict
from modules.ingesta import analizar_cve, buscar_cves_por_descripcion, HEADERS, NVD_BASE_URL
from modules.scoring import calcular_score, ajustar_por_inventario
from modules.evidencia import seleccionar_cvss
from modules.inventario import equipos_afectados, importar_inventario
from modules.analisis_ia import generar_analisis, generar_regla_sigma
from modules.exportar_pdf import generar_pdf
from backend.service import cached, allowance
from modules.http_client import get_json

app = FastAPI(title='VulnSOC API', version='2.0.0', docs_url='/api/docs', openapi_url='/api/openapi.json')
CVE = Annotated[str, Field(pattern=r'^CVE-\d{4}-\d{4,19}$')]
class Asset(BaseModel):
    nombre: str = Field(min_length=1, max_length=120)
    ip: str = Field(default='', max_length=100)
    criticidad: str = Field(default='media', pattern='^(alta|media|baja)$')
    exposicion: str = Field(default='desconocida', pattern='^(internet|interna|desconocida)$')
    tecnologias: list[Annotated[str, Field(max_length=200)]] = Field(default_factory=list, max_length=100)
class Inventory(BaseModel):
    equipos: list[Asset] = Field(default_factory=list, max_length=500)
class AnalysisRequest(BaseModel):
    cve_id: CVE
    inventario: Inventory = Field(default_factory=Inventory)
    ia: bool = False
class SearchRequest(BaseModel):
    termino: str = Field(min_length=2, max_length=200)
    cpe: str = Field(default='', max_length=500)
    inicio: int = Field(default=0, ge=0, le=100000)
class ReportRequest(BaseModel):
    model_config = ConfigDict(extra='ignore')
    cve_id: CVE
    resultado: dict
    score: dict
    analisis: dict = Field(default_factory=dict)

@app.middleware('http')
async def protect(request: Request, call_next):
    if request.method == 'POST':
        # Bound actual body size, including chunked requests.
        body = bytearray()
        async for part in request.stream():
            body.extend(part)
            if len(body) > 2_000_000:
                return Response('Archivo demasiado grande', status_code=413)
        request._body = bytes(body)
        host = request.client.host if request.client else 'unknown'
        if not allowance('http:'+host, 60, 60):
            return Response('Demasiadas solicitudes. Espera un minuto.', status_code=429, headers={'Retry-After':'60'})
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-store'
    return response

@app.get('/api/health')
def health():
    return {'status':'ok', 'version':'2.0.0'}

def sources(cve):
    result = cached('sources:v2:'+cve, 1800, lambda: analizar_cve(cve))
    if 'error' in result['nvd']:
        raise HTTPException(502, result['nvd']['error'])
    if result['nvd'].get('estado_nvd') == 'Rejected':
        raise HTTPException(422, 'Este identificador está rechazado en NVD. Revisa su referencia oficial.')
    return result

def ai_budget(request):
    host = request.client.host if request.client else 'unknown'
    return allowance('ai:'+host, int(os.getenv('AI_VISITOR_DAILY_LIMIT','10')), 86400) and allowance('ai:global', int(os.getenv('AI_DAILY_LIMIT','80')), 86400)

@app.post('/api/analyze')
def analyze(payload: AnalysisRequest, request: Request):
    result = sources(payload.cve_id)
    inv = payload.inventario.model_dump()
    score = ajustar_por_inventario(calcular_score(result['nvd'], result['kev'], result['epss']), inv, result['nvd'].get('productos_afectados',[]), result['nvd'].get('plataformas_afectadas',[]), result['nvd'].get('cpe_afectados',[]))
    # Keep the legacy capped field inside the historical engine only.
    score.pop('score_mostrado', None)
    analysis = {}
    if payload.ia:
        context = json.dumps([result, score], sort_keys=True)
        key = 'ai:v4:'+hashlib.sha256(context.encode()).hexdigest()
        def generate():
            if not ai_budget(request):
                return {'error':'Cuota de IA agotada. Los datos y la exportación siguen disponibles.'}
            return generar_analisis(result['nvd'], result['kev'], score)
        analysis = cached(key, 3600, generate)
    return {'cve_id':payload.cve_id, 'resultado':result, 'score':score, 'analisis':analysis,
            'score_interno':score['score_interno'],
            'prioridad':score['prioridad'], 'tipo':score.get('tipo_vulnerabilidad','Desconocido'),
            'en_kev':result['kev'].get('en_kev',False), 'epss_score':score['epss_score'],
            'equipos_afectados':equipos_afectados(inv, result['nvd'].get('productos_afectados',[]),result['nvd'].get('plataformas_afectadas',[]), result['nvd'].get('cpe_afectados',[])),
            'fecha':datetime.now(timezone.utc).isoformat()}

def upstream(url, params):
    def fetch():
        try:
            headers = dict(HEADERS)
            if os.getenv('NVD_API_KEY'): headers['apiKey'] = os.environ['NVD_API_KEY']
            return get_json(url, params=params, headers=headers, timeout=30)
        except (requests.RequestException, ValueError):
            raise HTTPException(502, 'NVD no está disponible. Vuelve a intentarlo en unos instantes.')
    return cached('query:'+json.dumps([url,params],sort_keys=True),1800,fetch)

@app.post('/api/products')
def products(payload: SearchRequest):
    data = upstream('https://services.nvd.nist.gov/rest/json/cpes/2.0', {'keywordSearch':payload.termino,'resultsPerPage':30,'startIndex':payload.inicio})
    return {'total':data.get('totalResults',0),'products':[{'cpe':v['cpe']['cpeName'],'title':next((t['title'] for t in v['cpe'].get('titles',[]) if t['lang']=='en'),v['cpe']['cpeName'])} for v in data.get('products',[]) if not v['cpe'].get('deprecated')]}

@app.post('/api/search')
def search(payload: SearchRequest):
    params = {'resultsPerPage':20,'startIndex':payload.inicio}
    if payload.cpe:
        if not payload.cpe.startswith('cpe:2.3:') or len(payload.cpe.split(':'))<13:
            raise HTTPException(422,'Selecciona un producto CPE válido.')
        params.update(cpeName=payload.cpe, isVulnerable='')
    else: params['keywordSearch']=payload.termino
    data=upstream(NVD_BASE_URL,params)
    cves=[]
    for v in data.get('vulnerabilities',[]):
        c=v['cve']; cvss=seleccionar_cvss(c.get('metrics', {}))['cvss_score']
        cves.append({'cve_id':c['id'],'descripcion':next((d['value'] for d in c.get('descriptions',[]) if d['lang']=='en'),''),'cvss_score':cvss,'fecha_publicacion':c.get('published','')})
    return {'total':data.get('totalResults',0),'cves':cves}

@app.post('/api/inventory/validate')
def validate_inventory(payload: dict):
    try: return Inventory.model_validate(importar_inventario(json.dumps(payload))).model_dump()
    except (ValueError, TypeError, AttributeError): raise HTTPException(422,'El inventario no tiene un formato válido.')

@app.post('/api/sigma')
def sigma(payload: AnalysisRequest, request: Request):
    result=sources(payload.cve_id)
    def generate():
        if not ai_budget(request): return {'error':'Cuota de IA agotada. Inténtalo más tarde.'}
        return generar_regla_sigma(result['nvd'],result['kev'])
    return cached('sigma:v2:'+payload.cve_id,3600,generate)

@app.post('/api/report')
def report(payload: ReportRequest):
    try:
        result=payload.resultado
        if result['nvd']['cve_id'] != payload.cve_id: raise ValueError()
        pdf=generar_pdf(result['nvd'], result['kev'], result['epss'], payload.score, payload.analisis)
    except (KeyError, ValueError, TypeError, AttributeError):
        raise HTTPException(422,'El análisis importado no contiene datos válidos para el informe.')
    return Response(pdf,media_type='application/pdf',headers={'Content-Disposition':f'attachment; filename="VulnSOC-{payload.cve_id}.pdf"'})
