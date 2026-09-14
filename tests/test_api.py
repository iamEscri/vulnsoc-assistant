import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend.app import app
from backend import service
from modules.exportar_pdf import generar_pdf
from modules.analisis_ia import generar_analisis

SOURCE={'nvd':{'cve_id':'CVE-2021-44228','descripcion':'Apache Log4j allows remote code execution. <script> & untrusted data.','cvss_score':10.0,'cvss_version':'3.1','fecha_publicacion':'2021-12-10T10:00:00Z','fecha_modificacion':'2026-01-10T10:00:00Z','cwes':['CWE-502'],'productos_afectados':['apache log4j'],'referencias':['https://logging.apache.org/log4j/2.x/security.html','javascript:alert(1)'],'vector_ataque':{'attackVector':'NETWORK'}},'kev':{'en_kev':True,'accion_requerida':'Apply vendor updates.','fecha_limite':'2021-12-24'},'epss':{'epss_score':0.94,'percentil':0.99}}
class ApiTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.db=patch.object(service,'DB',self.tmp.name+'/state.db');self.db.start();self.client=TestClient(app)
 def tearDown(self):self.db.stop();self.tmp.cleanup()
 @patch('backend.app.analizar_cve',return_value=SOURCE)
 def test_analysis_survives_ai_failure_and_exports_pdf(self,source):
  with patch('backend.app.generar_analisis',return_value={'error':'Cuota agotada'}):
   response=self.client.post('/api/analyze',json={'cve_id':'CVE-2021-44228','ia':True})
  self.assertEqual(response.status_code,200)
  result=response.json();self.assertEqual(result['analisis']['error'],'Cuota agotada');self.assertEqual(result['prioridad'],'CRÍTICA')
  pdf=self.client.post('/api/report',json=result)
  self.assertEqual(pdf.status_code,200);self.assertTrue(pdf.content.startswith(b'%PDF-'))
  self.client.post('/api/analyze',json={'cve_id':'CVE-2021-44228'})
  self.assertEqual(source.call_count,1)
 @patch('backend.app.analizar_cve',return_value=SOURCE)
 def test_context_changes_invalidate_ai_cache(self,source):
  response={'resumen_ejecutivo':'Resumen','analisis_tecnico':'Análisis','plan_mitigacion':'Plan'}
  with patch('backend.app.generar_analisis',return_value=response) as ai:
   a={'cve_id':'CVE-2021-44228','ia':True}
   self.client.post('/api/analyze',json=a);self.client.post('/api/analyze',json=a)
   self.assertEqual(ai.call_count,1)
   a['inventario']={'equipos':[{'nombre':'Servidor','tecnologias':['apache log4j']}]}
   self.client.post('/api/analyze',json=a);self.assertEqual(ai.call_count,2)
 def test_validation_and_legacy_inventory(self):
  self.assertEqual(self.client.post('/api/analyze',json={'cve_id':'bad'}).status_code,422)
  r=self.client.post('/api/inventory/validate',json={'software':['Apache'],'sistemas_operativos':['Linux']})
  self.assertEqual(r.status_code,200);self.assertEqual(r.json()['equipos'][0]['nombre'],'General')
  self.assertEqual(self.client.post('/api/inventory/validate',json={'equipos':['bad']}).status_code,422)
  self.assertEqual(self.client.post('/api/report',json={'cve_id':'CVE-2021-44228','resultado':{},'score':{}}).status_code,422)
 def test_quota_durable_and_body_bounded(self):
  self.assertTrue(service.allowance('test',1,60));self.assertFalse(service.allowance('test',1,60))
  self.assertEqual(self.client.post('/api/analyze',content=b'x'*2_000_001).status_code,413)
 @patch('backend.app.upstream')
 def test_version_search_uses_cpe(self,upstream):
  upstream.return_value={'totalResults':0,'vulnerabilities':[]}
  cpe='cpe:2.3:a:apache:tomcat:9.0.80:*:*:*:*:*:*:*'
  self.assertEqual(self.client.post('/api/search',json={'termino':'Apache','cpe':cpe}).status_code,200)
  self.assertEqual(upstream.call_args.args[1]['cpeName'],cpe)
  self.assertIn('isVulnerable',upstream.call_args.args[1])
 def test_existing_ai_sections_and_provider_failure(self):
  result={'resumen_ejecutivo':'Texto','analisis_tecnico':'Texto','plan_mitigacion':'Texto'}
  with patch('modules.analisis_ia._llamar_ia',return_value=json.dumps(result)) as ai:
   self.assertNotIn('error',generar_analisis(SOURCE['nvd'],SOURCE['kev'],{}));self.assertEqual(ai.call_count,3)
  with patch('modules.analisis_ia._llamar_ia',side_effect=RuntimeError('Provider unavailable')):
   self.assertIn('error',generar_analisis(SOURCE['nvd'],SOURCE['kev'],{}))
 def test_sigma_empty_output_is_an_error(self):
  from modules.analisis_ia import generar_regla_sigma
  with patch('requests.get') as get, patch('modules.analisis_ia._llamar_ia',return_value='```yaml\n```'):
   get.return_value.status_code=401
   result=generar_regla_sigma(SOURCE['nvd'],SOURCE['kev'])
  self.assertIn('error',result);self.assertNotIn('regla',result)
 def test_groq_rejects_empty_or_truncated_output(self):
  from types import SimpleNamespace
  from modules.analisis_ia import _llamar_groq
  with patch('modules.analisis_ia._get_groq_client') as client:
   for content,finish in [('', 'stop'), ('partial yaml', 'length')]:
    client.return_value.chat.completions.create.return_value=SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content),finish_reason=finish)])
    with self.assertRaises(ValueError):_llamar_groq('Test')
 def test_contextual_score_uses_policy_and_verified_asset(self):
  from datetime import datetime, timezone
  nvd={**SOURCE['nvd'],'fecha_publicacion':datetime.now(timezone.utc).isoformat(),'vector_ataque':{'attackVector':'NETWORK','privilegesRequired':'NONE','userInteraction':'NONE','attackComplexity':'LOW'},'cpe_afectados':[{'criteria':'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'}]}
  with patch('backend.app.analizar_cve',return_value={**SOURCE,'nvd':nvd}):
   response=self.client.post('/api/analyze',json={'cve_id':'CVE-2021-44228','inventario':{'equipos':[{'nombre':'Servidor','tecnologias':['apache log4j 2.14.1'],'criticidad':'alta','exposicion':'internet'}]}})
  self.assertEqual(response.status_code,200)
  result=response.json();self.assertEqual(result['score_interno'],195);self.assertEqual(result['prioridad'],'CRÍTICA')
  self.assertNotIn('score_mostrado',result);self.assertNotIn('score_mostrado',result['score'])
  from modules.analisis_ia import _construir_contexto
  self.assertIn('195 puntos',_construir_contexto(nvd,SOURCE['kev'],result['score']))
 def test_unknown_sources_export_as_unknown(self):
  from modules.scoring import calcular_score
  nvd={**SOURCE['nvd'],'cvss_score':None}
  kev={'error':'Offline'};epss={'epss_score':None,'estado':'sin_datos'}
  score=calcular_score(nvd,kev,epss)
  self.assertEqual(score['prioridad'],'SIN DETERMINAR')
  response=self.client.post('/api/report',json={'cve_id':nvd['cve_id'],'resultado':{'nvd':nvd,'kev':kev,'epss':epss},'score':score})
  self.assertEqual(response.status_code,200);self.assertTrue(response.content.startswith(b'%PDF-'))
 def test_long_pdf_and_escaped_content(self):
  from modules.scoring import calcular_score
  data={**SOURCE['nvd'],'descripcion':SOURCE['nvd']['descripcion']*150}
  score=calcular_score(data,SOURCE['kev'],SOURCE['epss'])
  pdf=generar_pdf(data,SOURCE['kev'],SOURCE['epss'],score,{'plan_mitigacion':('1. Revisar <host> & proveedor.\n'*100)})
  self.assertTrue(pdf.startswith(b'%PDF-'))
if __name__=='__main__':unittest.main()
