import unittest
from unittest.mock import patch
from modules.scoring import calcular_score, ajustar_por_inventario, _detectar_tipo_vulnerabilidad
from modules.evidencia import seleccionar_cvss, extraer_cpes, version_en_rango
from modules.inventario import equipos_afectados, importar_inventario
from modules.ingesta import obtener_epss, obtener_datos_nvd

CPE = {'criteria':'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*','vulnerable':True,'versionStartIncluding':'2.0','versionEndExcluding':'2.15.0'}
NVD = {'cvss_score':9.8,'cvss_version':'3.1','descripcion':'remote code execution','cwes':['CWE-502'],'vector_ataque':{'attackVector':'NETWORK','privilegesRequired':'NONE','userInteraction':'NONE','attackComplexity':'LOW'}}

def asset(technology, criticality='alta', exposure='internet'):
    return {'equipos':[{'nombre':'Servidor','tecnologias':[technology],'criticidad':criticality,'exposicion':exposure}]}

class MethodologyTests(unittest.TestCase):
    def test_published_guide_examples_match_engine(self):
        import json
        from pathlib import Path
        examples = json.loads((Path(__file__).resolve().parents[1] / 'frontend/src/examples/scoring-policy.json').read_text())
        for example in examples:
            with self.subTest(example=example['title']):
                score = calcular_score({'cvss_score': example['cvss']}, {'en_kev': example['kev']}, {'epss_score': example['epss']})
                if example['context']:
                    score = ajustar_por_inventario(score, asset('Apache Log4j 2.14.1'), ['apache log4j'], [], [CPE])
                self.assertEqual((score['score_interno'], score['prioridad']), (example['points'], example['priority']))
                self.assertEqual(sum(step['points'] for step in example['steps']), score['score_interno'])

    def test_no_double_count_and_no_type_bonus(self):
        score = calcular_score(NVD, {'en_kev':False}, {'epss_score':.001})
        self.assertEqual((score['score_interno'],score['prioridad']), (98,'ALTA'))
        other = calcular_score({**NVD,'vector_ataque':{},'cwes':[],'descripcion':''}, {'en_kev':False}, {'epss_score':.001})
        self.assertEqual(score['score_interno'],other['score_interno'])
    def test_known_exploitation_supersedes_prediction(self):
        scores=[calcular_score(NVD,{'en_kev':True},{'epss_score':p}) for p in [0,.001,.99,1]]
        self.assertEqual({s['score_interno'] for s in scores},{158})
        self.assertTrue(all(s['prioridad']=='CRÍTICA' for s in scores))
    def test_epss_policy_boundaries(self):
        scores=[calcular_score({**NVD,'cvss_score':5}, {'en_kev':False},{'epss_score':p})['score_interno'] for p in [0,.0099,.01,.0999,.1,.6999,.7,1]]
        self.assertEqual(scores,[50,50,60,60,70,70,80,80])
    def test_missing_is_not_zero(self):
        missing=calcular_score({}, {}, {'epss_score':None})
        self.assertEqual(missing['prioridad'],'SIN DETERMINAR');self.assertTrue(missing['provisional'])
        zero=calcular_score({'cvss_score':0},{'en_kev':False},{'epss_score':0})
        self.assertEqual(zero['prioridad'],'BAJA');self.assertFalse(zero['provisional'])
    def test_kev_minimum_when_cvss_missing(self):
        score=calcular_score({}, {'en_kev':True},{'epss_score':0})
        self.assertEqual(score['score_interno'],90);self.assertEqual(score['prioridad'],'ALTA');self.assertTrue(score['provisional'])
    def test_failures_cannot_override_known_data(self):
        score=calcular_score(NVD,{'error':'Offline','en_kev':True},{'epss_score':1,'error':'Offline'})
        self.assertEqual(score['score_interno'],98);self.assertTrue(score['provisional']);self.assertIsNone(score['epss_score'])
    def test_source_substrings_do_not_mean_rce(self):
        self.assertEqual(_detectar_tipo_vulnerabilidad([],'An open source library for source code.'),('Desconocido',0))
        self.assertEqual(_detectar_tipo_vulnerabilidad(['CWE-20'],'Input validation')[0],'Validación de entrada')
        self.assertEqual(_detectar_tipo_vulnerabilidad(['CWE-502'],'Deserialization')[0],'Deserialización')
        self.assertEqual(_detectar_tipo_vulnerabilidad([],'Remote code execution is possible.')[0],'RCE (inferido)')
    def test_vendor_match_never_confirms_product(self):
        self.assertEqual(equipos_afectados(asset('Apache Tomcat 9.0.80'),['apache log4j'],[],[CPE]),[])
        self.assertEqual(equipos_afectados(asset('Apache'),['apache log4j'],[],[CPE]),[])
    def test_numeric_ranges_and_ambiguous_versions(self):
        for version,expected in [('1.9',False),('2.0',True),('2.14.1',True),('2.15.0',False),('2.15.0-rc1',None),(None,None)]:
            with self.subTest(version=version):self.assertIs(version_en_rango(version,CPE),expected)
        self.assertIsNone(version_en_rango('2.14.1',{**CPE,'condicional':True}))
    def test_context_requires_version_and_never_deducts(self):
        base=calcular_score(NVD,{'en_kev':False},{'epss_score':0})
        for tech in ['Apache Tomcat 9.0.80','Apache Log4j','Apache Log4j 2.15.0']:
            adjusted=ajustar_por_inventario(base,asset(tech),['apache log4j'],[],[CPE])
            self.assertEqual(adjusted['score_interno'],98);self.assertTrue(adjusted['provisional'])
        matched=ajustar_por_inventario(base,asset('Apache Log4j 2.14.1'),['apache log4j'],[],[CPE])
        self.assertEqual(matched['score_interno'],133)
        internal=ajustar_por_inventario(base,asset('Apache Log4j 2.14.1','baja','interna'),['apache log4j'],[],[CPE])
        self.assertEqual(internal['score_interno'],103)
    def test_multiple_assets_do_not_inflate_or_combine_context(self):
        base=calcular_score(NVD,{'en_kev':False},{'epss_score':0})
        inventory={'equipos':asset('Apache Log4j 2.14.1','alta','interna')['equipos']+asset('Apache Log4j 2.14.1','baja','internet')['equipos']*20}
        adjusted=ajustar_por_inventario(base,inventory,['apache log4j'],[],[CPE])
        self.assertEqual(adjusted['score_interno'],118)
    def test_recursive_and_cpes_are_conservative(self):
        configs=[{'operator':'AND','nodes':[{'operator':'OR','children':[{'cpeMatch':[CPE]}]}]}]
        result=extraer_cpes(configs)
        self.assertTrue(result[0]['condicional']);self.assertIsNone(version_en_rango('2.14.1',result[0]))
    def test_cvss4_and_primary_precedence(self):
        data={'cvssMetricV40':[{'type':'Secondary','cvssData':{'baseScore':4}},{'type':'Primary','source':'nvd@nist.gov','cvssData':{'baseScore':9.3,'attackVector':'NETWORK'}}],'cvssMetricV31':[{'cvssData':{'baseScore':10}}]}
        chosen=seleccionar_cvss(data);self.assertEqual(chosen['cvss_score'],9.3);self.assertEqual(chosen['cvss_version'],'4.0')
        with patch('modules.ingesta.get_json',return_value={'totalResults':1,'vulnerabilities':[{'cve':{'metrics':data}}]}):
            self.assertEqual(obtener_datos_nvd('CVE-2021-44228')['cvss_score'],chosen['cvss_score'])
    def test_epss_empty_zero_and_error(self):
        for body, expected in [({'data':[]},None),({'data':[{'epss':'0','percentile':'0','date':'2026-09-13'}]},0),({'data':[{'epss':'nan','percentile':'0'}]},None)]:
            with patch('modules.ingesta.get_json',return_value=body):self.assertEqual(obtener_epss('CVE-2021-44228')['epss_score'],expected)
    def test_future_recency_never_awards_points(self):
        s=calcular_score({**NVD,'fecha_publicacion':'2999-01-01'}, {'en_kev':False},{'epss_score':0})
        self.assertEqual(s['score_interno'],98);self.assertTrue(s['provisional'])
    def test_legacy_inventory_exposure_unknown(self):
        self.assertEqual(importar_inventario('{"software":["Apache"]}')['equipos'][0]['exposicion'],'desconocida')

if __name__=='__main__':unittest.main()
