import copy
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from reportlab.platypus import Paragraph, Table
from modules.exportar_pdf import generar_pdf, _styles, WIDTH
from modules.pdf_markdown import markdown_flowables

EXAMPLE = json.loads((Path(__file__).resolve().parents[1] / 'frontend/src/examples/log4shell.json').read_text())


class PDFTests(unittest.TestCase):
    def export(self, entry, analysis=None, **kwargs):
        return generar_pdf(entry['resultado']['nvd'], entry['resultado']['kev'], entry['resultado']['epss'], entry['score'], analysis or {}, **kwargs)

    def text(self, pdf):
        if not shutil.which('pdftotext'): self.skipTest('PDF text checks require Poppler pdftotext')
        return subprocess.run(['pdftotext', '-', '-'], input=pdf, stdout=subprocess.PIPE, check=True).stdout.decode()

    def test_source_traceability_assets_and_no_ai(self):
        entry = copy.deepcopy(EXAMPLE)
        entry['resultado']['nvd']['descripcion'] += '\n\nFIN DE LA DESCRIPCIÓN COMPLETA'
        entry['resultado']['nvd']['referencias'] = ['https://example.com/advisory?a=1&b=2', 'javascript:alert(1)']
        pdf = self.export(entry, equipos_afectados=[{'nombre':'Servidor de producción', 'estado':'version_compatible', 'criticidad':'alta','exposicion':'internet','coincidencias':['Apache Log4j 2.14.1']}], fecha_analisis='2026-09-14T10:30:00Z')
        text = self.text(pdf)
        for value in ['VulnSOC','160','CRÍTICA','FIN DE LA DESCRIPCIÓN COMPLETA','Servidor de producción','14/09/2026 10:30 UTC','No se ha generado análisis con IA','https://example.com/advisory?a=1&b=2']:
            self.assertIn(value, text)
        self.assertNotIn('CONFIDENCIAL', text)
        self.assertNotIn('javascript:', text)
        self.assertTrue(pdf.startswith(b'%PDF-'))

    def test_unknown_and_legacy_scores_are_not_recalculated(self):
        entry=copy.deepcopy(EXAMPLE)
        entry['score']={'score_interno':225,'prioridad':'CRÍTICA','factores':[{'factor':'Histórico','puntos':210,'detalle':'Datos heredados'}]}
        text=self.text(self.export(entry))
        self.assertIn('225',text); self.assertIn('Desglose parcial',text);self.assertIn('no se aplican los umbrales actuales',text)
        entry['score']={'score_interno':0,'prioridad':'SIN DETERMINAR','factores':[]}
        entry['resultado']['nvd']['cvss_score']=None
        entry['resultado']['kev']={'error':'Offline'}
        entry['resultado']['epss']={'epss_score':None}
        text=self.text(self.export(entry))
        self.assertIn('Sin determinar',text);self.assertIn('Sin verificar',text);self.assertIn('Sin datos',text)
        self.assertNotIn('0.0%',text)

    def test_markdown_is_structured_and_does_not_fetch_resources(self):
        text='**Resumen ejecutivo**\n\n**Hallazgo** y *contexto*.\n\n| Factor | Puntos |\n| --- | --- |\n| KEV | 60 |\n\n```yaml\ntitle: Example\n```\n\n[Enlace](javascript:alert%281%29)\n\n<img src="https://example.com/pixel"/>\n\n![alt](https://example.com/image.png)'
        flows=markdown_flowables(text,_styles(),WIDTH,skip_title='Resumen ejecutivo')
        self.assertTrue(any(isinstance(f,Table) for f in flows))
        paragraphs=' '.join(f.text for f in flows if isinstance(f,Paragraph))
        self.assertIn('<b>Hallazgo</b>',paragraphs)
        self.assertNotIn('<a href="javascript:',paragraphs)
        self.assertNotIn('<img ',paragraphs)
        self.assertNotIn('###',paragraphs)
        self.assertNotIn('Resumen ejecutivo',paragraphs)
        pdf=self.export(EXAMPLE,{'resumen_ejecutivo':text})
        rendered=self.text(pdf)
        self.assertIn('title: Example',rendered)
        self.assertNotIn('| --- |',rendered)

    def test_long_tables_code_and_lists_survive_page_breaks(self):
        cell='Evidencia detallada del proveedor. '*180
        markdown='| Factor | Evidencia |\n| --- | --- |\n| KEV | '+cell+' |\n\n'
        markdown+='1. Validar versión\n   - Revisar configuración\n\n```text\n'+'línea larga '+'x'*500+'\n'+'verificar\n'*100+'FIN_CODIGO\n```\n\nFIN_ANEXO'
        text=self.text(self.export(EXAMPLE,{'analisis_tecnico':markdown}))
        self.assertIn('FIN_CODIGO',text);self.assertIn('FIN_ANEXO',text)
        self.assertEqual(' '.join(text.split()).count('Evidencia detallada del proveedor.'),180)

    def test_wide_tables_become_labelled_records(self):
        markdown='| A | B | C | D | E | F |\n| --- | --- | --- | --- | --- | --- |\n| 1 | 2 | 3 | 4 | 5 | 6 |'
        text=self.text(self.export(EXAMPLE,{'plan_mitigacion':markdown}))
        self.assertIn('Tabla extensa',text);self.assertIn('Registro 1',text);self.assertIn('F: 6',text)


if __name__=='__main__': unittest.main()
