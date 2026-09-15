import unittest
from modules.inventario import equipos_afectados, DATOS_INSUFICIENTES
from modules.scoring import calcular_score, ajustar_por_inventario

CPE = {'criteria': 'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*',
       'versionStartIncluding': '2.0', 'versionEndExcluding': '3.0'}


def inventory(tech='vendor product 2.5'):
    return {'equipos': [{'nombre': 'Server', 'tecnologias': [tech], 'criticidad': 'media'}]}


class InventoryCoverageTests(unittest.TestCase):
    def setUp(self):
        self.base = calcular_score({'cvss_score': 7.5, 'cwes': [], 'descripcion': ''},
                                   {'en_kev': False}, {'epss_score': 0})

    def test_absent_or_unbounded_source_is_not_no_matches(self):
        for matches in [[], [{'criteria': CPE['criteria']}], [{'criteria': 'invalid'}]]:
            with self.subTest(matches=matches):
                result = ajustar_por_inventario(self.base, inventory(), [], [], matches)
                self.assertEqual(result['contexto_inventario'], 'datos_insuficientes')
                self.assertEqual(result['score_interno'], self.base['score_interno'])
                self.assertEqual(result['prioridad'], self.base['prioridad'])
                self.assertTrue(result['provisional'])
                self.assertIn(DATOS_INSUFICIENTES, result['advertencias'])

    def test_product_without_version_coverage_has_explicit_state(self):
        for matches, labels in [([], ['vendor product']), ([{'criteria': CPE['criteria']}], [])]:
            assets = equipos_afectados(inventory(), labels, [], matches)
            self.assertEqual(assets[0]['estado'], 'datos_insuficientes')
            self.assertEqual(assets[0]['limitacion'], DATOS_INSUFICIENTES)

    def test_existing_states_with_source_coverage_are_unchanged(self):
        for tech, expected in [('vendor product 2.5', 'version_compatible'),
                               ('vendor product', 'posible'),
                               ('vendor product 3.0', 'fuera_de_rango')]:
            self.assertEqual(equipos_afectados(inventory(tech), [], [], [CPE])[0]['estado'], expected)
        result = ajustar_por_inventario(self.base, inventory('other product 2.5'), [], [], [CPE])
        self.assertEqual(result['contexto_inventario'], 'sin_coincidencias')
        self.assertEqual(result['score_interno'], self.base['score_interno'])

    def test_compatible_evidence_keeps_points_even_with_incomplete_criteria(self):
        result = ajustar_por_inventario(self.base, inventory(), [], [], [CPE, {'criteria': CPE['criteria']}])
        self.assertEqual(result['contexto_inventario'], 'version_compatible')
        self.assertEqual(result['score_interno'], self.base['score_interno'] + 10)

    def test_no_inventory_still_has_no_inventory_state(self):
        self.assertEqual(ajustar_por_inventario(self.base, {'equipos': []}, [], [], []), self.base)
