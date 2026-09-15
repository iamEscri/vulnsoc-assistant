import unittest

from modules.evidencia import comparar_version, version_en_rango
from modules.inventario import equipos_afectados


def criterion(product='vendor:product', version='*', update='*', **bounds):
    return {'criteria': f'cpe:2.3:a:{product}:{version}:{update}:*:*:*:*:*:*', 'vulnerable': True, **bounds}


class VersionTests(unittest.TestCase):
    def test_reported_inventory_cases(self):
        # Relevant NVD CPE criteria retrieved 2026-09-15 for CVE-2024-6387.
        ssh = criterion('openbsd:openssh', versionStartIncluding='8.6', versionEndIncluding='9.8')
        ssh_matches = [ssh, criterion('openbsd:openssh', version='8.5', update='p1'),
                       criterion('openbsd:openssh', versionEndExcluding='4.4'),
                       criterion('openbsd:openssh', version='4.4', update='-'),
                       criterion('openbsd:openssh', version='8.6', update='-')]
        # Relevant NVD criteria for CVE-2021-44228; prereleases use CPE update.
        log = criterion('apache:log4j', version='2.0', update='beta9')
        log_later = criterion('apache:log4j', versionStartIncluding='2.13.0', versionEndExcluding='2.15.0')
        for tech, matches, expected in [
            ('OpenSSH 8.9', ssh_matches, 'version_compatible'),
            ('OpenSSH 8.5p1', ssh_matches, 'version_compatible'),
            ('OpenSSH 9.8p1', ssh_matches, 'fuera_de_rango'),
            ('Apache Log4j 2.14.1', [log, log_later], 'version_compatible'),
            ('Apache Log4j 2.0-beta9', [log, log_later], 'version_compatible'),
            ('Apache Log4j 2.0-beta8', [log, log_later], 'fuera_de_rango'),
            ('OpenSSH', ssh_matches, 'posible'),
        ]:
            with self.subTest(tech=tech):
                assets = equipos_afectados({'equipos': [{'nombre': 'Test', 'tecnologias': [tech]}]}, [], [], matches)
                self.assertEqual(assets[0]['estado'], expected)

    def test_release_order_and_numeric_regressions(self):
        for a, b in [('2.0-alpha2', '2.0-beta1'), ('2.0-beta9', '2.0-beta10'),
                     ('2.0-beta10', '2.0-rc1'), ('2.0-rc1', '2.0'),
                     ('2.0', '2.0p1'), ('2.0p2', '2.0p10'), ('8.9', '8.10')]:
            with self.subTest(a=a, b=b):
                self.assertEqual(comparar_version(a, b), -1)
                self.assertEqual(comparar_version(b, a), 1)
        self.assertEqual(comparar_version('2.0.0', '2'), 0)
        self.assertEqual(comparar_version('2.0beta9', '2.0-beta9'), 0)

    def test_bound_inclusivity(self):
        for bound, expected in [('versionStartIncluding', True), ('versionStartExcluding', False),
                                ('versionEndIncluding', True), ('versionEndExcluding', False)]:
            self.assertIs(version_en_rango('2.0-rc1', criterion(**{bound: '2.0-rc1'})), expected)

    def test_cpe_update_is_preserved_on_both_sides(self):
        match = criterion(version='2.0', update='beta9')
        self.assertTrue(version_en_rango('2.0-beta9', match))
        self.assertFalse(version_en_rango('2.0', match))
        self.assertTrue(version_en_rango('2.0-beta9', criterion(version=r'2.0\-beta9')))
        self.assertIsNone(version_en_rango('2.0-beta9', criterion(update='beta9')))
        for update, expected in [('beta9', 'version_compatible'), ('beta8', 'fuera_de_rango')]:
            tech = criterion(version='2.0', update=update)['criteria']
            assets = equipos_afectados({'equipos': [{'nombre': 'Test', 'tecnologias': [tech]}]}, [], [], [match])
            self.assertEqual(assets[0]['estado'], expected)

    def test_unknown_schemes_and_conditions_stay_unverified(self):
        match = criterion(versionStartIncluding='2.0', versionEndExcluding='3.0')
        for version in [None, '*', '-', '2.1-vendor7', '2.1p1-3.el9', '2.1+build7']:
            self.assertIsNone(version_en_rango(version, match))
        self.assertIsNone(version_en_rango('2.1p1', {**match, 'condicional': True}))
        self.assertIsNone(version_en_rango('2.1', criterion(version='2.1', update='vendor7')))
        constrained = criterion(version='2.1')
        constrained['criteria'] = 'cpe:2.3:a:vendor:product:2.1:*:*:*:*:linux:*:*'
        self.assertIsNone(version_en_rango('2.1', constrained))
