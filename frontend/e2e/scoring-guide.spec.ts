import { test, expect } from '@playwright/test';

test('methodology explains examples without changing history and fits mobile', async ({ page }) => {
 await page.goto('/');
 await page.getByRole('button', { name: 'Metodología', exact: true }).click();
 await expect(page.getByRole('heading', { name: 'Metodología y fuentes' })).toBeVisible();
 const examples = page.getByRole('region', { name: 'Ejemplos de scoring' });
 await expect(examples.getByText('72 puntos · MEDIA', { exact: true })).toBeVisible();
 await page.getByLabel('Explora un ejemplo').selectOption('2');
 await expect(examples.getByText('160 puntos · CRÍTICA', { exact: true })).toBeVisible();
 await page.getByLabel('Explora un ejemplo').selectOption('3');
 await expect(examples.getByText('133 puntos · CRÍTICA', { exact: true })).toBeVisible();
 await expect(examples.getByRole('heading', { name: 'Criticidad alta del mismo activo' })).toBeVisible();
 await page.setViewportSize({ width: 1440, height: 1000 });
 const thresholds = page.getByRole('region', { name: 'Umbrales de prioridad' });
 await thresholds.screenshot({ path: 'artifacts/methodology-thresholds.png' });
 await examples.screenshot({ path: 'artifacts/methodology-example.png' });
 await expect(page.getByRole('navigation', { name: 'Contenido de la metodología' })).toBeVisible();
 for (const id of ['start', 'sources', 'scoring', 'assets', 'report', 'data']) {
  await page.locator(`a[href="#method-${id}"]`).click();
  await expect(page.locator(`#method-${id}`)).toBeInViewport();
 }
 await page.setViewportSize({ width: 390, height: 844 });
 expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
 expect(await thresholds.locator('strong').first().evaluate(element => parseFloat(getComputedStyle(element).fontSize))).toBeGreaterThanOrEqual(28);
 await page.screenshot({ path: 'artifacts/scoring-guide-mobile.png', fullPage: true });
 await page.getByRole('button', { name: /^Historial/ }).click();
 await expect(page.getByText('Sin análisis que mostrar')).toBeVisible();
 await page.getByRole('button', { name: 'Vista general', exact: true }).click();
 await expect(page.getByText('EPSS informativo: KEV tiene precedencia.', { exact: true })).toBeVisible();
 await page.getByText('Entender el scoring · reglas y ejemplos', { exact: true }).click();
 await expect(page.getByLabel('Explora un ejemplo')).toBeVisible();
});
