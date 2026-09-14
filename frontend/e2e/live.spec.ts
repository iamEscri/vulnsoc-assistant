import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';

// Explicit opt-in: uses real sources and the configured AI provider/quota.
test('live API analysis, AI, Sigma and PDF through the interface',async({page})=>{
 test.skip(process.env.VULNSOC_LIVE!=='1','Requires running API, network and configured AI provider.');
 test.setTimeout(240_000);
 await page.goto('/');
 await page.getByLabel('Identificador CVE').fill('CVE-2021-44228');
 await page.getByRole('button',{name:'Investigar',exact:true}).click();
 await expect(page.getByRole('heading',{name:'CVE-2021-44228',exact:true})).toBeVisible({timeout:90_000});
 await expect(page.locator('.internal-number')).not.toContainText('—');
 await page.getByRole('tab',{name:'Análisis con IA',exact:true}).click();
 await page.getByRole('button',{name:'Generar análisis',exact:true}).click();
 await expect(page.locator('.generated-text').first()).toBeVisible({timeout:120_000});
 await page.getByRole('tab',{name:'Detección Sigma',exact:true}).click();
 await page.getByRole('button',{name:'Obtener regla',exact:true}).click();
 await expect(page.locator('pre')).toContainText('title:',{timeout:90_000});
 const yamlDownload=page.waitForEvent('download');
 await page.getByRole('button',{name:'Descargar YAML',exact:true}).click();
 expect((await yamlDownload).suggestedFilename()).toBe('CVE-2021-44228.yml');
 const pdfResponse=page.waitForResponse(r=>r.url().endsWith('/api/report'));
 const pdfDownload=page.waitForEvent('download');
 await page.getByRole('button',{name:'Exportar informe PDF',exact:true}).click();
 const response=await pdfResponse;expect(response.ok()).toBe(true);
 const pdf=await pdfDownload;await pdf.saveAs('artifacts/live-report.pdf');
 expect((await readFile('artifacts/live-report.pdf')).subarray(0,5).toString()).toBe('%PDF-');
 expect(pdf.suggestedFilename()).toBe('VulnSOC-CVE-2021-44228.pdf');
 await page.screenshot({path:'artifacts/live-sigma.png',fullPage:true});
});
