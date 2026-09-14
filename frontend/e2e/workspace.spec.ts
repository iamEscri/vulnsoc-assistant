import { test, expect } from '@playwright/test';
const fixture={cve_id:'CVE-2021-44228',prioridad:'CRÍTICA',score_mostrado:100,score_interno:180,tipo:'RCE',en_kev:true,epss_score:.94,fecha:'2026-09-11T12:00:00Z',resultado:{nvd:{cve_id:'CVE-2021-44228',descripcion:'Apache Log4j permite la ejecución remota de código. Comprueba las versiones y los avisos del proveedor.',cvss_score:10,cvss_version:'3.1',fecha_publicacion:'2021-12-10',referencias:['https://logging.apache.org/log4j/2.x/security.html'],cwes:['CWE-502'],productos_afectados:['Apache Log4j'],vector_ataque:{attackVector:'NETWORK'}},kev:{en_kev:true,accion_requerida:'Aplicar las actualizaciones del proveedor.'},epss:{epss_score:.94}},score:{score_mostrado:100,score_interno:180,prioridad:'CRÍTICA',factores:[{factor:'CVSS base',puntos:100,detalle:'CVSS 3.1 = 10'},{factor:'CISA KEV',puntos:30,detalle:'Explotación activa confirmada'},{factor:'EPSS alto',puntos:25,detalle:'Probabilidad de explotación elevada'},{factor:'Tipo RCE',puntos:25,detalle:'Ejecución remota de código'}]},analisis:{}};
test('analysis, persistent history, exports and responsive intelligence interface',async({page})=>{
 const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/api/analyze',r=>r.fulfill({json:fixture}));
 await page.emulateMedia({reducedMotion:'reduce'});await page.setViewportSize({width:1440,height:1000});await page.goto('/');
 await expect(page.getByText('Guardado en este dispositivo',{exact:true}).first()).toBeVisible();
 await page.screenshot({path:'artifacts/precision-empty.png',fullPage:true});
 await page.getByLabel('Identificador CVE').fill('CVE-2021-44228');await page.getByRole('button',{name:'Investigar',exact:true}).click();
 await expect(page.getByRole('heading',{name:'CVE-2021-44228',exact:true})).toBeVisible();
 await page.getByRole('tab',{name:'Evidencias y scoring'}).click();await expect(page.getByText('Cómo se calcula la prioridad')).toBeVisible();
 await page.getByRole('tab',{name:'Resumen',exact:true}).click();await page.screenshot({path:'artifacts/precision-detail.png',fullPage:true});
 await page.reload();await page.getByRole('button',{name:/^Historial/}).click();await expect(page.getByRole('button',{name:'CVE-2021-44228',exact:true})).toBeVisible();
 const downloaded=page.waitForEvent('download');await page.getByRole('button',{name:'Exportar',exact:true}).click();expect((await downloaded).suggestedFilename()).toBe('historial_vulnsoc.json');
 await page.getByRole('button',{name:'Inventario de activos',exact:true}).click();await page.getByRole('button',{name:'Añadir activo'}).click();await page.getByLabel('Nombre del activo').fill('Servidor de producción');await page.getByLabel('Tecnologías · una por línea').fill('Apache Log4j 2.14.1');await page.getByRole('button',{name:'Guardar activo'}).click();await expect(page.getByRole('heading',{name:'Servidor de producción'})).toBeVisible();
 await page.reload();await page.getByRole('button',{name:'Inventario de activos',exact:true}).click();await expect(page.getByRole('heading',{name:'Servidor de producción'})).toBeVisible();
 await page.getByRole('button',{name:'Vista general',exact:true}).click();await page.screenshot({path:'artifacts/precision-desktop.png',fullPage:true});
 await page.emulateMedia({reducedMotion:'reduce'});await page.setViewportSize({width:390,height:844});await expect(page.locator('aside,.sidebar,.avatar,.workspace')).toHaveCount(0);await page.screenshot({path:'artifacts/precision-mobile.png',fullPage:true});expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await page.getByRole('button',{name:/^Historial/}).click();await expect(page.getByRole('heading',{name:'Historial de análisis'})).toBeVisible();expect(errors).toEqual([]);
});
test('version lookup, AI failure, batch partial failures and legacy imports',async({page})=>{
 await page.route('**/api/products',r=>r.fulfill({json:{total:1,products:[{title:'Apache Tomcat 9.0.80',cpe:'cpe:2.3:a:apache:tomcat:9.0.80:*:*:*:*:*:*:*'}]}}));
 await page.route('**/api/search',r=>{expect(r.request().postDataJSON().cpe).toContain('9.0.80');return r.fulfill({json:{total:1,cves:[{cve_id:'CVE-2021-44228',descripcion:'Resultado de prueba',cvss_score:10,fecha_publicacion:'2021-12-10'}]}});});
 await page.route('**/api/analyze',r=>{const body=r.request().postDataJSON();return body.cve_id==='CVE-2023-44487'?r.fulfill({status:502,json:{detail:'Fuente temporalmente no disponible'}}):r.fulfill({json:{...fixture,analisis:body.ia?{error:'Cuota de IA agotada'}:{}}});});
 await page.goto('/');await page.getByRole('button',{name:'Explorar vulnerabilidades',exact:true}).click();await page.getByRole('button',{name:'Tecnología y versión'}).click();await page.getByLabel('Tecnología o fabricante').fill('Apache Tomcat');await page.getByLabel('Versión',{exact:true}).fill('9.0.80');await page.getByRole('button',{name:'Buscar',exact:true}).click();await page.getByRole('button',{name:/Apache Tomcat 9.0.80/}).click();await page.getByRole('button',{name:'Analizar vulnerabilidad',exact:true}).click();await page.getByRole('tab',{name:'Análisis con IA'}).click();await page.getByRole('button',{name:'Generar análisis'}).click();await expect(page.getByText('Cuota de IA agotada',{exact:true})).toBeVisible();await expect(page.getByRole('button',{name:'Exportar informe PDF'})).toBeEnabled();
 await page.getByRole('button',{name:'Análisis múltiple',exact:true}).click();await page.getByLabel('Identificadores CVE').fill('CVE-2021-44228\nCVE-2023-44487');await page.getByRole('button',{name:'Analizar lote'}).click();await expect(page.getByText('CVE-2023-44487: Fuente temporalmente no disponible')).toBeVisible();await expect(page.getByRole('heading',{name:'Comparativa de prioridad'})).toBeVisible();
 await page.getByRole('button',{name:/^Historial/}).click();await page.locator('input[type=file]').setInputFiles({name:'legacy.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify([fixture]))});await expect(page.getByText('Importación completada.',{exact:false})).toBeVisible();await expect(page.getByRole('button',{name:'CVE-2021-44228',exact:true})).toHaveCount(1);
 await page.locator('input[type=file]').setInputFiles({name:'invalid.json',mimeType:'application/json',buffer:Buffer.from('{"invalid":true}')});await expect(page.getByRole('alert')).toBeVisible();
});

test('navigation, Sigma, PDF and reduced motion',async({page})=>{
 await page.emulateMedia({reducedMotion:'reduce'});await page.setViewportSize({width:360,height:800});
 await page.route('**/api/analyze',r=>r.fulfill({json:fixture}));
 await page.route('**/api/sigma',r=>r.fulfill({json:{regla:'title: Detection example\nstatus: experimental',advertencia:'Borrador pendiente de validación.'}}));
 await page.route('**/api/report',r=>r.fulfill({contentType:'application/pdf',body:'%PDF-1.4 test fixture'}));
 await page.goto('/');
 const nav=page.getByRole('navigation',{name:'Navegación principal'});await expect(nav.getByRole('button')).toHaveCount(5);
 for(const [name,title] of [['Explorar vulnerabilidades','Explorar vulnerabilidades'],['Análisis múltiple','Análisis múltiple'],['Inventario de activos','Inventario de activos'],['Historial','Historial de análisis'],['Vista general','Vista general']]){await nav.getByRole('button',{name:new RegExp(name)}).click();await expect(nav.getByRole('button',{name:new RegExp(name)})).toHaveAttribute('aria-current','page');if(name!=='Vista general')await expect(page.getByRole('heading',{name:title,exact:true})).toBeVisible();expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);}
 await page.getByLabel('Identificador CVE').fill('CVE-2021-44228');await page.getByRole('button',{name:'Investigar',exact:true}).click();await page.getByRole('tab',{name:'Detección Sigma'}).click();await page.getByRole('button',{name:'Obtener regla'}).click();await expect(page.locator('pre')).toContainText('Detection example');const yaml=page.waitForEvent('download');await page.getByRole('button',{name:'Descargar YAML'}).click();expect((await yaml).suggestedFilename()).toBe('CVE-2021-44228.yml');const pdf=page.waitForEvent('download');await page.getByRole('button',{name:'Exportar informe PDF'}).click();expect((await pdf).suggestedFilename()).toBe('VulnSOC-CVE-2021-44228.pdf');
 await page.getByRole('button',{name:'Metodología',exact:true}).click();await expect(page.getByRole('heading',{name:'Metodología y fuentes'})).toBeVisible();
});

test('score waterfall preserves positive, negative and zero contributions',async({page})=>{
 const entry={...fixture,score_interno:105,prioridad:'ALTA',score:{...fixture.score,score_interno:105,prioridad:'ALTA',factores:[{factor:'CVSS base',puntos:100,detalle:'CVSS 3.1 = 10'},{factor:'CISA KEV',puntos:30,detalle:'Explotación activa confirmada'},{factor:'Inventario',puntos:-25,detalle:'Producto no detectado en el inventario'},{factor:'Sin datos adicionales',puntos:0,detalle:'La ausencia de datos no es ausencia de riesgo'}]}};
 await page.route('**/api/analyze',r=>r.fulfill({json:entry}));await page.goto('/');
 const cve=page.getByLabel('Identificador CVE');await expect(cve).toBeVisible();const box=await cve.boundingBox();expect(box!.y+box!.height).toBeLessThan(720);
 await cve.fill(entry.cve_id);await page.getByRole('button',{name:'Investigar',exact:true}).click();
 const chart=page.getByRole('region',{name:'Desglose del VulnSOC Score'});await expect(chart.locator('.internal-number')).toContainText('105');await expect(chart.locator('.accumulated-value')).toHaveText(['100','130','105','105']);await expect(chart.locator('.waterfall-bar.deduction')).toHaveCount(1);await expect(chart.locator('.waterfall-bar.zero')).toHaveCount(1);
 await chart.getByRole('button',{name:/Inventario/}).click();await expect(chart.getByText('Producto no detectado en el inventario')).toBeVisible();await chart.getByRole('button',{name:/Sin datos adicionales/}).focus();await page.keyboard.press('Enter');await expect(chart.getByText('La ausencia de datos no es ausencia de riesgo')).toBeVisible();
 await page.getByRole('tab',{name:'Mitigación',exact:true}).click();await expect(page.getByRole('heading',{name:'Plan de mitigación',exact:true})).toBeVisible();await expect(page.getByRole('button',{name:'Consultar referencias'})).toBeVisible();
 await expect(page.locator('.field-art,canvas,.ticker,.footer-word,.sidebar')).toHaveCount(0);const footer=await page.locator('footer').boundingBox();expect(footer!.height).toBeLessThan(150);
});

test('explanatory flow can pause and respects reduced motion without fabricating analysis',async({page})=>{
 await page.setViewportSize({width:1440,height:1000});await page.emulateMedia({reducedMotion:'no-preference'});await page.goto('/');
 const flow=page.getByRole('figure',{name:'Flujo de priorización de VulnSOC'});
 await expect(flow.getByText('Ejemplo ilustrativo · CRÍTICA, 160 puntos',{exact:true})).toBeVisible();
 await expect(page.locator('.internal-number')).toHaveText('160pts');
 await expect(page.getByText('Ejemplo preanalizado ·',{exact:false})).toBeVisible();
 await flow.getByRole('button',{name:'Pausar animación'}).click();
 expect(await flow.locator('.flow-pulse').first().evaluate(el=>getComputedStyle(el).animationPlayState)).toBe('paused');
 await flow.getByRole('button',{name:'Reanudar animación'}).click();
 expect(await flow.locator('.flow-pulse').first().evaluate(el=>getComputedStyle(el).animationPlayState)).toBe('running');
 await page.emulateMedia({reducedMotion:'reduce'});
 expect(await flow.locator('.flow-result').evaluate(el=>getComputedStyle(el).animationName)).toBe('none');
 await expect(flow.locator('.flow-pulse').first()).toBeHidden();
 await page.setViewportSize({width:390,height:844});await expect(flow.locator('.flow-mobile')).toBeVisible();await expect(flow.locator('svg[role=img]')).toBeHidden();
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await page.route('**/api/analyze',r=>r.fulfill({json:fixture}));await page.getByLabel('Identificador CVE').fill(fixture.cve_id);await page.getByRole('button',{name:'Investigar',exact:true}).click();
 await expect(page.locator('.internal-number')).toHaveText('180pts');await expect(page.locator('.visible-score,.score-orbit')).toHaveCount(0);
 await page.getByRole('button',{name:'Vista general',exact:true}).click();await expect(flow.getByText('Referencia local · CVE-2021-44228',{exact:true})).toBeVisible();await expect(flow.getByText('Ejemplo ilustrativo · CRÍTICA, 160 puntos',{exact:true})).toHaveCount(0);
});


test('preanalysed examples stay separate from history and asset criticality is semantic',async({page})=>{
 await page.goto('/');
 const examples=page.getByRole('group',{name:'Seleccionar CVE de ejemplo'});
 await expect(examples).toBeVisible();await expect(page.locator('.internal-number')).toHaveText('160pts');
 await examples.getByRole('button',{name:/CVE-2023-48795/}).click();await expect(page.locator('.internal-number')).toHaveText('89pts');
 await expect(page.getByText('Sin análisis que mostrar',{exact:true})).toBeVisible();
 await page.reload();await page.getByRole('button',{name:'Historial',exact:true}).click();await expect(page.getByRole('heading',{name:'0 análisis guardados'})).toBeVisible();
 await page.getByRole('button',{name:'Inventario de activos',exact:true}).click();await page.getByRole('button',{name:'Añadir activo'}).click();
 const criticality=page.getByLabel('Criticidad',{exact:true});await expect(criticality).toHaveAttribute('data-criticality','media');
 const medium=await criticality.evaluate(el=>getComputedStyle(el).color);
 await criticality.selectOption('baja');const low=await criticality.evaluate(el=>getComputedStyle(el).color);
 await criticality.selectOption('alta');const high=await criticality.evaluate(el=>getComputedStyle(el).color);expect(new Set([medium,low,high]).size).toBe(3);
 await page.getByLabel('Nombre del activo').fill('Servidor crítico');await page.getByRole('button',{name:'Guardar activo'}).click();await expect(page.locator('.asset-card .asset-criticality')).toHaveAttribute('data-criticality','alta');
 await page.getByRole('button',{name:'Vista general',exact:true}).click();
 await page.route('**/api/analyze',r=>r.fulfill({json:fixture}));await page.getByRole('button',{name:'Analizar con datos actuales'}).click();await expect(page.getByRole('heading',{name:'CVE-2021-44228',exact:true})).toBeVisible();
 await page.getByRole('button',{name:'Historial',exact:true}).click();await expect(page.getByRole('heading',{name:'1 análisis guardados'})).toBeVisible();
});

test('unknown evidence stays unknown in detail and history',async({page})=>{
 const unknown={...fixture,score_interno:0,prioridad:'SIN DETERMINAR',en_kev:false,epss_score:null,resultado:{...fixture.resultado,nvd:{...fixture.resultado.nvd,cvss_score:null},kev:{error:'No disponible'},epss:{epss_score:null,estado:'sin_datos'}},score:{score_interno:0,prioridad:'SIN DETERMINAR',metodologia_version:'2.0',provisional:true,advertencias:['CVSS no disponible','EPSS sin datos'],accion_recomendada:'Completar información antes de priorizar.',factores:[{factor:'CVSS desconocido',puntos:0,detalle:'Sin datos'}]}};
 await page.route('**/api/analyze',r=>r.fulfill({json:unknown}));await page.goto('/');await page.getByLabel('Identificador CVE').fill(fixture.cve_id);await page.getByRole('button',{name:'Investigar',exact:true}).click();
 await expect(page.locator('.internal-number')).toHaveText('—pts');await expect(page.getByText('Prioridad provisional',{exact:true})).toBeVisible();await expect(page.locator('.detail-metrics')).toContainText('Sin datos');await expect(page.locator('.detail-metrics')).not.toContainText('0.0%');await expect(page.locator('.detail-banner .badge')).toHaveClass(/unknown/);
 await page.getByRole('button',{name:'Historial',exact:true}).click();await expect(page.locator('tbody')).toContainText('SIN DETERMINAR');await expect(page.locator('tbody')).toContainText('Provisional');await expect(page.locator('tbody')).not.toContainText('0.0%');
});

test('historical report can be updated to the current methodology',async({page})=>{
 await page.goto('/');await page.getByRole('button',{name:'Historial',exact:true}).click();await page.locator('input[type=file]').setInputFiles({name:'legacy.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify([fixture]))});await page.getByRole('button',{name:fixture.cve_id,exact:true}).click();await expect(page.getByText('Informe histórico · metodología anterior',{exact:true})).toBeVisible();
 await page.route('**/api/analyze',r=>r.fulfill({json:{...fixture,score_interno:160,score:{score_interno:160,prioridad:'CRÍTICA',metodologia_version:'2.0',provisional:false,advertencias:[],factores:[{factor:'CVSS',puntos:100,detalle:'10/10'},{factor:'KEV',puntos:60,detalle:'Explotación documentada'}]}}}));
 await page.getByRole('button',{name:'Actualizar análisis',exact:true}).click();await expect(page.getByText('Metodología 2.0',{exact:true})).toBeVisible();await expect(page.locator('.internal-number')).toHaveText('160pts');
});

test('saved AI Markdown renders in analysis and mitigation without regeneration',async({page})=>{
 const markdown='### Descripción de la vulnerabilidad\n\n- **Producto afectado:** Apache Log4j\n\n| Factor | Puntos |\n| --- | --- |\n| KEV | 60 |\n\n```yaml\ntitle: Detection\n```';
 await page.route('**/api/analyze',r=>r.fulfill({json:{...fixture,analisis:{resumen_ejecutivo:markdown,analisis_tecnico:markdown,plan_mitigacion:markdown}}}));
 await page.goto('/');await page.getByLabel('Identificador CVE').fill(fixture.cve_id);await page.getByRole('button',{name:'Investigar',exact:true}).click();
 await page.getByRole('tab',{name:'Análisis con IA',exact:true}).click();
 const text=page.locator('.analysis-markdown').first();
 await expect(text.getByRole('heading',{name:'Descripción de la vulnerabilidad'})).toBeVisible();
 await expect(text.locator('strong')).toHaveText('Producto afectado:');
 await expect(text.getByRole('cell',{name:'60',exact:true})).toBeVisible();
 await page.setViewportSize({width:360,height:800});
 expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
 await page.getByRole('tab',{name:'Mitigación',exact:true}).click();
 await expect(page.locator('.analysis-markdown h4')).toHaveText('Descripción de la vulnerabilidad');
 await page.locator('.analysis-markdown').screenshot({path:'artifacts/ai-markdown-mobile.png'});
});
