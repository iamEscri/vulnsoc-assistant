import { useState } from 'react';
import examples from './examples/scoring-policy.json';

export function ScoringGuide({ expanded = false }: { expanded?: boolean }) {
 const [index, setIndex] = useState(0);
 const example = examples[index];
 const content = <>
  <div className="scoring-guide-content">
   <h3>Severidad + explotación + contexto del activo</h3>
   <p>La severidad es solo el principio; el contexto define la prioridad. VulnSOC 2.0 utiliza puntos para ordenar la atención, no para expresar un porcentaje de riesgo.</p>
   <div className="scoring-rules">
    <section><h4>01 · Severidad</h4><p><strong>CVSS × 10</strong>, redondeado a puntos enteros. CVSS 7,2 aporta 72 puntos. CWE, vector de ataque y antigüedad no añaden bonificaciones.</p></section>
    <section><h4>02 · Explotación</h4><p><strong>KEV confirmado: +60.</strong> EPSS se muestra como información y no suma: la evidencia de explotación tiene precedencia sobre la predicción.</p><p>Sin KEV confirmado, se aplica un único tramo EPSS:</p><ul><li>Menos del 1 %: +0</li><li>Desde el 1 % hasta menos del 10 %: +10</li><li>Desde el 10 % hasta menos del 70 %: +20</li><li>Desde el 70 %: +30</li></ul><p>Si KEV no se puede verificar, se advierte de ello; no equivale a estar fuera del catálogo.</p></section>
    <section><h4>03 · Tu entorno</h4><p>Este ajuste solo se aplica cuando el motor establece compatibilidad de producto y versión. Después valora la criticidad y la exposición de ese mismo activo.</p>
     <div className="context-table-wrap"><table className="context-points-table"><caption>Aportaciones del activo al score</caption><thead><tr><th scope="col">Factor</th><th scope="col">Condición</th><th scope="col">Puntos</th></tr></thead><tbody>
      <tr><th scope="row">Compatibilidad</th><td>Producto y versión compatibles con un criterio publicado</td><td>+5</td></tr>
      <tr><th scope="row">Criticidad baja</th><td>Importancia baja declarada para el activo</td><td>+0</td></tr>
      <tr><th scope="row">Criticidad media</th><td>Importancia media declarada para el activo</td><td>+5</td></tr>
      <tr><th scope="row">Criticidad alta</th><td>Importancia alta declarada para el activo</td><td>+15</td></tr>
      <tr><th scope="row">Accesible desde Internet</th><td>Exposición indicada por ti en el inventario</td><td>+15</td></tr>
      <tr><th scope="row">Exposición interna o desconocida</th><td>No se añade bonificación por exposición; desconocida no significa interna</td><td>+0</td></tr>
     </tbody></table></div>
     <p>Se aplica una sola criticidad: baja, media o alta. Se toma el activo de mayor contribución conjunta, hasta <strong>+35 = 5 + 15 + 15</strong>. No se suman varios activos ni se mezclan sus características.</p>
     <h4>¿Cómo se sabe si está expuesto a Internet?</h4><p><strong>Lo indicas tú</strong> en Inventario de activos → Añadir o editar activo → Exposición declarada. Elige «Accesible desde Internet» si el servicio recibe conexiones desde Internet, por ejemplo un servidor web público. Poder navegar o descargar actualizaciones desde el equipo no significa que esté expuesto.</p><p>VulnSOC no escanea puertos ni lo deduce de la IP. Si no conoces la configuración de red, selecciona «Desconocida» y consúltala con quien administra el servicio. Ese estado aporta +0 por exposición y, si hay un activo compatible seleccionado, genera una advertencia.</p>
     <p>Sin coincidencia verificable no se suma ni se resta. La compatibilidad no confirma compromiso. Tras modificar el inventario, actualiza el análisis para incorporar el cambio.</p></section>
   </div>
   <section className="priority-guide" aria-label="Umbrales de prioridad"><h3>Del total de puntos a la prioridad</h3><p>Compara el total con estos intervalos. Son umbrales propios de VulnSOC 2.0, no categorías CVSS.</p><div className="priority-bands">{[
    ['Baja','0–54','low','Mantener seguimiento. Baja prioridad no implica ausencia de riesgo.'],
    ['Media','55–89','medium','Evaluar en el ciclo de gestión y seguir nuevas evidencias.'],
    ['Alta','90–129','high','Revisar la aplicabilidad y planificar la remediación con prioridad.'],
    ['Crítica','≥130','critical','Revisar con urgencia la aplicabilidad y priorizar mitigación o parche.'],
   ].map(([label,range,tone,action])=><article key={label} data-tone={tone}><h4>{label}</h4><strong>{range}</strong><span>puntos de prioridad</span><p>{action}</p></article>)}</div></section>
   <p>KEV garantiza como mínimo 90 puntos (alta): si CVSS + KEV no llega a 90, se añade el ajuste necesario antes del contexto de activos. Sin CVSS ni KEV confirmado, la prioridad queda <strong>sin determinar</strong>. Un dato ausente nunca equivale a cero.</p>
   <section className="scoring-example" aria-label="Ejemplos de scoring">
    <label>Explora un ejemplo<select value={index} onChange={event => setIndex(Number(event.target.value))}>{examples.map((item, i) => <option value={i} key={item.title}>{item.title}</option>)}</select></label>
    <div aria-live="polite" className="example-walkthrough"><header><span className="eyebrow">ESCENARIO {index+1} DE {examples.length} · DATOS DIDÁCTICOS</span><h4>{example.title}</h4><p>{example.description}</p></header>
    <div className="example-inputs"><span>CVSS<strong>{example.cvss??'Sin datos'}</strong></span><span>CISA KEV<strong>{example.kev?'Incluida':'No incluida'}</strong></span><span>EPSS<strong>{(example.epss*100).toLocaleString('es-ES',{maximumFractionDigits:3})} %</strong></span><span>Activos<strong>{example.context?'Compatible · alta · Internet':'Sin ajuste'}</strong></span></div>
    <ol className="example-steps">{example.steps.map((step,i)=><li key={i}><span className="example-step-number">0{i+1}</span><div><h5>{step.title}</h5><p>{step.reason}</p></div><strong>{step.points>0?'+':''}{step.points}<small>puntos</small></strong></li>)}</ol>
    <div className="example-conclusion"><div><span className="eyebrow">RESULTADO EXPLICADO</span><strong>{example.points} puntos · {example.priority}</strong><p>{example.takeaway}</p></div><p className="scoring-equation">{example.equation}</p></div></div>
    <p className="help">Escenarios didácticos con valores fijos; no son consultas actuales ni se guardan en el historial.</p>
   </section>
   <p><strong>Prioridad y aplicabilidad son distintas.</strong> Una CVE puede ser crítica y estar pendiente de comprobar en tus activos. Las advertencias indican qué falta verificar; no prueban que tu entorno esté afectado o protegido.</p>
   <p>Los pesos y los umbrales son una política propia, no una fórmula validada estadísticamente. 128 y 130 son puntuaciones próximas aunque cambie la etiqueta. Con estas reglas, el máximo posible es 195 puntos (100 + 60 + 35); crítica empieza en 130, no en 195. EPSS no mide la probabilidad de compromiso de tu activo y un 100,0 % mostrado puede ser un redondeo.</p>
   <p>Los informes históricos conservan su metodología: actualiza el análisis para aplicar estas reglas. La IA no asigna los puntos.</p>
   <p>Fuentes: <a href="https://nvd.nist.gov/vuln-metrics/cvss" target="_blank" rel="noreferrer">NVD / CVSS</a> · <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noreferrer">CISA KEV</a> · <a href="https://www.first.org/epss/faq" target="_blank" rel="noreferrer">FIRST / EPSS y explotación conocida</a>. Estas fuentes no establecen los pesos de VulnSOC.</p>
  </div>
 </>;
 return expanded ? <div className="scoring-guide scoring-guide-full">{content}</div> : <details className="scoring-guide"><summary>Entender el scoring · reglas y ejemplos</summary>{content}</details>;
}
