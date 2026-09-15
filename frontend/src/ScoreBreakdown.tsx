import { type CSSProperties, useState, useRef } from 'react';
import { ChevronDown, Fingerprint, ArrowUpRight } from 'lucide-react';
import { ScoringGuide } from './ScoringGuide';
import { scoreLabel, type Entry } from './data';

/** A waterfall of the existing engine's factors. Does not recompute priority. */
export function ScoreBreakdown({entry,onOpen}:{entry:Entry|null;onOpen?:()=>void}){
 const [expanded,setExpanded]=useState<number|null>(null);
 const guideRef=useRef<HTMLElement>(null);
 const currentPolicy=entry?.score.metodologia_version==='2.0';
 const priorityExplanation=!entry?'Analiza una vulnerabilidad para conocer su prioridad.':entry.prioridad==='SIN DETERMINAR'?'No hay datos suficientes para determinar la prioridad.':!currentPolicy?'Este análisis conserva la prioridad registrada. Actualízalo para revisar las evidencias disponibles.':({
  CRÍTICA:'Esta vulnerabilidad alcanza el umbral de prioridad crítica (≥130 puntos).',
  ALTA:'Esta vulnerabilidad se sitúa en el rango de prioridad alta (90–129 puntos).',
  MEDIA:'Esta vulnerabilidad se sitúa en el rango de prioridad media (55–89 puntos).',
  BAJA:'Esta vulnerabilidad se sitúa en el rango de prioridad baja (0–54 puntos).',
 } as Record<string,string>)[entry.prioridad]??'Consulta las evidencias disponibles para interpretar el resultado.';
 const factors=entry?.score.factores??[];
 let accumulated=0;
 const rows=factors.map(f=>{const start=accumulated;accumulated+=f.puntos;return {...f,start,end:accumulated};});
 const min=Math.min(0,...rows.map(r=>Math.min(r.start,r.end)));
 const max=Math.max(160,entry?.score_interno??0,...rows.map(r=>Math.max(r.start,r.end)))*1.06;
 const position=(n:number)=>(n-min)/(max-min)*100;
 const partial=entry&&Math.abs(Math.max(0,accumulated)-entry.score_interno)>.01;
 return <section ref={guideRef} className={'score-lab '+(entry?'has-score':'awaiting-score')} data-priority={entry?severity(entry.prioridad):undefined} aria-label="Desglose del VulnSOC Score">
  <header className="score-lab-header"><div><span className="eyebrow">MOTOR DE PRIORIZACIÓN CONTEXTUAL</span><h2>Cómo se construye la prioridad</h2></div>{onOpen&&entry&&<button className="text-link mono" onClick={onOpen}>{entry.cve_id}<ArrowUpRight size={14}/></button>}</header>
  <div className="score-lab-layout"><div className="score-verdict"><span className="verdict-label">RESULTADO CONTEXTUAL</span><span>VulnSOC Score</span><div className="internal-number">{entry?scoreLabel(entry):'—'}<small>pts</small></div>{entry?<span className={'badge '+severity(entry.prioridad)}><i/>{entry.prioridad}</span>:<span className="neutral-badge">Pendiente de análisis</span>}<p><strong>{priorityExplanation}</strong></p><p>La puntuación combina severidad, evidencia de explotación y contexto de tus activos. Indica prioridad de atención, no un porcentaje de riesgo.</p>{entry?.score.provisional&&<p className="help">Resultado provisional: revisa las advertencias del análisis.</p>}<button className="text-link" onClick={()=>{const guide=guideRef.current?.querySelector('details');if(guide){guide.open=true;guide.querySelector('summary')?.focus();guide.scrollIntoView({block:'start'});}}}>Cómo se calcula <ArrowUpRight size={14}/></button>{currentPolicy&&<div className="threshold-legend"><span>BAJA <b>&lt;55</b></span><span>MEDIA <b>55–89</b></span><span>ALTA <b>90–129</b></span><span>CRÍTICA <b>≥130</b></span></div>}</div>
  <div className="score-waterfall">{entry&&rows.length?<><div className="waterfall-heading"><span>01 / EVIDENCIAS QUE SUMAN CONTEXTO</span><span>Σ PUNTOS</span></div><div className="waterfall-rows">{rows.map((r,i)=><div key={i} style={{'--step':Math.min(i,12)} as CSSProperties} className={'waterfall-item '+(expanded===i?'expanded':'')}><button className="waterfall-row" onClick={()=>setExpanded(expanded===i?null:i)} aria-expanded={expanded===i} aria-controls={`factor-${entry.cve_id}-${i}`}><span className="factor-name"><span className="factor-step">{String(i+1).padStart(2,'0')}</span>{r.factor}<small className={r.puntos<0?'negative':''}>{r.puntos>0?'+':''}{r.puntos} pts</small></span><span className="waterfall-track" aria-hidden="true"><i className={'waterfall-bar '+(r.puntos<0?'deduction':r.puntos===0?'zero':'')} style={{left:`${position(Math.min(r.start,r.end))}%`,width:r.puntos===0?'2px':`${Math.abs(r.puntos)/(max-min)*100}%`}}/><i className="waterfall-end" style={{left:`${position(r.end)}%`}}/></span><b className="accumulated-value">{r.end}</b><ChevronDown size={13}/></button>{entry.score.metodologia_version==='2.0'&&r.factor.startsWith('EPSS')&&r.puntos===0&&<p className="factor-zero-reason">{r.factor==='EPSS desconocido'?'Sin datos: probabilidad desconocida, no 0 %.':entry.en_kev&&!entry.resultado.kev.error?'EPSS informativo: KEV tiene precedencia.':'No suma: EPSS inferior al umbral del 1 %.'}</p>}<div id={`factor-${entry.cve_id}-${i}`} hidden={expanded!==i} className="factor-explanation">{r.detalle}</div></div>)}</div><p className="score-hint">Cada barra muestra la aportación del factor; la cifra de la derecha, el total acumulado.</p>{partial&&<p className="help">Desglose parcial: los factores disponibles suman {accumulated} puntos; el informe registra {entry.score_interno}. Se conserva el resultado original.</p>}<div className="score-resolution"><span><small>02 / PUNTUACIÓN CONTEXTUAL</small><b>{scoreLabel(entry)} pts</b></span><ArrowUpRight size={18}/><span><small>03 / PRIORIDAD</small><b className="resolution-priority" data-priority={severity(entry.prioridad)}>{entry.prioridad}</b></span></div><p className="score-hint">Selecciona un factor para consultar su evidencia. La ausencia de coincidencias en inventario no resta puntos.</p></>:<div className="score-empty"><Fingerprint size={28}/><h3>Cada punto debe tener una razón.</h3><p>Al analizar un CVE verás cuánto aportan CVSS, señales de explotación y contexto de activos. Selecciona cada factor para consultar la evidencia que lo respalda.</p></div>}</div></div>
 <ScoringGuide/>
 </section>;
}
export function severity(priority:string){return priority==='CRÍTICA'?'critical':priority==='ALTA'?'high':priority==='MEDIA'?'medium':priority==='BAJA'?'low':'unknown';}
