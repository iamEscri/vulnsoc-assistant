import { useId, useState } from 'react';
import { Pause, Play } from 'lucide-react';
import { scoreLabel, type Entry } from './data';
import { severity } from './ScoreBreakdown';

/** An explanatory flow, never an indication of live source availability. */
export function IntelligenceFlow({ entry }: { entry: Entry | null }) {
  const id = useId();
  const [paused, setPaused] = useState(false);
  const priority = entry?.prioridad ?? 'CRÍTICA';
  return <figure className={`intelligence-flow ${paused ? 'paused' : ''}`} aria-label="Flujo de priorización de VulnSOC">
    <figcaption><span className="eyebrow">DE LA EVIDENCIA A LA DECISIÓN</span><button type="button" onClick={() => setPaused(!paused)} aria-label={paused ? 'Reanudar animación' : 'Pausar animación'}>{paused ? <Play size={13}/> : <Pause size={13}/>}</button></figcaption>
    <svg viewBox="0 0 580 286" role="img" aria-labelledby={id}>
      <title id={id}>NVD, CISA KEV, EPSS y activos convergen en VulnSOC para determinar la prioridad contextual. {entry ? `Referencia guardada: ${entry.cve_id}, ${priority}, ${scoreLabel(entry)} puntos.` : 'Ejemplo ilustrativo: prioridad crítica, 160 puntos.'}</title>
      {[55, 113, 171, 229].map((y, i) => <g key={y}>
        <path className="flow-wire" d={`M 151 ${y} H 183 Q 210 ${y} 210 ${y < 142 ? y+25 : y-25} V 142 H 258`}/>
        <path className="flow-pulse" style={{animationDelay: `${i*.55}s`}} d={`M 151 ${y} H 183 Q 210 ${y} 210 ${y < 142 ? y+25 : y-25} V 142 H 258`}/>
      </g>)}
      {[
        ['NVD', 'Severidad · CVSS'], ['CISA KEV', 'Explotación conocida'],
        ['EPSS', 'Probabilidad'], ['ACTIVOS', 'Contexto del entorno'],
      ].map(([name, detail], i) => <g className={`flow-source source-${i}`} key={name} transform={`translate(8 ${31+i*58})`}>
        <rect width="143" height="48" rx="8"/><circle cx="14" cy="17" r="3"/>
        <text x="25" y="21" className="flow-label">{name}</text><text x="14" y="37" className="flow-caption">{detail}</text>
      </g>)}
      <g className="flow-engine"><rect x="250" y="89" width="116" height="108" rx="22"/><path d="M308 107l13 5v10c0 10-13 16-13 16s-13-6-13-16v-10z"/><text x="308" y="158" textAnchor="middle" className="flow-brand">VulnSOC</text><text x="308" y="177" textAnchor="middle" className="flow-caption">SCORING CONTEXTUAL</text></g>
      <path className="flow-wire" d="M366 142 H413"/><path className="flow-pulse flow-output-pulse" d="M366 142 H413"/>
      <g className={`flow-result ${severity(priority)}`}><rect x="414" y="99" width="158" height="89" rx="10"/><text x="429" y="121" className="flow-caption">PRIORIDAD CONTEXTUAL</text><text x="429" y="144" className="flow-priority">{priority}</text><text x="429" y="172" className="flow-score">{entry?scoreLabel(entry):160}<tspan className="flow-caption"> pts</tspan></text></g>
    </svg>
    <div className="flow-mobile"><div className="mobile-sources">{[['NVD','Severidad · CVSS'],['CISA KEV','Explotación conocida'],['EPSS','Probabilidad'],['ACTIVOS','Contexto del entorno']].map(([name,caption])=><div key={name}><b>{name}</b><small>{caption}</small></div>)}</div><div className="mobile-flow-output"><div className="mobile-engine"><b>VulnSOC</b><small>Scoring contextual</small></div><span className="mobile-connector" aria-hidden="true">→</span><div className="mobile-result" data-priority={severity(priority)}><small>Prioridad contextual</small><b>{priority}</b><span>{entry?scoreLabel(entry):160}<small> pts</small></span></div></div></div>
    <div className="flow-note"><span className="flow-note-mark"/><span>{entry ? `Referencia local · ${entry.cve_id}` : 'Ejemplo ilustrativo · CRÍTICA, 160 puntos'}</span><small>Esquema del proceso, sin consultas en directo.</small></div>
  </figure>;
}
