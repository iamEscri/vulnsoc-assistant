import { useEffect, useState } from 'react';
import { ArrowRight, BookOpen } from 'lucide-react';
import { entrySchema, type Entry } from './data';
import { ScoreBreakdown } from './ScoreBreakdown';
import log4shell from './examples/log4shell.json';
import terrapin from './examples/terrapin.json';

const examples = [log4shell, terrapin].map(value => entrySchema.parse(value));
const names = ['Log4Shell · Apache Log4j', 'Terrapin · SSH'];

export function PriorityShowcase({entry,onOpen,onAnalyze,busy}:{entry:Entry|null;onOpen?:()=>void;onAnalyze:(id:string)=>void;busy:boolean}) {
  const [showExamples,setShowExamples] = useState(!entry);
  const [index,setIndex] = useState(0);
  useEffect(()=>{setShowExamples(!entry);},[entry]);
  const example = examples[index];
  const displayed = showExamples || !entry ? example : entry;
  return <section className="priority-showcase" aria-label="Ejemplos y priorización contextual">
    <div className="showcase-toolbar"><span><BookOpen size={17}/>{showExamples || !entry ? 'Explora el motor con CVEs preanalizadas' : 'Priorización de tu análisis'}</span>{entry&&<button className="text-link" onClick={()=>setShowExamples(!showExamples)}>{showExamples?'Volver a mi análisis':'Ver ejemplos preanalizados'}</button>}</div>
    {(showExamples || !entry)&&<div className="example-guide">
      <div className="example-choices" role="group" aria-label="Seleccionar CVE de ejemplo">{examples.map((item,i)=><button key={item.cve_id} aria-pressed={i===index} onClick={()=>setIndex(i)}><b>{item.cve_id}</b><span>{names[i]}</span><small>{item.score_interno} puntos · {item.prioridad}</small></button>)}</div>
      <div className="example-context"><p><b>Ejemplo preanalizado · {new Date(example.fecha!).toLocaleDateString('es-ES')}</b><br/>Datos de NVD, CISA KEV y FIRST EPSS consultados en esa fecha, evaluados con metodología {example.score.metodologia_version}, sin inventario. No se añade a tu historial ni representa el riesgo de tus activos.</p><button className="btn" disabled={busy} onClick={()=>onAnalyze(example.cve_id)}>Analizar con datos actuales <ArrowRight size={15}/></button></div>
    </div>}
    <ScoreBreakdown key={displayed.cve_id} entry={displayed} onOpen={showExamples || !entry ? undefined : onOpen}/>
  </section>;
}
