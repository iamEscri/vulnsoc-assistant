import { openDB } from 'idb';
import { z } from 'zod';

export const assetSchema=z.object({nombre:z.string().min(1).max(120),ip:z.string().default(''),criticidad:z.enum(['alta','media','baja']).default('media'),tecnologias:z.array(z.string().max(200)).max(100)});
export const inventorySchema=z.object({equipos:z.array(assetSchema).max(500)});
const factor=z.object({factor:z.string(),puntos:z.number(),detalle:z.string()});
export const entrySchema=z.object({
 cve_id:z.string().regex(/^CVE-\d{4}-\d{4,19}$/), prioridad:z.string(),score_mostrado:z.number(),score_interno:z.number(),tipo:z.string(),en_kev:z.boolean(),epss_score:z.number(),fecha:z.string().optional(),
 resultado:z.object({nvd:z.object({cve_id:z.string(),descripcion:z.string(),cvss_score:z.number().nullable().optional(),cvss_version:z.string().nullable().optional(),fecha_publicacion:z.string().optional(),fecha_modificacion:z.string().optional(),referencias:z.array(z.string()).default([]),productos_afectados:z.array(z.string()).default([]),cwes:z.array(z.string()).default([]),vector_ataque:z.record(z.string()).default({}),refs_parche:z.array(z.string()).default([])}).passthrough(),kev:z.object({en_kev:z.boolean().optional(),error:z.string().optional(),accion_requerida:z.string().optional(),fecha_limite:z.string().optional()}).passthrough(),epss:z.object({epss_score:z.number().optional(),error:z.string().optional()}).passthrough()}),
 score:z.object({score_mostrado:z.number(),score_interno:z.number(),prioridad:z.string(),factores:z.array(factor)}).passthrough(),
 analisis:z.object({resumen_ejecutivo:z.string().optional(),analisis_tecnico:z.string().optional(),plan_mitigacion:z.string().optional(),error:z.string().optional(),alucinacion_detectada:z.boolean().optional(),proveedor:z.string().optional()}).passthrough(),
 equipos_afectados:z.array(z.object({nombre:z.string(),criticidad:z.string(),coincidencias:z.array(z.string()),coincidencias_plataforma:z.array(z.string()).default([])})).default([])
}).passthrough();
export type Entry=z.infer<typeof entrySchema>;
export type Asset=z.infer<typeof assetSchema>;
export type Inventory=z.infer<typeof inventorySchema>;
export type SearchHit={cve_id:string;descripcion:string;cvss_score:number|null;fecha_publicacion:string};
export const historySchema=z.array(entrySchema).max(1000);
export function mergeHistory(current:Entry[],incoming:Entry[]){ const map=new Map(incoming.map(e=>[e.cve_id,e]));current.forEach(e=>map.set(e.cve_id,e));return [...map.values()].slice(0,1000); }
let database:ReturnType<typeof openDB>|undefined;
const db=()=>database??=openDB('vulnsoc-workspace',1,{upgrade(db){db.createObjectStore('workspace');}});
export async function readLocal(){return (await db()).get('workspace','state');}
export async function saveLocal(historial:Entry[],inventario:Inventory){return (await db()).put('workspace',{historial,inventario},'state');}
export async function api<T>(path:string,body?:unknown):Promise<T>{
 const response=await fetch('/api/'+path,{method:body===undefined?'GET':'POST',headers:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
 if(!response.ok){let message='No se ha podido completar la operación.';const text=await response.text();try{const detail=JSON.parse(text).detail;if(typeof detail==='string')message=detail;else message='Revisa los datos introducidos.';}catch{message=text||message;}throw new Error(message);}
 return response.json();
}
export function download(data:BlobPart,name:string,type='application/json'){const url=URL.createObjectURL(new Blob([data],{type}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
export function safeUrl(url:string){try{const u=new URL(url);return ['http:','https:'].includes(u.protocol)?u.href:undefined;}catch{return undefined;}}
