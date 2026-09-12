import { describe, expect, it } from 'vitest';
import { entrySchema, historySchema, inventorySchema, mergeHistory, safeUrl } from './data';
const entry=entrySchema.parse({cve_id:'CVE-2021-44228',prioridad:'CRÍTICA',score_mostrado:100,score_interno:180,tipo:'RCE',en_kev:true,epss_score:.9,resultado:{nvd:{cve_id:'CVE-2021-44228',descripcion:'Descripción'},kev:{en_kev:true},epss:{epss_score:.9}},score:{score_mostrado:100,score_interno:180,prioridad:'CRÍTICA',factores:[]},analisis:{}});
describe('importaciones y referencias',()=>{
 it('acepta historiales antiguos sin fecha ni equipos',()=>{expect(historySchema.parse([entry])[0].equipos_afectados).toEqual([]);});
 it('rechaza estructuras incompletas antes de guardarlas',()=>{expect(historySchema.safeParse([{cve_id:'CVE-2021-44228'}]).success).toBe(false);expect(inventorySchema.safeParse({equipos:[{nombre:''}]}).success).toBe(false);});
 it('elimina duplicados y conserva la entrada actual',()=>{const older={...entry,score_interno:100};const merged=mergeHistory([entry],[older,older]);expect(merged).toHaveLength(1);expect(merged[0].score_interno).toBe(180);});
 it('solo permite referencias HTTP y HTTPS',()=>{expect(safeUrl('javascript:alert(1)')).toBeUndefined();expect(safeUrl('data:text/html,hello')).toBeUndefined();expect(safeUrl('https://nvd.nist.gov/')).toBe('https://nvd.nist.gov/');});
});
