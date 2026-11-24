// 1GR isolated CI recovery evidence only; never authorize restore or production.
import {createHash,createPublicKey,verify} from 'node:crypto';
import type {Pool,PoolConnection,RowDataPacket} from 'mysql2/promise';
import {gfMigrationTarget} from '../migrate-gf-provenance';
import {gqInspectAuthoritySnapshot} from './gqAuthorityReconciliation';
const audience='aaditech:disposable-ci:authority-recovery:v1';
const specs=[
 ['auth_gk_customer_intents_candidate','intent_hash','intent_hash,actor_id,session_hash,customer_id,audit_id,name,gstin,contactPerson,email,phone,city,state,expires_at,consumed_at,created_at'],
 ['auth_gl_lead_intents_candidate','intent_hash','intent_hash,actor_id,session_hash,lead_id,audit_id,name,company,email,phone,source,status,score,scoreReason,intentScore,requirement,estimatedBudget,location,gstin,expires_at,consumed_at,created_at'],
 ['auth_gl_product_intents_candidate','intent_hash','intent_hash,actor_id,session_hash,product_id,audit_id,sku,brand,model,category,specs,unitCost,freightCost,riskBuffer,sellingPrice,minPrice,gstRate,hsn,warrantyMonths,leadTimeDays,expires_at,consumed_at,created_at'],
 ['auth_gj_quote_intents_candidate','intent_hash','intent_hash,actor_id,session_hash,request_key,request_hash,quote_id,expires_at,consumed_at,created_at'],
 ['auth_gn_intent_nonces_candidate','intent_hash','intent_hash,operation,actor_id,entity_id,reserved_at,consumed_at'],
 ['auth_go_issuer_keys_candidate','key_id','key_id,spki_sha256,scope_mask,not_before,not_after,revoked_at'],
 ['auth_go_intent_approvals_candidate','intent_hash','intent_hash,key_id,spki_sha256,evidence_sha256,expires_at,approved_at']
] as const;
export const GR_TABLES=Object.freeze(specs.map(x=>x[0]));
export type GrTableDigest={table:string;rowCount:number;sha256:string};
export type GrManifest={version:1;audience:typeof audience;sequence:number;previousSha256:string;sourceCommit:string;observedAtMs:number;tables:GrTableDigest[]};
const hex=/^[0-9a-f]{64}$/;
const maxRows=10000;
function fail():never{throw Error('GR_RECOVERY_HOLD');}
function digest(v:unknown):v is string{return typeof v==='string'&&hex.test(v);}
function obj(value:unknown,keys:string[]):Record<string,unknown>{
 if(!value||typeof value!=='object'||Object.getPrototypeOf(value)!==Object.prototype)fail();
 const v=value as Record<string,unknown>;
 if(Reflect.ownKeys(v).length!==keys.length||keys.some(k=>!Object.prototype.hasOwnProperty.call(v,k)||!Object.getOwnPropertyDescriptor(v,k)?.enumerable||!('value' in Object.getOwnPropertyDescriptor(v,k)!)))fail();
 return v;
}
export function grManifestBytes(value:unknown):Buffer{
 const m=obj(value,['version','audience','sequence','previousSha256','sourceCommit','observedAtMs','tables']);
 if(m.version!==1||m.audience!==audience||typeof m.sequence!=='number'||!Number.isSafeInteger(m.sequence)||m.sequence<1||
 !digest(m.previousSha256)||typeof m.sourceCommit!=='string'||!/^[0-9a-f]{40}$/.test(m.sourceCommit)||
 typeof m.observedAtMs!=='number'||!Number.isSafeInteger(m.observedAtMs)||m.observedAtMs<=0||
 !Array.isArray(m.tables)||m.tables.length!==specs.length)fail();
 const tables=Array.from(m.tables as unknown[],(value,i)=>{
  const t=obj(value,['table','rowCount','sha256']);
  if(t.table!==specs[i][0]||typeof t.rowCount!=='number'||!Number.isSafeInteger(t.rowCount)||t.rowCount<0||t.rowCount>maxRows||!digest(t.sha256))fail();
  return [t.table,t.rowCount,t.sha256];
 });
 return Buffer.from('AADITECH-GR-RECOVERY-V1\n'+JSON.stringify([m.version,m.audience,m.sequence,m.previousSha256,m.sourceCommit,m.observedAtMs,tables]),'utf8');
}
export function grMakeManifest(tables:GrTableDigest[],anchor:{sequence:number;previousSha256:string;sourceCommit:string;observedAtMs:number}):GrManifest{
 const m:GrManifest={version:1,audience,...anchor,tables};grManifestBytes(m);return m;
}
// Exact expected anchor and pinned key supplied independently of the manifest.
export function grVerifyManifest(value:unknown,signature:unknown,expected:{sequence:number;previousSha256:string;sourceCommit:string;publicKeyPem:string;spkiSha256:string},actual:GrTableDigest[]){
 const bytes=grManifestBytes(value),m=value as GrManifest;
 if(m.sequence!==expected.sequence||m.previousSha256!==expected.previousSha256||m.sourceCommit!==expected.sourceCommit||
 !digest(expected.spkiSha256)||typeof signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signature)||
 typeof expected.publicKeyPem!=='string'||expected.publicKeyPem.length>4096||!expected.publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----'))fail();
 try{
  const key=createPublicKey(expected.publicKeyPem),sig=Buffer.from(signature as string,'base64url');
  if(key.asymmetricKeyType!=='ed25519'||createHash('sha256').update(key.export({format:'der',type:'spki'})).digest('hex')!==expected.spkiSha256||
  sig.length!==64||sig.toString('base64url')!==signature||!verify(null,bytes,key,sig))fail();
 }catch{return fail();}
 const observed=grManifestBytes({...m,tables:actual});
 if(!observed.equals(bytes))fail();
 return {status:'MATCH' as const,manifestSha256:createHash('sha256').update(bytes).digest('hex'),productionReleaseAuthorized:false as const};
}
// Cast each explicit column to UTF-8 text inside MySQL (preserves decimal and
// DATETIME precision; SQL NULL stays null). Primary-key ordering is binary.
// No row contents leave this helper; bounded row count and per-row bytes.
export async function grCaptureAuthorityDigests(c:Pick<PoolConnection,'query'>,restored=false):Promise<GrTableDigest[]>{
 gfMigrationTarget(process.env);
 const output:GrTableDigest[]=[];
 for(const [table,pk,columns] of specs){
  const fields=columns.split(',');
  const [rows]=await c.query<RowDataPacket[]>('SELECT '+fields.map(k=>'CAST('+k+' AS CHAR CHARACTER SET utf8mb4) AS '+k).join(',')+' FROM '+(restored?'gs_restore_'+table:table)+' ORDER BY BINARY '+pk+' LIMIT '+(maxRows+1));
  if(rows.length>maxRows)fail();
  const hash=createHash('sha256').update(JSON.stringify(['GR_TABLE_V1',table,fields])+'\n');
  for(const row of rows){
   const values=fields.map(k=>row[k]);
   if(values.some(v=>v!==null&&typeof v!=='string'))fail();
   const bytes=JSON.stringify(values);
   if(Buffer.byteLength(bytes,'utf8')>131072)fail();
   hash.update(bytes+'\n','utf8');
  }
  output.push({table,rowCount:rows.length,sha256:hash.digest('hex')});
 }
 return output;
}
export async function grCaptureConsistentAuthority(pool:Pick<Pool,'getConnection'>){
 gfMigrationTarget(process.env);
 const c=await pool.getConnection();
 try{
  await c.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
  await c.query('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
  if((await gqInspectAuthoritySnapshot(c)).status!=='PASS')fail();
  return await grCaptureAuthorityDigests(c);
 }finally{try{await c.rollback();}catch(e){c.destroy();throw e;}finally{c.release();}}
}


// 1GS isolated logical row export/import rehearsal. Temporary tables are
// session-local, not application tables. CREATE LIKE does not copy FKs/triggers.
// Source must be quiescent for the schema capture; data is a consistent snapshot.
// Never emit raw source rows or call on live data.
export async function gsRehearseLogicalRestore(pool:Pick<Pool,'getConnection'>){
 gfMigrationTarget(process.env);
 const source=await pool.getConnection();
 let restore:PoolConnection|undefined;
 const created:string[]=[];
 try{
  await source.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
  await source.query('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
  if((await gqInspectAuthoritySnapshot(source)).status!=='PASS')fail();
  const original=await grCaptureAuthorityDigests(source);
  restore=await pool.getConnection();
  let totalBytes=0;
  for(const [table,pk,columns] of specs){
   const dest='gs_restore_'+table,fields=columns.split(',');
   const [rows]=await source.query<RowDataPacket[]>('SELECT '+fields.map(k=>'CAST('+k+' AS CHAR CHARACTER SET utf8mb4) AS '+k).join(',')+' FROM '+table+' ORDER BY BINARY '+pk+' LIMIT '+(maxRows+1));
   if(rows.length>maxRows)fail();
   await restore.query('CREATE TEMPORARY TABLE '+dest+' LIKE '+table);created.push(dest);
   for(const row of rows){
    const values=fields.map(k=>row[k]);
    if(values.some(v=>v!==null&&typeof v!=='string'))fail();
    totalBytes+=Buffer.byteLength(JSON.stringify(values),'utf8');
    if(totalBytes>16*1024*1024)fail();
    await restore.execute('INSERT INTO '+dest+'('+columns+') VALUES ('+fields.map(()=>'?').join(',')+')',values);
   }
  }
  const restored=await grCaptureAuthorityDigests(restore,true);
  if(JSON.stringify(original)!==JSON.stringify(restored))fail();
  // Deliberately remove one row ONLY from the temporary restored copy.
  const [result]=await restore.query<import('mysql2/promise').ResultSetHeader>('DELETE FROM gs_restore_auth_gn_intent_nonces_candidate LIMIT 1');
  if(result.affectedRows!==1)fail();
  const damaged=await grCaptureAuthorityDigests(restore,true);
  if(JSON.stringify(original)===JSON.stringify(damaged))fail();
  return {original,restored,damaged,productionReleaseAuthorized:false as const};
 }finally{
  if(restore){try{for(const table of created.reverse())await restore.query('DROP TEMPORARY TABLE '+table);}finally{restore.destroy();}}
  try{await source.rollback();}catch(e){source.destroy();throw e;}finally{source.release();}
 }
}
