// CI-only persistence candidate; no live installer or operational authority.
import {createHash,randomUUID} from 'node:crypto';
import type {Pool,PoolConnection,RowDataPacket} from 'mysql2/promise';
import {hashToken} from '../auth/crypto';
import {lockActiveCrmOwner} from '../crm/repository';
import {evaluateInternalPlan,GU_MODULES} from './planners';
import {reject} from './validation';
export const GV_TABLE='planning_records_gv_candidate';
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,token=/^[A-Za-z0-9_-]{43}$/;
export class PlanningRecordError extends Error{constructor(readonly status:number,readonly code:string){super(code);}}
function stop(status:number,code:string):never{throw new PlanningRecordError(status,code);}
export function gvPersistenceEnabled(env:NodeJS.ProcessEnv=process.env){
 return env.GV_PLANNING_FIXTURE==='YES'&&env.CRM_TEST_DB==='1'&&env.NODE_ENV==='test'&&env.DB_NAME==='aaditech_ci'&&env.DB_SSL==='false';
}
export function gvId(v:unknown):string{if(typeof v!=='string'||!uuid.test(v))reject('INVALID_RECORD_ID');return v;}
export function gvSessionCookie(header:string|undefined):string{
 const m=(header??'').split(';').map(x=>x.trim()).filter(x=>x.startsWith('aaditech_session='));
 const v=m.length===1?m[0].slice('aaditech_session='.length):'';
 if(!token.test(v))stop(403,'SESSION_AUTHORITY_REQUIRED');return v;
}
export function gvCanonical(value:unknown):string{
 function visit(v:unknown,depth:number):unknown{
  if(depth>16)reject('INVALID_CANONICAL_VALUE');
  if(v===null||typeof v==='boolean'||typeof v==='string')return v;
  if(typeof v==='number'){if(!Number.isSafeInteger(v)||Object.is(v,-0))reject('INVALID_CANONICAL_VALUE');return v;}
  if(Array.isArray(v)){
   if(v.length>100||Reflect.ownKeys(v).length!==v.length+1)reject('INVALID_CANONICAL_VALUE');
   return Array.from({length:v.length},(_,i)=>{const x=Object.getOwnPropertyDescriptor(v,String(i));if(!x||!x.enumerable||!('value' in x))reject('INVALID_CANONICAL_VALUE');return visit(x.value,depth+1);});
  }
  if(!v||typeof v!=='object'||Object.getPrototypeOf(v)!==Object.prototype)reject('INVALID_CANONICAL_VALUE');
  const keys=Reflect.ownKeys(v);if(keys.length>100||keys.some(k=>typeof k!=='string'))reject('INVALID_CANONICAL_VALUE');
  return Object.fromEntries((keys as string[]).sort().map(k=>{const x=Object.getOwnPropertyDescriptor(v,k);if(!x||!x.enumerable||!('value' in x))reject('INVALID_CANONICAL_VALUE');return [k,visit(x.value,depth+1)];}));
 }
 const json=JSON.stringify(visit(value,0));if(Buffer.byteLength(json,'utf8')>65536)reject('CANONICAL_VALUE_TOO_LARGE');return json;
}
const sha=(v:string)=>createHash('sha256').update(v,'utf8').digest('hex');
export function gvPrepare(module:unknown,payload:unknown){
 const canonical=gvCanonical(payload),result=evaluateInternalPlan(module,JSON.parse(canonical)),resultJson=gvCanonical(result);
 return {module:result.module,requestSha256:sha('AADITECH-GV-REQUEST-V1\n'+result.module+'\n'+canonical),resultJson,resultSha256:sha('AADITECH-GV-RESULT-V1\n'+resultJson)};
}
export function gvVerifyStored(row:{module:unknown;result_json:unknown;result_sha256:unknown}){
 if(typeof row.module!=='string'||!GU_MODULES.includes(row.module)||typeof row.result_json!=='string'||typeof row.result_sha256!=='string'||sha('AADITECH-GV-RESULT-V1\n'+row.result_json)!==row.result_sha256)stop(503,'RECORD_INTEGRITY_HOLD');
 try{
  const result=JSON.parse(row.result_json) as Record<string,unknown>;
  if(gvCanonical(result)!==row.result_json||result.module!==row.module||result.releaseDecision!=='HOLD'||result.productionReleaseAuthorized!==false||result.externalExecutionEnabled!==false||result.requiresHumanReview!==true||result.evidenceStatus!=='OPERATOR_SUPPLIED_UNVERIFIED')stop(503,'RECORD_INTEGRITY_HOLD');
  return result;
 }catch{return stop(503,'RECORD_INTEGRITY_HOLD');}
}
async function scoped<T>(pool:Pool,actor:string,session:string,fn:(c:PoolConnection)=>Promise<T>):Promise<T>{
 if(!gvPersistenceEnabled())stop(503,'PERSISTENCE_DISABLED');gvId(actor);if(!token.test(session))stop(403,'SESSION_AUTHORITY_REQUIRED');
 const c=await pool.getConnection();
 try{
  const [target]=await c.query<RowDataPacket[]>('SELECT DATABASE() AS name');if(target[0]?.name!=='aaditech_ci')stop(503,'PERSISTENCE_DISABLED');
  await c.beginTransaction();await lockActiveCrmOwner(c,actor);
  const [active]=await c.execute<RowDataPacket[]>('SELECT 1 FROM auth_sessions WHERE token_hash=? AND BINARY user_id=BINARY ? AND expires_at>UTC_TIMESTAMP(3) AND mfa_verified_at IS NOT NULL FOR UPDATE',[hashToken(session),actor]);
  if(active.length!==1)stop(403,'SESSION_AUTHORITY_REQUIRED');
  const result=await fn(c);await c.commit();return result;
 }catch(e){await c.rollback();throw e;}finally{c.release();}
}
const cols="id,module,request_sha256,result_json,result_sha256,DATE_FORMAT(created_at,'%Y-%m-%dT%H:%i:%s.%f') AS createdAt";
function view(row:RowDataPacket){return {id:row.id,module:row.module,createdAt:row.createdAt,result:gvVerifyStored({module:row.module,result_json:row.result_json,result_sha256:row.result_sha256})};}
export async function gvCreate(pool:Pool,actor:string,session:string,key:unknown,module:unknown,payload:unknown){
 const requestKey=gvId(key),p=gvPrepare(module,payload);
 return scoped(pool,actor,session,async c=>{
  const [old]=await c.execute<RowDataPacket[]>('SELECT '+cols+' FROM '+GV_TABLE+' WHERE actor_id=? AND request_key=? FOR UPDATE',[actor,requestKey]);
  if(old.length){if(old[0].request_sha256!==p.requestSha256||old[0].module!==p.module)stop(409,'IDEMPOTENCY_CONFLICT');return {...view(old[0]),replayed:true};}
  const id=randomUUID();
  await c.execute('INSERT INTO '+GV_TABLE+'(id,actor_id,request_key,module,request_sha256,result_json,result_sha256) VALUES (?,?,?,?,?,?,?)',[id,actor,requestKey,p.module,p.requestSha256,p.resultJson,p.resultSha256]);
  const [rows]=await c.execute<RowDataPacket[]>('SELECT '+cols+' FROM '+GV_TABLE+' WHERE actor_id=? AND id=?',[actor,id]);if(rows.length!==1)stop(503,'RECORD_INTEGRITY_HOLD');return {...view(rows[0]),replayed:false};
 });
}
export async function gvRead(pool:Pool,actor:string,session:string,id:unknown){
 const recordId=gvId(id);return scoped(pool,actor,session,async c=>{
  const [rows]=await c.execute<RowDataPacket[]>('SELECT '+cols+' FROM '+GV_TABLE+' WHERE actor_id=? AND id=?',[actor,recordId]);if(rows.length!==1)stop(404,'RECORD_NOT_FOUND');return view(rows[0]);
 });
}
export async function gvList(pool:Pool,actor:string,session:string){
 return scoped(pool,actor,session,async c=>{const [rows]=await c.execute<RowDataPacket[]>('SELECT '+cols+' FROM '+GV_TABLE+' WHERE actor_id=? ORDER BY created_at DESC,id DESC LIMIT 50',[actor]);return {items:rows.map(view),releaseDecision:'HOLD',externalExecutionEnabled:false};});
}
