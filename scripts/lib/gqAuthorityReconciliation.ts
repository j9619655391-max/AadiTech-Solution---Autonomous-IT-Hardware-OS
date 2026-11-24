// 1GQ disposable CI only. Read-only consistency check, not restore authorization.
import type {Pool,PoolConnection,RowDataPacket} from 'mysql2/promise';
import {gfMigrationTarget} from '../migrate-gf-provenance';
const registry='auth_gn_intent_nonces_candidate',approval='auth_go_intent_approvals_candidate',keys='auth_go_issuer_keys_candidate';
const specs=[
 {op:'customers',table:'auth_gk_customer_intents_candidate',id:'customer_id',mask:1},
 {op:'leads',table:'auth_gl_lead_intents_candidate',id:'lead_id',mask:2},
 {op:'products',table:'auth_gl_product_intents_candidate',id:'product_id',mask:4},
 {op:'quote-binding',table:'auth_gj_quote_intents_candidate',id:'quote_id',mask:8}
] as const;
export async function gqInspectAuthoritySnapshot(db:Pick<PoolConnection,'query'>){
 gfMigrationTarget(process.env);
 const anomalies:string[]=[];
 const check=async(code:string,sql:string,args:string[]=[])=>{
  const [rows]=await db.query<RowDataPacket[]>(sql,args);
  if(rows.length)anomalies.push(code);
 };
 for(const s of specs){
  const mismatch='NOT (g.consumed_at <=> t.consumed_at) OR BINARY g.actor_id<>BINARY t.actor_id OR BINARY g.entity_id<>BINARY t.'+s.id;
  await check(s.op+':REGISTRY_TO_MODULE','SELECT 1 FROM '+registry+' g LEFT JOIN '+s.table+' t ON t.intent_hash=g.intent_hash WHERE g.operation=? AND (t.intent_hash IS NULL OR '+mismatch+') LIMIT 1',[s.op]);
  await check(s.op+':MODULE_TO_REGISTRY','SELECT 1 FROM '+s.table+' t LEFT JOIN '+registry+' g ON g.intent_hash=t.intent_hash WHERE g.intent_hash IS NULL OR g.operation<>? OR '+mismatch+' LIMIT 1',[s.op]);
  await check(s.op+':CONSUMED_WITHOUT_VALID_RECEIPT','SELECT 1 FROM '+s.table+' t LEFT JOIN '+approval+' a ON a.intent_hash=t.intent_hash LEFT JOIN '+keys+' k ON k.key_id=a.key_id WHERE t.consumed_at IS NOT NULL AND (a.intent_hash IS NULL OR k.key_id IS NULL OR BINARY k.spki_sha256<>BINARY a.spki_sha256 OR a.expires_at<>t.expires_at OR a.approved_at>t.consumed_at OR a.expires_at<=t.consumed_at OR k.not_before>t.consumed_at OR k.not_after<a.expires_at OR (k.scope_mask & '+s.mask+')<>'+s.mask+' OR (k.revoked_at IS NOT NULL AND k.revoked_at<t.consumed_at)) LIMIT 1');
  if(s.op==='quote-binding'){
   await check(s.op+':MISSING_BUSINESS_EVIDENCE','SELECT 1 FROM '+s.table+' t LEFT JOIN sales_quote_create_requests r ON r.actor_id=t.actor_id AND r.request_key=t.request_key LEFT JOIN sales_quote_drafts q ON q.id=t.quote_id WHERE t.consumed_at IS NOT NULL AND (r.quote_id IS NULL OR BINARY r.quote_id<>BINARY t.quote_id OR BINARY r.request_hash<>BINARY t.request_hash OR q.id IS NULL OR BINARY q.created_by<>BINARY t.actor_id) LIMIT 1');
  }else{
   await check(s.op+':MISSING_BUSINESS_EVIDENCE','SELECT 1 FROM '+s.table+' t LEFT JOIN crm_'+s.op+' c ON c.id=t.'+s.id+' LEFT JOIN crm_audit_events a ON a.id=t.audit_id WHERE t.consumed_at IS NOT NULL AND (c.id IS NULL OR a.id IS NULL OR a.operation<>\'CREATE\' OR a.entity_type<>? OR BINARY a.actor_user_id<>BINARY t.actor_id OR BINARY a.entity_id<>BINARY t.'+s.id+' OR a.after_data IS NULL) LIMIT 1',[s.op]);
  }
 }
 await check('ORPHAN_APPROVAL','SELECT 1 FROM '+approval+' a LEFT JOIN '+registry+' g ON g.intent_hash=a.intent_hash WHERE g.intent_hash IS NULL LIMIT 1');
 return {status:anomalies.length?'HOLD' as const:'PASS' as const,anomalies,productionReleaseAuthorized:false as const};
}
// Own a fresh connection and one repeatable-read, read-only snapshot.
// Rollback on every exit; no repair, export of row contents or writes.
export async function gqReconcileAuthority(pool:Pick<Pool,'getConnection'>){
 gfMigrationTarget(process.env);
 const c=await pool.getConnection();
 try{
  await c.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
  await c.query('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
  return await gqInspectAuthoritySnapshot(c);
 }finally{try{await c.rollback();}catch(e){c.destroy();throw e;}finally{c.release();}}
}
