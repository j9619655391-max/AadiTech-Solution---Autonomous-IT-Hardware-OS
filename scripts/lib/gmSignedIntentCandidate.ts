// 1GM: isolated CI issuer-side signature verification candidate only.
// Do not import into application runtime. No live key enrollment or signing service.
import {createHash,createPublicKey,verify} from 'node:crypto';
import type {Pool,ResultSetHeader} from 'mysql2/promise';
import {definitions,validate,type CRMEntity} from '../../server/crm/validation';
import {gfMigrationTarget} from '../migrate-gf-provenance';

export const GM_AUDIENCE='aaditech:disposable-ci:authority-intent:v1';
export type GmOperation='customers'|'leads'|'products'|'quote-binding';
export type GmPinnedKey={
 keyId:string;publicKeyPem:string;spkiSha256:string;notBeforeMs:number;notAfterMs:number;
 revoked:boolean;operations:readonly GmOperation[];
};
export type GmEnvelope={
 version:1;audience:typeof GM_AUDIENCE;keyId:string;operation:GmOperation;
 actorId:string;sessionHash:string;intentHash:string;entityId:string;auditId:string|null;
 issuedAtMs:number;expiresAtMs:number;payload:Record<string,unknown>;
};
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const digest=/^[0-9a-f]{64}$/;
const keyId=/^[a-zA-Z0-9_-]{1,64}$/;
const keys=['version','audience','keyId','operation','actorId','sessionHash','intentHash','entityId','auditId','issuedAtMs','expiresAtMs','payload'];
const operations:readonly GmOperation[]=['customers','leads','products','quote-binding'];
function fail():never{throw Error('GM_INTENT_REJECTED');}
function record(value:unknown):Record<string,unknown>{
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.getPrototypeOf(value)!==Object.prototype)fail();
 const descriptors=Object.getOwnPropertyDescriptors(value);
 if(Reflect.ownKeys(value).length!==Object.keys(descriptors).length||
    Object.values(descriptors).some(x=>!x.enumerable||!('value' in x)))fail();
 return value as Record<string,unknown>;
}
function exact(value:Record<string,unknown>,fields:readonly string[]){
 if(Object.keys(value).length!==fields.length||fields.some(x=>!Object.prototype.hasOwnProperty.call(value,x)))fail();
}
function isText(value:unknown,pattern:RegExp):value is string{return typeof value==='string'&&pattern.test(value);}
function validTime(value:unknown):value is number{return typeof value==='number'&&Number.isSafeInteger(value)&&value>=0&&value<=253402300799999;}
function stableFields(value:Record<string,unknown>){return Object.fromEntries(Object.keys(value).sort().map(k=>[k,value[k]]));}
function validatedPayload(op:GmOperation,value:unknown):Record<string,unknown>{
 const raw=record(value);
 if(op==='quote-binding'){
  exact(raw,['requestKey','requestHash']);
  if(!isText(raw.requestKey,uuid)||!isText(raw.requestHash,digest))fail();
  return stableFields(raw);
 }
 exact(raw,Object.keys(definitions[op as CRMEntity]));
 let checked:Record<string,unknown>;
 try{checked=validate(op as CRMEntity,raw);}catch{return fail();}
 // Signed payload must be canonical, not silently trimmed/rounded/coerced.
 for(const k of Object.keys(raw))if(raw[k]!==checked[k])fail();
 return stableFields(checked);
}
export function gmCanonicalIntent(value:unknown):{envelope:GmEnvelope;bytes:Buffer}{
 const raw=record(value);exact(raw,keys);
 if(raw.version!==1||raw.audience!==GM_AUDIENCE||!isText(raw.keyId,keyId)||
    !operations.includes(raw.operation as GmOperation)||!isText(raw.actorId,uuid)||
    !isText(raw.sessionHash,digest)||!isText(raw.intentHash,digest)||!isText(raw.entityId,uuid)||
    !validTime(raw.issuedAtMs)||!validTime(raw.expiresAtMs)||raw.expiresAtMs<=raw.issuedAtMs||
    raw.expiresAtMs-raw.issuedAtMs>300000)fail();
 if(raw.operation==='quote-binding'?raw.auditId!==null:!isText(raw.auditId,uuid))fail();
 const envelope={...raw,payload:validatedPayload(raw.operation as GmOperation,raw.payload)} as GmEnvelope;
 const bytes=Buffer.from('AADITECH-GM-INTENT-V1\n'+JSON.stringify(stableFields(envelope as unknown as Record<string,unknown>)),'utf8');
 if(bytes.length>65536)fail();
 return {envelope,bytes};
}
export function gmVerifyIntent(value:unknown,signature:unknown,pins:readonly GmPinnedKey[],nowMs:number):GmEnvelope{
 const {envelope,bytes}=gmCanonicalIntent(value);
 if(!validTime(nowMs)||envelope.issuedAtMs>nowMs||envelope.expiresAtMs<=nowMs||
    !isText(signature,/^[A-Za-z0-9_-]{86}$/)||!Array.isArray(pins)||pins.length<1||pins.length>32)fail();
 const matched=pins.filter(k=>k.keyId===envelope.keyId);
 if(matched.length!==1)fail();
 const pin=matched[0];
 if(pin.revoked!==false||!validTime(pin.notBeforeMs)||!validTime(pin.notAfterMs)||
    pin.notBeforeMs>envelope.issuedAtMs||pin.notAfterMs<envelope.expiresAtMs||
    !Array.isArray(pin.operations)||!pin.operations.includes(envelope.operation)||
    !isText(pin.spkiSha256,digest)||typeof pin.publicKeyPem!=='string'||pin.publicKeyPem.length>4096||
    !pin.publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----'))fail();
 try{
  const key=createPublicKey(pin.publicKeyPem);
  if(key.asymmetricKeyType!=='ed25519'||createHash('sha256').update(key.export({format:'der',type:'spki'})).digest('hex')!==pin.spkiSha256)fail();
  const sig=Buffer.from(signature,'base64url');
  if(sig.length!==64||sig.toString('base64url')!==signature||!verify(null,bytes,key,sig))fail();
 }catch{return fail();}
 return envelope;
}
const target={
 customers:{table:'auth_gk_customer_intents_candidate',id:'customer_id'},
 leads:{table:'auth_gl_lead_intents_candidate',id:'lead_id'},
 products:{table:'auth_gl_product_intents_candidate',id:'product_id'}
} as const;
function utcSql(ms:number){return new Date(ms).toISOString().slice(0,23).replace('T',' ');}
// Only approved, separately supplied pins are accepted. No keys from request.
// Caller must use the isolated issuer account, not runtime/admin credentials.
// DB unique keys reject replay within the chosen authority table; no global nonce ledger yet.
export async function gmIssueVerifiedIntent(db:Pick<Pool,'execute'>,value:unknown,signature:unknown,pins:readonly GmPinnedKey[]){
 gfMigrationTarget(process.env);
 const e=gmVerifyIntent(value,signature,pins,Date.now());
 let table:string,columns:string[],values:(string|number|null)[];
 if(e.operation==='quote-binding'){
  table='auth_gj_quote_intents_candidate';
  columns=['intent_hash','actor_id','session_hash','request_key','request_hash','quote_id','expires_at'];
  values=[e.intentHash,e.actorId,e.sessionHash,e.payload.requestKey as string,e.payload.requestHash as string,e.entityId,utcSql(e.expiresAtMs)];
 }else{
  const t=target[e.operation];table=t.table;
  const fields=Object.keys(definitions[e.operation]);
  columns=['intent_hash','actor_id','session_hash',t.id,'audit_id',...fields,'expires_at'];
  values=[e.intentHash,e.actorId,e.sessionHash,e.entityId,e.auditId,...fields.map(k=>e.payload[k] as string|number|null),utcSql(e.expiresAtMs)];
 }
 try{
  const [result]=await db.execute<ResultSetHeader>('INSERT INTO '+table+'('+columns.join(',')+') VALUES ('+columns.map(()=>'?').join(',')+')',values);
  if(result.affectedRows!==1)fail();
 }catch{return fail();}
 return {operation:e.operation,issued:true as const};
}


// 1GN: compare independently supplied pinned key snapshots before accepting a
// rollover. This is a continuity check, NOT authentication of either snapshot.
// Retain all historical key IDs, fingerprints, intervals and operation scopes.
// A previously revoked key cannot be reactivated; a new ID cannot reuse old SPKI.
export function gmValidatePinTransition(previous:readonly GmPinnedKey[],next:readonly GmPinnedKey[],nowMs:number):void{
 if(!validTime(nowMs)||!Array.isArray(previous)||!Array.isArray(next)||!previous.length||
  previous.length>32||next.length>32||next.length<previous.length)fail();
 const validateSet=(pins:readonly GmPinnedKey[])=>{
  const ids=new Set<string>(),fingerprints=new Set<string>();
  for(const pin of pins){
   if(!pin||!isText(pin.keyId,keyId)||!isText(pin.spkiSha256,digest)||
      typeof pin.revoked!=='boolean'||!validTime(pin.notBeforeMs)||!validTime(pin.notAfterMs)||
      pin.notBeforeMs>=pin.notAfterMs||!Array.isArray(pin.operations)||!pin.operations.length||
      pin.operations.some(op=>!operations.includes(op))||new Set(pin.operations).size!==pin.operations.length||
      ids.has(pin.keyId)||fingerprints.has(pin.spkiSha256)||typeof pin.publicKeyPem!=='string'||
      pin.publicKeyPem.length>4096||!pin.publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----'))fail();
   try{
    const key=createPublicKey(pin.publicKeyPem);
    if(key.asymmetricKeyType!=='ed25519'||createHash('sha256').update(key.export({format:'der',type:'spki'})).digest('hex')!==pin.spkiSha256)fail();
   }catch{return fail();}
   ids.add(pin.keyId);fingerprints.add(pin.spkiSha256);
  }
 };
 validateSet(previous);validateSet(next);
 for(const old of previous){
  const current=next.find(p=>p.keyId===old.keyId);
  if(!current||current.spkiSha256!==old.spkiSha256||current.notBeforeMs!==old.notBeforeMs||
     current.notAfterMs!==old.notAfterMs||old.revoked&&!current.revoked||
     JSON.stringify([...current.operations].sort())!==JSON.stringify([...old.operations].sort()))fail();
 }
 // No backdated new key. The independent authority must establish the clock.
 for(const current of next)if(!previous.some(p=>p.keyId===current.keyId)&&current.notBeforeMs<nowMs)fail();
}


// 1GO separate approval adapter. The approval account may SELECT issued
// intent rows and INSERT receipt columns only. No key or issuer write access.
// Match signed payload against the actual immutable issued row before approval.
// SQL checks key status at consumption; it does NOT verify Ed25519 itself.
export async function gmApproveIssuedIntent(db:Pick<Pool,'execute'>,value:unknown,signature:unknown,pins:readonly GmPinnedKey[]){
 gfMigrationTarget(process.env);
 const e=gmVerifyIntent(value,signature,pins,Date.now());
 const pin=pins.find(p=>p.keyId===e.keyId);
 if(!pin)fail();
 const fields=e.operation==='quote-binding'?['request_key','request_hash']:Object.keys(definitions[e.operation]);
 const t=e.operation==='quote-binding'?{table:'auth_gj_quote_intents_candidate',id:'quote_id'}:target[e.operation];
 const expected:Record<string,unknown>={actor_id:e.actorId,session_hash:e.sessionHash,[t.id]:e.entityId};
 if(e.operation==='quote-binding'){expected.request_key=e.payload.requestKey;expected.request_hash=e.payload.requestHash;}
 else{expected.audit_id=e.auditId;for(const k of fields)expected[k]=e.payload[k];}
 const columns=Object.keys(expected);
 // Exact binary string comparison in JS on the selected stored values;
 // mysql2 DECIMAL must remain strings (default). All identifiers fixed above.
 const [rows]=await db.execute<import('mysql2/promise').RowDataPacket[]>(
  'SELECT '+columns.join(',')+", DATE_FORMAT(expires_at,'%Y-%m-%d %H:%i:%s.%f') AS expiry FROM "+t.table+
  ' WHERE intent_hash=? AND consumed_at IS NULL AND expires_at>UTC_TIMESTAMP(3)',[e.intentHash]);
 if(rows.length!==1||rows[0].expiry!==utcSql(e.expiresAtMs)+'000'||columns.some(k=>rows[0][k]!==expected[k]))fail();
 const evidence=createHash('sha256').update(gmCanonicalIntent(e).bytes).update(Buffer.from(signature as string,'base64url')).digest('hex');
 try{
  const [result]=await db.execute<ResultSetHeader>('INSERT INTO auth_go_intent_approvals_candidate(intent_hash,key_id,spki_sha256,evidence_sha256,expires_at) VALUES (?,?,?,?,?)',
   [e.intentHash,e.keyId,pin.spkiSha256,evidence,utcSql(e.expiresAtMs)]);
  if(result.affectedRows!==1)fail();
 }catch{return fail();}
 return {approved:true as const,operation:e.operation};
}
