import {validId} from '../crm/repository';
import {troubleGuideById} from '../troubleshooting/guides';

export class ServiceTicketInputError extends Error {}
export type InternalTicketStatus='OPEN_INTERNAL'|'TRIAGED_INTERNAL'|'WAITING_INTERNAL'|'RESOLVED_HELD';
export type TicketPriority='LOW'|'NORMAL'|'HIGH';
const statuses:readonly InternalTicketStatus[]=['OPEN_INTERNAL','TRIAGED_INTERNAL','WAITING_INTERNAL','RESOLVED_HELD'];
const transitions:Record<InternalTicketStatus,readonly InternalTicketStatus[]>={
 OPEN_INTERNAL:['TRIAGED_INTERNAL'],
 TRIAGED_INTERNAL:['WAITING_INTERNAL','RESOLVED_HELD'],
 WAITING_INTERNAL:['TRIAGED_INTERNAL'],
 RESOLVED_HELD:[]
};
// Phase 1FT: block HIGH-CONFIDENCE credential material at admission.
// This is not a DLP/PII guarantee. Do not attempt to redact-and-store secrets;
// reject the whole request so raw credentials cannot enter service ticket audit.
const credentialIndicators:readonly RegExp[]=[
 /-----BEGIN (?:[A-Z ]{0,24})?PRIVATE KEY-----/i,
 /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
 /\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}\b/,
 /\bxox[baprs]-[A-Za-z0-9-]{16,}\b/,
 /\baaditech_session=[A-Za-z0-9_-]{16,}\b/i,
 /\bauthorization\s*:\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{18,}={0,2}\b/i,
 /\b(?:password|passwd|pwd|api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|private[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9_+/.!@#$%&*=-]{12,}/i,
 /(?:^|[\s"'(])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?=$|[\s"')])/
];
export function rejectCredentialLikeTicketText(value:string):void{
 if(credentialIndicators.some(re=>re.test(value)))
  throw new ServiceTicketInputError(
   'Credential-like content is not allowed in internal ticket text; omit secrets and retry');
}
// Phase 1FU: deny direct reads of HIGH-CONFIDENCE credential-bearing legacy
// text without mutating the original stored audit or claiming full DLP.
export const INTERNAL_TICKET_MASK='[REDACTED: possible credential in legacy internal text]';
export function maskCredentialLikeTicketText(value:unknown){
 if(typeof value!=='string')throw Error('Internal ticket projection text integrity unverified');
 const redacted=credentialIndicators.some(re=>re.test(value));
 return {text:redacted?INTERNAL_TICKET_MASK:value,redacted};
}
function textValue(value:unknown,max:number,label:string){
 if(typeof value!=='string')throw new ServiceTicketInputError('Invalid '+label);
 const v=value.trim();
 if(!v||v.length>max||/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(v))
  throw new ServiceTicketInputError('Invalid '+label);
 rejectCredentialLikeTicketText(v);
 return v;
}
function keys(value:unknown,allowed:readonly string[]){
 if(!value||typeof value!=='object'||Array.isArray(value)||
  Object.keys(value).some(k=>!allowed.includes(k)))
  throw new ServiceTicketInputError('Unexpected ticket fields');
}
export function validateTicketCreate(body:unknown){
 keys(body,['customerId','guideId','subject','description','priority','acknowledgeUnverifiedConsent']);
 const input=body as Record<string,unknown>;
 if(!validId(input.customerId))throw new ServiceTicketInputError('Valid customer ID required');
 if(input.acknowledgeUnverifiedConsent!==true)
  throw new ServiceTicketInputError('Acknowledge that customer consent is NOT verified');
 if(typeof input.guideId!=='string'||!troubleGuideById(input.guideId))
  throw new ServiceTicketInputError('Choose an existing troubleshooting guide');
 if(input.priority!=='LOW'&&input.priority!=='NORMAL'&&input.priority!=='HIGH')
  throw new ServiceTicketInputError('Invalid priority');
 return {customerId:input.customerId,guideId:input.guideId,
  subject:textValue(input.subject,180,'subject'),
  description:textValue(input.description,2000,'description'),
  priority:input.priority};
}
export function validateTicketTransition(body:unknown,current:InternalTicketStatus){
 keys(body,['expectedVersion','nextStatus','note']);
 const input=body as Record<string,unknown>;
 if(!Number.isSafeInteger(input.expectedVersion)||Number(input.expectedVersion)<1||Number(input.expectedVersion)>2147483646)
  throw new ServiceTicketInputError('Invalid ticket version');
 if(typeof input.nextStatus!=='string'||!statuses.includes(input.nextStatus as InternalTicketStatus)||
  !transitions[current].includes(input.nextStatus as InternalTicketStatus))
  throw new ServiceTicketInputError('Invalid internal status transition');
 return {expectedVersion:input.expectedVersion as number,
  nextStatus:input.nextStatus as InternalTicketStatus,note:textValue(input.note,500,'transition note')};
}
export function isInternalTicketStatus(value:unknown):value is InternalTicketStatus{
 return typeof value==='string'&&statuses.includes(value as InternalTicketStatus);
}

// Phase 1FP: never let a single internal ticket detail GET materialize
// unbounded audit events. The SQL caller selects newest first with LIMIT 101;
// this restores chronological order for the newest 100 while accurately
// reporting whether older internal entries require future governed paging.
export const INTERNAL_TICKET_HISTORY_LIMIT=100;
export function boundedInternalTicketHistory<T extends {versionAfter:number}>(newestFirst:readonly T[]){
 if(!Array.isArray(newestFirst)||newestFirst.length>INTERNAL_TICKET_HISTORY_LIMIT+1)
  throw Error('Internal ticket history query bound unverified');
 const history=newestFirst.slice(0,INTERNAL_TICKET_HISTORY_LIMIT).reverse();
 if(history.some(entry=>!Number.isSafeInteger(entry.versionAfter)||entry.versionAfter<1))
  throw Error('Internal ticket audit version integrity unverified');
 for(let i=1;i<history.length;i++){
  if(history[i].versionAfter<=history[i-1].versionAfter)
   throw Error('Internal ticket audit order integrity unverified');
 }
 const historyHasMore=newestFirst.length>INTERNAL_TICKET_HISTORY_LIMIT;
 return {history,historyLimit:INTERNAL_TICKET_HISTORY_LIMIT,historyHasMore,
  nextBeforeVersion:historyHasMore?history[0].versionAfter:null};
}

// Phase 1FQ: keyset-only older-audit query. No arbitrary OFFSET, loose
// coercion, duplicate query inputs or unbounded page-size control.
export function parseInternalTicketHistoryCursor(query:unknown):number{
 if(!query||typeof query!=='object'||Array.isArray(query)||
    Object.keys(query).length!==1||!Object.prototype.hasOwnProperty.call(query,'beforeVersion'))
  throw new ServiceTicketInputError('Exact beforeVersion query required');
 const value=(query as Record<string,unknown>).beforeVersion;
 if(typeof value!=='string'||!/^[1-9][0-9]{0,9}$/.test(value))
  throw new ServiceTicketInputError('Invalid audit history cursor');
 const number=Number(value);
 if(!Number.isSafeInteger(number)||number>2147483647)
  throw new ServiceTicketInputError('Invalid audit history cursor');
 return number;
}

// Phase 1FR: an API success must not silently invent a complete, internally
// consistent ticket history when the SQL ledger is missing or mutated. This
// checks application event continuity, NOT cryptographic authenticity.
export interface InternalTicketAuditEvent {
 versionAfter:number;
 operation:'CREATE'|'STATUS_CHANGE';
 fromStatus:InternalTicketStatus|null;
 toStatus:InternalTicketStatus;
}
export function verifyInternalTicketAuditWindow<T extends InternalTicketAuditEvent>(
 newestFirst:readonly T[],
 context:{currentVersion:number;currentStatus:InternalTicketStatus;beforeVersion?:number}
){
 const {currentVersion,currentStatus,beforeVersion}=context;
 if(!Number.isSafeInteger(currentVersion)||currentVersion<1||
    currentVersion>2147483647||!isInternalTicketStatus(currentStatus)||
    (beforeVersion!==undefined&&(!Number.isSafeInteger(beforeVersion)||
      beforeVersion<1||beforeVersion>currentVersion+1)))
  throw Error('1FR ticket audit anchor invalid');
 const window=boundedInternalTicketHistory(newestFirst);
 const {history,historyHasMore}=window;
 // A genuine ticket always has a CREATE(version=1) audit record. Empty
 // pages are only valid when querying older than version 1.
 if(!history.length){
  if(beforeVersion!==1)throw Error('1FR audit record missing');
  return window;
 }
 const expectedTop=beforeVersion===undefined?currentVersion:beforeVersion-1;
 if(history[history.length-1].versionAfter!==expectedTop)
  throw Error('1FR audit page top not contiguous with requested anchor');
 if(beforeVersion===undefined&&history[history.length-1].toStatus!==currentStatus)
  throw Error('1FR audit latest state drift');
 if(!historyHasMore&&history[0].versionAfter!==1)
  throw Error('1FR audit CREATE missing from oldest bounded page');
 // The extra 101st record is a real adjoining event, not a fabricated
 // hasMore flag pointing across an undetected gap.
 if(historyHasMore){
  const sentinel=newestFirst[INTERNAL_TICKET_HISTORY_LIMIT];
  if(sentinel.versionAfter!==history[0].versionAfter-1||
     sentinel.toStatus!==history[0].fromStatus)
   throw Error('1FR audit sentinel gap or status mismatch');
  if(sentinel.versionAfter===1){
   if(sentinel.operation!=='CREATE'||sentinel.fromStatus!==null||
      sentinel.toStatus!=='OPEN_INTERNAL')throw Error('1FR audit sentinel genesis invalid');
  }else if(sentinel.operation!=='STATUS_CHANGE'||
    !isInternalTicketStatus(sentinel.fromStatus)||
    !isInternalTicketStatus(sentinel.toStatus)||
    !transitions[sentinel.fromStatus].includes(sentinel.toStatus))
   throw Error('1FR audit sentinel transition invalid');
 }
 for(let i=0;i<history.length;i++){
  const row=history[i];
  if(i>0){
   const previous=history[i-1];
   if(row.versionAfter!==previous.versionAfter+1||
      row.fromStatus!==previous.toStatus)
    throw Error('1FR audit event sequence inconsistent');
  }
  if(row.versionAfter===1){
   if(row.operation!=='CREATE'||row.fromStatus!==null||
      row.toStatus!=='OPEN_INTERNAL')
    throw Error('1FR audit genesis invalid');
  }else if(row.operation!=='STATUS_CHANGE'||
   !isInternalTicketStatus(row.fromStatus)||
   !isInternalTicketStatus(row.toStatus)||
   !transitions[row.fromStatus].includes(row.toStatus)){
   throw Error('1FR audit transition invalid');
  }
 }
 return window;
}
