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
function textValue(value:unknown,max:number,label:string){
 if(typeof value!=='string')throw new ServiceTicketInputError('Invalid '+label);
 const v=value.trim();
 if(!v||v.length>max||/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(v))
  throw new ServiceTicketInputError('Invalid '+label);
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
export function boundedInternalTicketHistory<T>(newestFirst:readonly T[]){
 if(!Array.isArray(newestFirst)||newestFirst.length>INTERNAL_TICKET_HISTORY_LIMIT+1)
  throw Error('Internal ticket history query bound unverified');
 return {
  history:newestFirst.slice(0,INTERNAL_TICKET_HISTORY_LIMIT).reverse(),
  historyLimit:INTERNAL_TICKET_HISTORY_LIMIT,
  historyHasMore:newestFirst.length>INTERNAL_TICKET_HISTORY_LIMIT
 };
}
