import {createHash} from 'node:crypto';
import {
 INTERNAL_TICKET_HISTORY_LIMIT,isInternalTicketStatus,verifyInternalTicketAuditWindow,
 type InternalTicketAuditEvent,type InternalTicketStatus
} from './validation';

// Phase 1FS: this digest is computed from APPLICATION database records only.
// It is NOT a signature, independent WORM attestation, consent or service proof.
export const MAX_INTERNAL_AUDIT_FINGERPRINT_EVENTS=1000;
export class InternalAuditFingerprintLimitError extends Error {}

export interface InternalAuditFingerprintRow extends InternalTicketAuditEvent {
 note:string;
 // Use a DATE_FORMAT string, not the host's timezone-dependent JS Date.
 createdAtSql:string;
}
export type InternalAuditWindowReader<T extends InternalAuditFingerprintRow>=
 (beforeVersion?:number)=>Promise<readonly T[]>;

// Fixed versioned serialization and descending event order make the same
// intact stored internal audit repeatably hash to the same value. No secrets,
// customer PII, note content or per-event details leave this helper.
export async function computeInternalAuditFingerprint<T extends InternalAuditFingerprintRow>(
 ticket:{id:string;version:number;status:InternalTicketStatus},
 readWindow:InternalAuditWindowReader<T>
){
 if(!Number.isSafeInteger(ticket.version)||ticket.version<1||
    ticket.version>2147483647||!isInternalTicketStatus(ticket.status))
  throw Error('1FS internal audit anchor unverified');
 if(ticket.version>MAX_INTERNAL_AUDIT_FINGERPRINT_EVENTS)
  throw new InternalAuditFingerprintLimitError('Bounded internal audit fingerprint cap reached');
 const hash=createHash('sha256');
 hash.update('aaditech/internal-ticket-audit/sha256/v1\n');
 hash.update(JSON.stringify([ticket.id,ticket.version,ticket.status])+'\n');
 let cursor:number|undefined,seen=0;
 for(;;){
  const newest=await readWindow(cursor);
  const page=verifyInternalTicketAuditWindow(newest,{
   currentVersion:ticket.version,currentStatus:ticket.status,beforeVersion:cursor
  });
  // Check each page for valid stored text and fixed-format DB timestamp.
  // The SHA digest is not an authenticity guarantee if a privileged actor
  // changes both the underlying rows and the local fingerprint.
  for(const row of [...page.history].reverse()){
   if(typeof row.note!=='string'||!row.note.length||row.note.length>500||
      typeof row.createdAtSql!=='string'||
      !/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}$/.test(row.createdAtSql))
    throw Error('1FS invalid internal audit canonical event');
   hash.update(JSON.stringify([row.versionAfter,row.operation,row.fromStatus,
    row.toStatus,row.note,row.createdAtSql])+'\n');
   seen++;
   if(seen>MAX_INTERNAL_AUDIT_FINGERPRINT_EVENTS||seen>ticket.version)
    throw Error('1FS audit history count exceeded anchor');
  }
  if(!page.historyHasMore)break;
  if(page.nextBeforeVersion===null||page.nextBeforeVersion>=ticket.version||
     seen>MAX_INTERNAL_AUDIT_FINGERPRINT_EVENTS-INTERNAL_TICKET_HISTORY_LIMIT)
   throw Error('1FS bounded internal audit continuation invalid');
  cursor=page.nextBeforeVersion;
 }
 if(seen!==ticket.version)throw Error('1FS audit history total differs from ticket version');
 return {
  algorithm:'SHA-256' as const,format:'aaditech/internal-ticket-audit/sha256/v1' as const,
  auditDigestSha256:hash.digest('hex'),eventCount:seen,latestVersion:ticket.version,
  scope:'APPLICATION_UNATTESTED' as const,signatureVerified:false as const,
  externalAnchorVerified:false as const,customerConsentVerified:false as const,
  mode:'INTERNAL_HELD' as const,externalDispatchEnabled:false as const
 };
}
