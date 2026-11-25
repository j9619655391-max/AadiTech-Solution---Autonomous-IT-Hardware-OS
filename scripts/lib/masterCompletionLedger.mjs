import {readFileSync,existsSync} from 'node:fs';
import {createHash} from 'node:crypto';
const FILE=new URL('../../docs/completion/REMAINING_M01_M30_ACCEPTANCE_LEDGER.json',import.meta.url);
export const ALLOWED_STATUSES=Object.freeze([
 'SERVER_INTERNAL_HELD','LEGACY_PREVIEW_ONLY',
 'INTERNAL_DENY_ONLY','INTERNAL_HELD','INTERNAL_UNTRUSTED_PROOFS'
]);
export function assessMasterCompletionLedger(ledger){
 const issues=[];
 const object=ledger&&typeof ledger==='object'&&!Array.isArray(ledger)&&
  Object.getPrototypeOf(ledger)===Object.prototype;
 if(!object)return Object.freeze({releaseDecision:'HOLD',
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  ledgerStructurallyValid:false,issueCodes:Object.freeze(['INVALID_LEDGER'])});
 if(ledger.schemaVersion!==1||
    ledger.sourceRepository!=='j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS'||
    ledger.sourceBranch!=='chore/phase0-foundation-20261106'||
    ledger.releaseDecision!=='HOLD'||
    ledger.productionReleaseAuthorized!==false||
    ledger.productionReleaseBlocked!==true||
    ledger.independentExternalAcceptanceVerified!==false)
  issues.push('ILLEGAL_RELEASE_OR_REPOSITORY_BOUNDARY');
 const entries=ledger.modules;
 if(!Array.isArray(entries)||entries.length!==30){
  issues.push('MISSING_MODULE_TRACKS');
 }else{
  const ids=new Set();
  for(let i=0;i<entries.length;i++){
   const m=entries[i];
   if(!m||typeof m!=='object'||Array.isArray(m)||
      Object.getPrototypeOf(m)!==Object.prototype){
    issues.push('INVALID_MODULE_ENTRY');continue;
   }
   const expected='M'+String(i+1).padStart(2,'0');
   if(m.id!==expected||ids.has(m.id))issues.push('DUPLICATE_OR_MISORDERED_MODULE_ID');
   ids.add(m.id);
   if(!ALLOWED_STATUSES.includes(m.engineeringStatus)||
      typeof m.name!=='string'||m.name.length<10||
      typeof m.remainingAcceptanceGate!=='string'||m.remainingAcceptanceGate.length<25)
    issues.push('CLAIMED_COMPLETION_WITHOUT_ACCEPTANCE');
   if(m.evidenceOwner!=='UNASSIGNED'||m.securityReviewer!=='UNASSIGNED'||
      m.operationsReviewer!=='UNASSIGNED'||
      m.signedAcceptanceEvidence!==null||m.realExternalAuthorityVerified!==false||
      m.productionEnabled!==false||m.releaseDecision!=='HOLD')
    issues.push('UNAUTHORIZED_MODULE_EVIDENCE_PROMOTION');
   for(const path of [m.sourcePath,m.internalTestReference]){
    if(typeof path!=='string'||!/^((src|server|scripts|tests)\/)[a-zA-Z0-9_./-]+$/.test(path)||
       path.includes('..')||!existsSync(path))
     issues.push('BROKEN_OR_UNREVIEWED_MODULE_REFERENCE');
   }
  }
 }
 const counts={};
 for(const m of Array.isArray(entries)?entries:[])
  if(typeof m?.engineeringStatus==='string')
   counts[m.engineeringStatus]=(counts[m.engineeringStatus]||0)+1;
 return Object.freeze({
  releaseDecision:'HOLD',productionReleaseAuthorized:false,
  productionReleaseBlocked:true,
  ledgerStructurallyValid:issues.length===0,
  trackedModules:Array.isArray(entries)?entries.length:0,
  moduleStatusCounts:Object.freeze(counts),
  genuineExternalEvidenceVerified:false,
  approvedCustomerDispatch:false,
  officialInventoryAndFinancePosting:false,
  blockerCodes:Object.freeze([...new Set(issues)].sort()),
  ledgerSha256:createHash('sha256').update(JSON.stringify(ledger)).digest('hex')
 });
}
export function loadMasterCompletionLedger(){
 return JSON.parse(readFileSync(FILE,'utf8'));
}
