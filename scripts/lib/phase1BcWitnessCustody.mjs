import {createHash} from 'node:crypto';
import {phase1AzAssessReadiness} from './phase1AzExternalReadiness.mjs';
import {assessPhase1BbWitnessConsistency} from './phase1BbWitnessConsistency.mjs';

// Phase 1BC: OFFLINE candidate transparency-head custody. Neither locally
// signed heads nor a caller-provided SPKI establish external independence,
// operational authority, source authenticity, WORM, encrypted DR or release.
const SHA=/^[0-9a-f]{64}$/;
const BASE=['INDEPENDENT_SOURCE_OF_TRUTH_NOT_AUTHENTICATED',
 'EXTERNAL_WITNESS_KEY_CUSTODY_NOT_CONFIRMED',
 'EXTERNAL_WORM_AUDIT_NOT_VERIFIED',
 'ENCRYPTED_RESTORE_AND_LEGAL_APPROVAL_NOT_VERIFIED'];
const digest=value=>createHash('sha256').update('AADITECH-PHASE-1BC-OBSERVED-CUSTODY-V1\0')
 .update(JSON.stringify(value)).digest('hex');
function head(value){
 if(typeof value!=='string')throw Error('1BC missing signed Merkle head');
 const p=value.indexOf('|');
 if(p<1||p>10)throw Error('1BC malformed signed Merkle head');
 const size=Number(value.slice(0,p)),root=value.slice(p+1);
 if(!Number.isSafeInteger(size)||size<1||size>1_000_000_000||!SHA.test(root))
  throw Error('1BC invalid Merkle head size or hash');
 return {size,root};
}
export function assessPhase1BcWitnessCustody({azPacket=null,observations=[],now=new Date()}={}){
 if(!(now instanceof Date)||!Number.isFinite(now.getTime())||
   !Array.isArray(observations)||observations.length>8)
  throw Error('1BC invalid clock or bounded observations');
 const blockers=new Set(BASE);
 const deny=(extra={})=>Object.freeze({phase:'1BC',
  claimCryptographicallyConsistent:false,packetSha256:null,pinSetSha256:null,
  evidenceSha256:null,oldTreeSize:null,oldRootSha256:null,
  newTreeSize:null,newRootSha256:null,...extra,
  sourceOfTruthAuthenticated:false,independentKeyCustodyVerified:false,
  immutableStorageVerified:false,actualEncryptedRestoreVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD',
  blockerCodes:Object.freeze([...blockers].sort())});
 if(!azPacket||observations.length<2){
  blockers.add('MISSING_CANDIDATE_WITNESS_EVIDENCE');
  return deny();
 }
 const az=phase1AzAssessReadiness(azPacket,{now});
 const report=assessPhase1BbWitnessConsistency({azPacket,observations,now});
 if(!az.packetInspected||!az.internalEvidenceConsistent||
   !report.internalAppendOnlyConsistent)
  blockers.add('CANDIDATE_PROOF_OR_ENROLLMENT_INVALID');
 let oldTreeSize=null,oldRootSha256=null,newTreeSize=null,newRootSha256=null;
 if(report.oldTreeHead!==null&&report.newTreeHead!==null){
  const old=head(report.oldTreeHead),next=head(report.newTreeHead);
  oldTreeSize=old.size;oldRootSha256=old.root;
  newTreeSize=next.size;newRootSha256=next.root;
  if(next.size<=old.size)blockers.add('NO_FORWARD_APPEND_ONLY_PROGRESS');
 }else blockers.add('MISSING_HISTORICAL_AND_CURRENT_ROOTS');
 // Digest-only key-custody commitment. This is NOT an out-of-band key pin.
 const expected=azPacket.witnesses.map(w=>[
  w.witnessRef,w.organizationRef,w.administrativeAuthorityRef,
  w.publicKeySpkiSha256
 ]).sort((a,b)=>a[0].localeCompare(b[0]));
 const observed=observations.map(x=>[
  x.current?.body?.witnessRef,x.current?.body?.organizationRef,
  x.pin?.authorityRef,x.pin?.publicKeySha256
 ]).sort((a,b)=>String(a[0]).localeCompare(String(b[0])));
 if(JSON.stringify(expected)!==JSON.stringify(observed))
  blockers.add('SELF_SUPPLIED_PIN_SET_MISMATCH');
 const pinSetSha256=digest(['WITNESS_PIN_CANDIDATES',expected]);
 const claims=observations.map(x=>[
  x.current.body.witnessRef,x.pin.publicKeySha256,
  x.previous.body,x.previous.signature,
  x.previous.inclusionProofSha256,x.current.body,
  x.current.signature,x.current.inclusionProofSha256,
  x.consistencyProofSha256
 ]).sort((a,b)=>a[0].localeCompare(b[0]));
 const evidenceSha256=digest(['CANDIDATE_PROOF_EVIDENCE',az.packetSha256,
  oldTreeSize,oldRootSha256,newTreeSize,newRootSha256,claims]);
 const errors=[...blockers].filter(x=>!BASE.includes(x));
 return Object.freeze({phase:'1BC',
  claimCryptographicallyConsistent:errors.length===0,
  packetSha256:az.packetSha256,pinSetSha256,evidenceSha256,
  oldTreeSize,oldRootSha256,newTreeSize,newRootSha256,
  distinctClaimedWitnessAdministrators:report.distinctClaimedAuthorities,
  sourceOfTruthAuthenticated:false,independentKeyCustodyVerified:false,
  immutableStorageVerified:false,actualEncryptedRestoreVerified:false,
  productionReleaseAuthorized:false,productionReleaseBlocked:true,
  releaseDecision:'HOLD',
  blockerCodes:Object.freeze([...blockers].sort())});
}
