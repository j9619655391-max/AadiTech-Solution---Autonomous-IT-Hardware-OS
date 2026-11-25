import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {
 REPO,ROLES as SOURCES,canonical,
 signingBytes,assessCandidateRemoteQuorum
} from '../scripts/phase1cx-pinned-external-source-highwatermark.mjs';
import {
 DOMAIN,OFFICERS,candidateBytes,assessOperatorPinLifecycle
} from '../scripts/phase1cy-operator-pin-lifecycle-quarantine.mjs';

const NOW='2026-11-20T00:00:00.000Z';
const H='d'.repeat(40),BASE='e'.repeat(40),
 POLICY='f'.repeat(64),CV='1'.repeat(64),NONCE='2'.repeat(64);
const dig=x=>createHash('sha256').update(x).digest('hex');
function keyRecord(keyId){
 const pair=generateKeyPairSync('ed25519'),
  pem=pair.publicKey.export({type:'spki',format:'pem'}).toString();
 return {privateKey:pair.privateKey,keyId,publicKeyPem:pem,
  spkiSha256:dig(pair.publicKey.export({type:'spki',format:'der'}))};
}
function signed(type,role,statement,privateKey,keyId){
 return {role,keyId,algorithm:'Ed25519',
  signature:sign(null,Buffer.from(DOMAIN+type+'/'+role+'/v1\n'+
   canonical(statement)),privateKey).toString('base64')};
}
function sourceSigned(role,statement,key){
 return {statement,signature:{keyId:key.keyId,algorithm:'Ed25519',
  signature:sign(null,signingBytes(role,statement),key.privateKey)
   .toString('base64')}};
}
function fixture(){
 const sources={},observations={},srcKeys={},priorKeys={},officerKeys={};
 for(const [i,role] of SOURCES.entries()){
  const key=keyRecord(role.toLowerCase().replaceAll('_','-')+'-key-v1');
  srcKeys[role]=key;priorKeys[role]=key;
  sources[role]={
   host:['revocation.custody-example.com','witness-a.custody-example.net',
    'witness-b.custody-example.org'][i],
   path:role==='REVOCATION'?'/v1/revocations/current.json':
    '/v1/checkpoints/latest.json',
   tlsSpkiSha256:String(i+3).repeat(64),
   signerSpkiSha256:key.spkiSha256,publicKeyPem:key.publicKeyPem,
   keyId:key.keyId
  };
 }
 const previousAnchor={
  epoch:7,checkpointDigest:'a'.repeat(64),
  revocationVersion:9,revocationDigest:'b'.repeat(64),
  observedAt:'2026-11-19T23:48:00.000Z'
 };
 const manifest={
  schemaVersion:1,repository:REPO,currentHeadSha:H,mainBaseSha:BASE,
  policyFingerprintSha256:POLICY,cvCandidateSha256:CV,nonce:NONCE,
  previousAnchor:structuredClone(previousAnchor),
  sources:structuredClone(sources)
 };
 const rev={schemaVersion:1,repository:REPO,sourceHeadSha:H,
  policyFingerprintSha256:POLICY,cvCandidateSha256:CV,
  epoch:8,checkpointDigest:'c'.repeat(64),
  previousCheckpointDigest:'a'.repeat(64),version:10,
  previousVersion:9,previousRevocationDigest:'b'.repeat(64),
  revokedKeyIds:[],nonce:NONCE,
  issuedAt:'2026-11-19T23:55:00.000Z',
  expiresAt:'2026-11-20T00:05:00.000Z'};
 const revDigest=dig(signingBytes('REVOCATION',rev));
 const witness={schemaVersion:1,repository:REPO,sourceHeadSha:H,
  policyFingerprintSha256:POLICY,cvCandidateSha256:CV,epoch:8,
  checkpointDigest:'c'.repeat(64),
  previousCheckpointDigest:'a'.repeat(64),revocationDigest:revDigest,
  nonce:NONCE,archiveDigest:POLICY,objectVersion:'remote-version-123',
  observedAt:'2026-11-19T23:57:00.000Z',
  expiresAt:'2026-11-20T00:06:00.000Z'};
 const statements={
  REVOCATION:rev,WITNESS_A:structuredClone(witness),
  WITNESS_B:structuredClone(witness)
 };
 for(const role of SOURCES){
  const spec=sources[role],key=srcKeys[role];
  observations[role]={status:'read',host:spec.host,path:spec.path,
   peerSpkiSha256:spec.tlsSpkiSha256,httpStatus:200,redirectCount:0,
   data:sourceSigned(role,statements[role],key)};
 }
 const officers={};
 for(const role of OFFICERS){
  const key=keyRecord(role.toLowerCase().replaceAll('_','-')+'-v1');
  officerKeys[role]=key;
  officers[role]={role,organizationId:'aaditech-candidate-organization',
   githubLogin:role==='SECURITY_OFFICER'?'candidate-security':'candidate-business',
   mandateDigest:role==='SECURITY_OFFICER'?'6'.repeat(64):'7'.repeat(64),
   keyId:key.keyId,publicKeyPem:key.publicKeyPem,
   spkiSha256:key.spkiSha256,
   validFrom:'2026-11-19T22:00:00.000Z',
   validUntil:'2026-11-21T00:00:00.000Z',revoked:false};
 }
 const previous={anchor:structuredClone(previousAnchor),
  sources:structuredClone(sources),officers};
 const statement={
  schemaVersion:1,kind:'CANDIDATE_OPERATOR_PIN_HANDOFF_HOLD',
  repository:REPO,sourceHeadSha:H,mainBaseSha:BASE,
  policyFingerprintSha256:POLICY,cvCandidateSha256:CV,
  nonce:NONCE,previousEpoch:7,
  previousCheckpointDigest:'a'.repeat(64),previousRevocationVersion:9,
  previousRevocationDigest:'b'.repeat(64),nextEpoch:8,
  nextCheckpointDigest:'c'.repeat(64),nextRevocationVersion:10,
  nextRevocationDigest:revDigest,
  previousSourceDigest:dig(canonical(previous.sources)),
  nextSourceDigest:dig(canonical(manifest.sources)),
  issuedAt:'2026-11-19T23:58:00.000Z',
  expiresAt:'2026-11-20T00:07:00.000Z',
  decision:'HOLD'
 };
 const officerSignatures=OFFICERS.map(role=>
  signed('handoff',role,statement,officerKeys[role].privateKey,
   officerKeys[role].keyId));
 const historicalWitnesses=['WITNESS_A','WITNESS_B'].map(role=>{
  const s={schemaVersion:1,role,repository:REPO,sourceHeadSha:H,
   epoch:7,checkpointDigest:'a'.repeat(64),revocationVersion:9,
   revocationDigest:'b'.repeat(64),challengeNonce:NONCE,
   observedAt:'2026-11-19T23:52:00.000Z'};
  return {statement:s,signature:signed('historical-anchor',role,s,
   priorKeys[role].privateKey,priorKeys[role].keyId)};
 });
 return {manifest,observations,previous,statement,officerSignatures,
  rotations:[],historicalWitnesses,
  incidents:{status:'CLEAR',forkReports:[],recoveryRequested:'NONE'},
  now:NOW,privateState:{srcKeys,priorKeys,officerKeys}};
}
function rotate(f,role,{signer=true,host=false,tls=false}={}){
 const sp=f.manifest.sources[role],previous=f.previous.sources[role];
 if(signer){
  const newKey=keyRecord(role.toLowerCase().replaceAll('_','-')+'-key-v2');
  f.privateState.srcKeys[role]=newKey;
  sp.keyId=newKey.keyId;
  sp.publicKeyPem=newKey.publicKeyPem;
  sp.signerSpkiSha256=newKey.spkiSha256;
 }
 if(host)sp.host='rotated-'+role.toLowerCase().replaceAll('_','-')+'.custody-example.io';
 if(tls)sp.tlsSpkiSha256='9'.repeat(64);
 const obs=f.observations[role];obs.host=sp.host;
 obs.peerSpkiSha256=sp.tlsSpkiSha256;
 obs.data=sourceSigned(role,obs.data.statement,f.privateState.srcKeys[role]);
 f.statement.nextSourceDigest=dig(canonical(f.manifest.sources));
 f.officerSignatures=OFFICERS.map(r=>signed('handoff',r,f.statement,
  f.privateState.officerKeys[r].privateKey,f.privateState.officerKeys[r].keyId));
 const statement={
  schemaVersion:1,repository:REPO,role,
  handoffDigest:dig(candidateBytes('handoff',f.statement)),
  previousKeyId:previous.keyId,nextKeyId:sp.keyId,
  previousTlsPin:previous.tlsSpkiSha256,nextTlsPin:sp.tlsSpkiSha256,
  previousSignerPin:previous.signerSpkiSha256,nextSignerPin:sp.signerSpkiSha256,
  previousHost:previous.host,nextHost:sp.host,
  previousPath:previous.path,nextPath:sp.path
 };
 const prevKey=f.privateState.priorKeys[role],
  nextKey=f.privateState.srcKeys[role];
 f.rotations.push({role,
  previousSignature:signed('rotation',role,statement,prevKey.privateKey,prevKey.keyId),
  successorSignature:signed('rotation',role,statement,nextKey.privateKey,nextKey.keyId)});
}
const get=edit=>{const f=fixture();edit?.(f);return assessOperatorPinLifecycle(f)};
function denied(edit,code){
 const r=get(edit);
 assert.equal(r.operatorPinLifecycleCandidateMathematicallyConsistent,false);
 assert.ok(r.anomalyCodes.includes(code),'wanted '+code+', got '+r.anomalyCodes.join('|'));
 assert.equal(r.quarantineRequired,true);
 assert.equal(r.automaticRecoveryOrUnquarantineAllowed,false);
 assert.equal(r.productionReleaseAuthorized,false);
 assert.equal(r.releaseDecision,'HOLD');
}
test('CY: synthetic two officer approvals and prior witness signatures mathematically pass, never grant GO',()=>{
 const r=get();
 assert.equal(r.operatorPinLifecycleCandidateMathematicallyConsistent,true,
  r.anomalyCodes.join('|'));
 assert.equal(r.priorThreeSourceCandidateVerified,true);
 assert.equal(r.twoClaimedOfficerAcknowledgmentsMathematicallyVerified,true);
 assert.equal(r.twoPriorWitnessCheckpointSignaturesVerified,true);
 assert.equal(r.requiredRotationsCount,0);
 assert.equal(r.verifiedRotationsCount,0);
 assert.equal(r.quarantineRequired,false);
 assert.match(r.candidateTransitionDigestSha256,/^[a-f0-9]{64}$/);
 for(const k of ['authorizedCorporateOperatorMandatesIndependentlyAuthenticated',
  'independentOldNewSourceKeyAndTlsPinEnrollmentVerified',
  'independentlyRetrievedPriorWitnessHighWatermarkVerified',
  'durableOffsiteReplayForkQuarantineStateVerified',
  'incidentClearanceAndIndependentRecoveryApprovalVerified',
  'currentHeadEnforcedGithubRulesetsCodeownersReviewVerified',
  'genuineProviderCcaRcaiEmudhraMcaAndStagingVerified',
  'independentOidcSlsaWormDrAttestationVerified',
  'productionReleaseAuthorized','automaticRecoveryOrUnquarantineAllowed'])
  assert.equal(r[k],false,k);
 assert.equal(r.releaseDecision,'HOLD');
});
test('CY: real detached ED25519 old-and-new signer co-signing permits candidate pin rotation only',()=>{
 const f=fixture();rotate(f,'REVOCATION',{signer:true,tls:true,host:true});
 const r=assessOperatorPinLifecycle(f);
 assert.equal(r.operatorPinLifecycleCandidateMathematicallyConsistent,true,
  r.anomalyCodes.join('|'));
 assert.equal(r.requiredRotationsCount,1);
 assert.equal(r.verifiedRotationsCount,1);
 assert.equal(r.productionReleaseAuthorized,false);
});
test('CY: TLS-only rotation still requires old and successor signing acknowledgment',()=>{
 const f=fixture();rotate(f,'WITNESS_B',{signer:false,tls:true});
 const r=assessOperatorPinLifecycle(f);
 assert.equal(r.operatorPinLifecycleCandidateMathematicallyConsistent,true,
  r.anomalyCodes.join('|'));
 assert.equal(r.requiredRotationsCount,1);
});
test('CY: canonical candidate domain contains no unsound JSON type',()=>{
 assert.equal(candidateBytes('handoff',{z:2,a:1}).toString(),
  DOMAIN+'handoff/v1\n{"a":1,"z":2}');
 assert.throws(()=>candidateBytes('unexpected',{x:1}),/CY_UNKNOWN_OR_OVERSIZE/);
 assert.throws(()=>candidateBytes('handoff',{x:1.5}),/CX_UNSUPPORTED_CANDIDATE/);
 assert.throws(()=>candidateBytes('handoff',{x:'a'.repeat(9000)}),
  /CY_UNKNOWN_OR_OVERSIZE/);
});
test('CY: preceding current source quorum missing or bad signer blocks operator approval',()=>{
 for(const change of [
  f=>{f.observations.REVOCATION.status='not_found'},
  f=>{f.observations.WITNESS_A.data.signature.signature='a'.repeat(88)},
  f=>{f.manifest.currentHeadSha='0'.repeat(40)},
  f=>{delete f.observations.WITNESS_B}
 ])denied(change,'CY_PRECEDING_REMOTE_CANDIDATE_QUORUM_MISSING');
});
test('CY: old roster unreviewed, hidden pin or wrong source is untrusted',()=>{
 for(const edit of [
  f=>{delete f.previous.sources.REVOCATION},
  f=>{f.previous.sources.WITNESS_A.host='localhost'},
  f=>{f.previous.sources.WITNESS_B.publicKeyPem='bad'},
  f=>{delete f.manifest.sources.REVOCATION}
 ])denied(edit,'CY_MISSING_OPERATOR_PREVIOUS_OR_CURRENT_SOURCE_ROSTER');
});
test('CY: previous epoch or checkpoint mismatch not accepted as current source predecessor',()=>{
 for(const edit of [
  f=>{f.previous.anchor.epoch++},
  f=>{f.previous.anchor.checkpointDigest='3'.repeat(64)},
  f=>{f.previous.anchor.revocationVersion++},
  f=>{f.previous.anchor.revocationDigest='0'.repeat(64)},
  f=>{f.previous.anchor.observedAt='invalid'}
 ])denied(edit,'CY_PREVIOUS_ANCHOR_NOT_EXACTLY_CURRENT_SOURCE_PREDECESSOR');
});
test('CY: changed head, base, policy, nonce or prior digest invalidates officer-handoff statement',()=>{
 for(const field of ['sourceHeadSha','mainBaseSha','policyFingerprintSha256',
  'cvCandidateSha256','nonce','previousCheckpointDigest','nextCheckpointDigest',
  'previousRevocationDigest','nextRevocationDigest']){
  denied(f=>{f.statement[field]='0'.repeat(
   ['sourceHeadSha','mainBaseSha'].includes(field)?40:64)},
   'CY_TWO_EPOCH_SOURCE_BOUND_OPERATOR_HANDOFF_INVALID');
 }
});
test('CY: forged transition GO, added fields, stale issue, bad expiry cannot authorize',()=>{
 for(const change of [
  f=>{f.statement.decision='GO'},
  f=>{f.statement.kind='PRODUCTION_APPROVAL'},
  f=>{f.statement.extra='override'},
  f=>{f.statement.issuedAt='2026-11-19T23:30:00.000Z'},
  f=>{f.statement.expiresAt='2026-11-19T23:59:00.000Z'}
 ])denied(change,'CY_TWO_EPOCH_SOURCE_BOUND_OPERATOR_HANDOFF_INVALID');
});
test('CY: two officer roles cannot be author, duplicate login, shared key or revoked',()=>{
 for(const change of [
  f=>{f.previous.officers.SECURITY_OFFICER.githubLogin='j9619655391-max'},
  f=>{f.previous.officers.BUSINESS_OFFICER.githubLogin='candidate-security'},
  f=>{f.previous.officers.SECURITY_OFFICER.spkiSha256=
   f.previous.officers.BUSINESS_OFFICER.spkiSha256},
  f=>{f.previous.officers.SECURITY_OFFICER.revoked=true},
  f=>{f.previous.officers.BUSINESS_OFFICER.validUntil='2026-11-19T23:00:00.000Z'},
  f=>{f.previous.officers.BUSINESS_OFFICER.organizationId='unrelated-org'}
 ])denied(change,'CY_DISTINCT_NOMINATED_OFFICER_MANDATES_AND_KEYS_REQUIRED');
});
test('CY: officer substitution, missing signature and malformed detached signature held',()=>{
 for(const change of [
  f=>{f.officerSignatures[0].signature=f.officerSignatures[1].signature},
  f=>{f.officerSignatures.pop()},
  f=>{f.officerSignatures[0].algorithm='RSA'},
  f=>{f.officerSignatures[0].keyId='fake-officer-id'},
  f=>{f.officerSignatures[0].signature='a'.repeat(88)}
 ]){
  const r=get(change);
  assert.equal(r.operatorPinLifecycleCandidateMathematicallyConsistent,false);
  assert.equal(r.quarantineRequired,true);
  assert.equal(r.productionReleaseAuthorized,false);
 }
});
test('CY: absent old-new signatures on changed signer SPKI is not permissible rotation',()=>{
 denied(f=>{const next=keyRecord('revocation-key-v2');
  f.manifest.sources.REVOCATION.keyId=next.keyId;
  f.manifest.sources.REVOCATION.signerSpkiSha256=next.spkiSha256;
  f.manifest.sources.REVOCATION.publicKeyPem=next.publicKeyPem;
  f.observations.REVOCATION.data=sourceSigned('REVOCATION',
   f.observations.REVOCATION.data.statement,next);
  f.statement.nextSourceDigest=dig(canonical(f.manifest.sources));
  f.officerSignatures=OFFICERS.map(r=>signed('handoff',r,f.statement,
   f.privateState.officerKeys[r].privateKey,f.privateState.officerKeys[r].keyId));
 },'CY_EXACT_ROTATION_COUNT_NOT_MATCHING_CHANGED_ROLES');
});
test('CY: swapped old or new signer co-signature invalid even when new source is valid',()=>{
 for(const item of ['previousSignature','successorSignature']){
  denied(f=>{rotate(f,'REVOCATION',{signer:true});f.rotations[0][item].signature=
   f.officerSignatures[0].signature},'CY_OLD_NEW_SIGNER_ROTATION_COSIGN_MISSING_REVOCATION');
 }
});
test('CY: duplicate, extra or missing rotation rows cannot hide a source change',()=>{
 denied(f=>{rotate(f,'REVOCATION',{signer:true});f.rotations.push(
  structuredClone(f.rotations[0]))},'CY_EXACT_ROTATION_COUNT_NOT_MATCHING_CHANGED_ROLES');
 denied(f=>{rotate(f,'REVOCATION',{signer:true});f.rotations[0].role='WITNESS_A'},
  'CY_UNKNOWN_DUPLICATE_OR_UNCHANGED_ROTATION');
 denied(f=>{rotate(f,'REVOCATION',{signer:true});f.rotations=[]},
  'CY_EXACT_ROTATION_COUNT_NOT_MATCHING_CHANGED_ROLES');
});
test('CY: even valid dual-signature rotation of a revoked old key needs external break-glass',()=>{
 denied(f=>{rotate(f,'REVOCATION',{signer:true});f.observations.REVOCATION.data.statement.revokedKeyIds=[
  f.previous.sources.REVOCATION.keyId]},
  'CY_PREVIOUS_SIGNER_REVOKED_BREAK_GLASS_REQUIRED_REVOCATION');
});
test('CY: old prior high-watermark witness receipts cannot be missing or duplicated',()=>{
 denied(f=>{f.historicalWitnesses.pop()},
  'CY_EXACT_TWO_PREVIOUS_WITNESS_ANCHOR_RECEIPTS_REQUIRED');
 denied(f=>{f.historicalWitnesses[1].statement.role='WITNESS_A'},
  'CY_DUPLICATE_OR_UNKNOWN_PREVIOUS_WITNESS');
});
test('CY: wrong prior witness digest, source head, nonce, epoch or signature quarantined',()=>{
 for(const field of ['sourceHeadSha','checkpointDigest','revocationDigest',
  'challengeNonce','epoch']){
  denied(f=>{f.historicalWitnesses[0].statement[field]=
   field==='epoch'?8:'0'.repeat(field==='sourceHeadSha'?40:64)},
   'CY_SIGNED_PREVIOUS_HIGHWATERMARK_NOT_CORROBORATED_WITNESS_A');
 }
 denied(f=>{f.historicalWitnesses[1].signature.signature=
  f.officerSignatures[0].signature},
  'CY_SIGNED_PREVIOUS_HIGHWATERMARK_NOT_CORROBORATED_WITNESS_B');
});
test('CY: an asserted prior witness observed after handoff or stale day is not independent proof',()=>{
 denied(f=>{f.historicalWitnesses[0].statement.observedAt=
  '2026-11-20T00:03:00.000Z'},
  'CY_SIGNED_PREVIOUS_HIGHWATERMARK_NOT_CORROBORATED_WITNESS_A');
 denied(f=>{f.historicalWitnesses[0].statement.observedAt=
  '2026-11-19T21:00:00.000Z'},
  'CY_SIGNED_PREVIOUS_HIGHWATERMARK_NOT_CORROBORATED_WITNESS_A');
});
test('CY: incident or fork report always quarantines; recovery proposal cannot silently unfreeze',()=>{
 for(const change of [
  f=>{f.incidents.status='QUARANTINED'},
  f=>{f.incidents.forkReports=[{head:'conflict'}]},
  f=>{f.incidents.recoveryRequested='UNQUARANTINE'},
  f=>{delete f.incidents.status}
 ])denied(change,'CY_INCIDENT_FORK_OR_UNAUTHORIZED_UNQUARANTINE_QUARANTINE');
});
test('CY: single key cannot impersonate cross-role source/operator signers or old key generations',()=>{
 denied(f=>{f.previous.officers.SECURITY_OFFICER.publicKeyPem=
  f.manifest.sources.REVOCATION.publicKeyPem;
  f.previous.officers.SECURITY_OFFICER.spkiSha256=
   f.manifest.sources.REVOCATION.signerSpkiSha256},
  'CY_CROSS_ROLE_GENERATION_OR_OFFICER_KEY_COLLISION');
 denied(f=>{f.manifest.sources.WITNESS_A.signerSpkiSha256=
  f.manifest.sources.REVOCATION.signerSpkiSha256;
  f.manifest.sources.WITNESS_A.publicKeyPem=
   f.manifest.sources.REVOCATION.publicKeyPem},
  'CY_CROSS_ROLE_GENERATION_OR_OFFICER_KEY_COLLISION');
});
test('CY: malformed empty packet never auto recovers, grants GO or contacts providers',()=>{
 for(const input of [{},{incidents:{status:'CLEAR',forkReports:[],recoveryRequested:'NONE'}},
  {manifest:{},previous:{}},{now:'invalid'}]){
  const r=assessOperatorPinLifecycle(input);
  assert.equal(r.operatorPinLifecycleCandidateMathematicallyConsistent,false);
  assert.equal(r.quarantineRequired,true);
  assert.equal(r.productionReleaseAuthorized,false);
  assert.equal(r.automaticRecoveryOrUnquarantineAllowed,false);
 }
});
test('CY: result never prints signer identities, trust pins or public keys',()=>{
 const f=fixture(),r=assessOperatorPinLifecycle(f),txt=JSON.stringify(r);
 assert.equal(txt.includes('BEGIN PUBLIC KEY'),false);
 assert.equal(txt.includes('candidate-security'),false);
 assert.equal(txt.includes(f.previous.sources.WITNESS_A.signerSpkiSha256),false);
 assert.equal(r.productionReleaseAuthorized,false);
});
