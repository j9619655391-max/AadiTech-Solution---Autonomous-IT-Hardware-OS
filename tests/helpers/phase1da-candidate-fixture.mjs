import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {canonical,REPO} from '../../scripts/phase1cx-pinned-external-source-highwatermark.mjs';
import {assessOperatorPinLifecycle} from '../../scripts/phase1cy-operator-pin-lifecycle-quarantine.mjs';
import {OFFICERS,signedBytes} from '../../scripts/phase1cz-corporate-mandate-incident-quarantine.mjs';
import {fixture as cyFixture} from './phase1cz-candidate-fixture.mjs';
const NOW='2026-11-20T00:00:00.000Z';
const sha=x=>createHash('sha256').update(x).digest('hex');
const makeKey=id=>{
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 const publicKeyPem=publicKey.export({type:'spki',format:'pem'}).toString();
 const spkiSha256=sha(publicKey.export({type:'spki',format:'der'}));
 return {keyId:id,privateKey,publicKeyPem,spkiSha256};
};
const sig=(kind,role,statement,key)=>({
 role,keyId:key.keyId,algorithm:'Ed25519',
 signature:sign(null,signedBytes(kind,role,statement),key.privateKey).toString('base64')
});
export function fixture(){
 const cy=cyFixture(),keys={},org='aaditech-candidate-organization';
 const root=makeKey('corporate-root-candidate-v1');
 const prior=cy.previous.officers;
 const officers={
  SECURITY_OFFICER:structuredClone(prior.SECURITY_OFFICER),
  BUSINESS_OFFICER:structuredClone(prior.BUSINESS_OFFICER)
 };
 keys.SECURITY_OFFICER=cy.privateState.officerKeys.SECURITY_OFFICER;
 keys.BUSINESS_OFFICER=cy.privateState.officerKeys.BUSINESS_OFFICER;
 for(const [role,login] of [
  ['INCIDENT_COMMANDER','candidate-incident'],
  ['RECOVERY_AUDITOR','candidate-recovery']
 ]){
  const k=makeKey(role.toLowerCase().replaceAll('_','-')+'-v1');
  keys[role]=k;
  officers[role]={role,organizationId:org,githubLogin:login,
   mandateDigest:role==='INCIDENT_COMMANDER'?'8'.repeat(64):'9'.repeat(64),
   keyId:k.keyId,publicKeyPem:k.publicKeyPem,spkiSha256:k.spkiSha256,
   validFrom:'2026-11-19T22:00:00.000Z',
   validUntil:'2026-11-21T00:00:00.000Z',revoked:false};
 }
 const authority={root:{
  keyId:root.keyId,publicKeyPem:root.publicKeyPem,
  spkiSha256:root.spkiSha256,organizationId:org,
  enrollmentEvidenceSha256:'3'.repeat(64),
  enrolledAt:'2026-11-19T22:00:00.000Z',
  expiresAt:'2026-11-21T00:00:00.000Z',revoked:false
 },officers};
 const {privateState,...cyEvidence}=cy;
 const assessment=assessOperatorPinLifecycle(cyEvidence);
 const mandate={schemaVersion:1,kind:'CANDIDATE_CORPORATE_MANDATE_HOLD',
  repository:REPO,sourceHeadSha:cy.manifest.currentHeadSha,
  mainBaseSha:cy.manifest.mainBaseSha,
  cyTransitionDigest:assessment.candidateTransitionDigestSha256,
  organizationId:org,officerRosterSha256:sha(canonical(officers)),
  nonce:cy.manifest.nonce,issuedAt:'2026-11-19T23:57:00.000Z',
  expiresAt:'2026-11-20T00:06:00.000Z',decision:'HOLD'};
 const mandateSignature=sig('mandate','ROOT',mandate,root);
 const incident={schemaVersion:1,kind:'FORK_OR_COMPROMISE_REVIEW_ONLY',
  incidentId:'incident-candidate-001',repository:REPO,
  sourceHeadSha:cy.manifest.currentHeadSha,
  previousCheckpointDigest:cy.previous.anchor.checkpointDigest,
  nextCheckpointDigest:cy.observations.REVOCATION.data.statement.checkpointDigest,
  cyTransitionDigest:assessment.candidateTransitionDigestSha256,
  sourceRosterSha256:cy.statement.nextSourceDigest,
  archiveEvidenceSha256:'5'.repeat(64),
  nonce:cy.manifest.nonce,issuedAt:'2026-11-19T23:58:00.000Z',
  expiresAt:'2026-11-20T00:07:00.000Z',decision:'QUARANTINE'};
 const officerApprovals=OFFICERS.map(r=>sig('incident',r,incident,keys[r]));
 const forkWitnesses=['WITNESS_A','WITNESS_B'].map(role=>{
  const s={schemaVersion:1,role,incidentId:incident.incidentId,
   repository:REPO,sourceHeadSha:incident.sourceHeadSha,
   previousCheckpointDigest:incident.previousCheckpointDigest,
   nextCheckpointDigest:incident.nextCheckpointDigest,
   nonce:incident.nonce,
   observedAt:'2026-11-19T23:59:00.000Z',
   decision:'FORK_REVIEW_PENDING'};
  return {statement:s,signature:sig('fork',role,s,
   privateState.priorKeys[role])};
 });
 const rec={schemaVersion:1,kind:'READ_ONLY_REHEARSAL',
  incidentId:incident.incidentId,sourceHeadSha:incident.sourceHeadSha,
  archiveEvidenceSha256:incident.archiveEvidenceSha256,
  objectVersion:'remote-version-123',restoreRegion:'ap-south-1',
  restoreObservedAt:'2026-11-19T23:59:30.000Z',
  restoreHashMatchesClaim:true,deleteDeniedClaim:true,decision:'HOLD'};
 const recovery={statement:rec,
  signatures:['INCIDENT_COMMANDER','RECOVERY_AUDITOR'].map(r=>
   sig('recovery',r,rec,keys[r]))};
 return {cyEvidence,authority,mandate,mandateSignature,
  incident,officerApprovals,forkWitnesses,recovery,now:NOW,
  ephemeralTestOnlyOfficerKeys:keys,
  ephemeralTestOnlyPriorWitnessKeys:privateState.priorKeys};
}