import {createHash} from 'node:crypto';
import {
  AUTHORITY_DIGEST_FIELDS, INDEPENDENT_REVIEW_DIGEST_FIELDS,
  PROVIDER_CODE, REQUESTED_SCOPE, reviewPhase1ApDigestInventory
} from './providerAuthorityPreflight.mjs';
import {DISALLOWED_WEBPKI_SHA256} from './phase1AqTrustIncident.mjs';

// Public SOURCE REFERENCE, never a provider-issued policy or application authorization.
// CCA disclosure checked on 2026-11-16; operator must reverify with CCA independently.
export const CCA_DISCLOSURE_URL='https://cca.gov.in/e_mudhra.html';
export const CCA_CPS_PUBLIC_REFERENCE='4.2.1';
export const CCA_TRUST_DOMAIN='INDIA_CCA_DSC_EVALUATION_ONLY';
export const EVIDENCE_FIELDS=Object.freeze([
  ...AUTHORITY_DIGEST_FIELDS,...INDEPENDENT_REVIEW_DIGEST_FIELDS
]);
const SHA=/^[a-f0-9]{64}$/;
const UTC=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const STATES=new Set(['NOT_CHECKED','CLAIMED_NOT_REVOKED','UNKNOWN','REVOKED']);
const POLICY_KEYS=['ccaCpsVersion','ccaDisclosureUrl','trustDomain','incidentDenylistSha256'];
const SNAPSHOT_KEYS=['schemaVersion','providerCode','requestedScope','sequence','recordedAt',
  'policy','artifactDigests','reviewDigests','windows'];
const WINDOW_KEYS=['capturedAt','refreshBy','revokedAt','revocationState'];
const MAX_WINDOW_HOURS=Object.freeze({
  authenticatedOcspSnapshotSha256:1,
  authenticatedCrlSnapshotSha256:24,
  rcaiRootCertificateSha256:168,
  emudhraIssuerChainSha256:168,
  providerCertificatePolicySha256:168,
  mcaCorporateRegistrySha256:720,
  lawfulSignatoryDelegationSha256:720
});
const DEFAULT_WINDOW_HOURS=168;
const HOUR=3_600_000;

export function localIncidentInventorySha256(){
  // Deliberately binds *all* current groups in a stable category+hash order.
  const canonical=Object.entries(DISALLOWED_WEBPKI_SHA256)
    .map(([group,values])=>[group,[...values].sort()]);
  return createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}
function exact(value,keys){
  if(value===null||typeof value!=='object'||Array.isArray(value)||
    Object.getPrototypeOf(value)!==Object.prototype||
    Object.keys(value).length!==keys.length||
    Object.keys(value).some(key=>!keys.includes(key)))
    throw Error('Unexpected policy/evidence fields or authority switches');
}
function timestamp(value){
  if(typeof value!=='string'||!UTC.test(value))throw Error('Canonical UTC date required');
  const time=Date.parse(value);
  if(!Number.isFinite(time)||new Date(time).toISOString().replace(/\.000Z$/,'Z')!==
      (value.endsWith('.000Z')?value.replace(/\.000Z$/,'Z'):value))
    throw Error('Invalid or noncanonical UTC time');
  return time;
}
function validateSnapshot(s,nowMs){
  exact(s,SNAPSHOT_KEYS);
  if(s.schemaVersion!==1||s.providerCode!==PROVIDER_CODE||
     s.requestedScope!==REQUESTED_SCOPE||!Number.isSafeInteger(s.sequence)||
     s.sequence<1)throw Error('Unrecognized provider, service or evidence sequence');
  const recorded=timestamp(s.recordedAt);
  if(recorded>nowMs+300_000)throw Error('Future-dated evidence inventory');
  exact(s.policy,POLICY_KEYS);
  if(s.policy.ccaDisclosureUrl!==CCA_DISCLOSURE_URL||
     s.policy.trustDomain!==CCA_TRUST_DOMAIN||
     typeof s.policy.ccaCpsVersion!=='string'||
     !/^\d{1,2}\.\d{1,2}\.\d{1,2}$/.test(s.policy.ccaCpsVersion)||
     typeof s.policy.incidentDenylistSha256!=='string'||
     !SHA.test(s.policy.incidentDenylistSha256))
    throw Error('Invalid public policy reference or trust domain');
  // Use Phase 1AP's strict, exact SHA-only validation; a full packet remains HOLD.
  reviewPhase1ApDigestInventory({
    schemaVersion:1,providerCode:s.providerCode,requestedScope:s.requestedScope,
    artifactDigests:s.artifactDigests,reviewDigests:s.reviewDigests
  });
  exact(s.windows,EVIDENCE_FIELDS);
  for(const kind of EVIDENCE_FIELDS){
    const w=s.windows[kind];
    exact(w,WINDOW_KEYS);
    const from=timestamp(w.capturedAt),due=timestamp(w.refreshBy);
    if(from>recorded||due<=from||due-from>
       (MAX_WINDOW_HOURS[kind]??DEFAULT_WINDOW_HOURS)*HOUR)
      throw Error('Invalid or overlong administrative evidence review window');
    if(!STATES.has(w.revocationState))throw Error('Unknown revocation observation');
    if(w.revokedAt===null){
      if(w.revocationState==='REVOKED')throw Error('Revocation timestamp missing');
    }else{
      const revoked=timestamp(w.revokedAt);
      if(revoked>recorded||w.revocationState!=='REVOKED')
        throw Error('Inconsistent or future-dated revocation observation');
    }
  }
  return recorded;
}
function hardHold(){
  return {
    phase:'1AU',reviewBasis:'UNVERIFIED_ADMINISTRATIVE_SHA_ONLY',
    currentInventoryInspected:false,baselineInventoryInspected:false,
    policyDriftDetected:null,changedClaimCount:0,expiredEvidenceCount:0,
    dueSoonEvidenceCount:0,revokedEvidenceCount:0,unknownRevocationCount:0,
    evidenceReviewRollbackDetected:false,incidenceInventoryChanged:false,
    currentCpsReferenceMismatch:false,
    externalProviderIdentityVerified:false,independentlyAuthenticatedRcaiCaChain:false,
    authenticatedLiveCrlOcsp:false,authorizedCredentialsBound:false,
    legallyVerifiedMcaAndSignatory:false,officialGrnVerified:false,
    stockPostingEnabled:false,productionReleaseAuthorized:false,
    releaseDecision:'HOLD'
  };
}
/** Candidate-only drift and freshness checks. There is NO path to real trust.
 * Policy SHA / timestamp comparisons do not authenticate provider disclosures,
 * independent signers, revocation responder status, legal facts or original bytes. */
export function assessPhase1AuPolicyDrift(baseline=null,current=null,now=new Date()){
  if(!(now instanceof Date)||!Number.isFinite(now.getTime()))
    throw Error('Explicit valid evaluation clock required');
  const result=hardHold();
  if(baseline===null&&current===null)
    return {...result,blockers:['NO_OFFLINE_EVIDENCE_CLAIMS','NO_PROVIDER_AUTHORITY']};
  if(current===null)
    return {...result,blockers:['MISSING_CURRENT_CLAIM_INVENTORY','NO_PROVIDER_AUTHORITY']};
  const nowMs=now.getTime(),currentRecorded=validateSnapshot(current,nowMs);
  const priorRecorded=baseline===null?null:validateSnapshot(baseline,nowMs);
  const reasons=new Set();
  const incidentFingerprint=localIncidentInventorySha256();
  if(baseline===null)reasons.add('NO_INDEPENDENT_BASELINE');
  if(current.policy.incidentDenylistSha256!==incidentFingerprint||
     (baseline!==null&&baseline.policy.incidentDenylistSha256!==incidentFingerprint))
    reasons.add('PUBLIC_INCIDENT_INVENTORY_CHANGED');
  if(current.policy.ccaCpsVersion!==CCA_CPS_PUBLIC_REFERENCE)
    reasons.add('PUBLIC_CPS_REFERENCE_MISMATCH');
  let changed=0,rollback=false,expired=0,dueSoon=0,revoked=0,unknown=0;
  if(baseline!==null){
    if(current.sequence<=baseline.sequence||currentRecorded<priorRecorded)
      {rollback=true;reasons.add('EVIDENCE_SEQUENCE_ROLLBACK');}
    if(current.policy.ccaCpsVersion!==baseline.policy.ccaCpsVersion||
       current.policy.trustDomain!==baseline.policy.trustDomain||
       current.policy.incidentDenylistSha256!==baseline.policy.incidentDenylistSha256)
      reasons.add('POLICY_REFERENCE_DRIFT');
  }
  for(const key of EVIDENCE_FIELDS){
    const w=current.windows[key];
    const category=AUTHORITY_DIGEST_FIELDS.includes(key)?'artifactDigests':'reviewDigests';
    if(baseline!==null){
      const before=baseline.windows[key];
      if(current[category][key]!==baseline[category][key]){
        changed++;reasons.add('SHA_CLAIM_CHANGED_REVIEW_REQUIRED');
      }
      if(timestamp(w.capturedAt)<timestamp(before.capturedAt)||
         (before.revocationState==='REVOKED'&&w.revocationState!=='REVOKED')||
         (before.revokedAt!==null&&w.revokedAt!==before.revokedAt)){
        rollback=true;reasons.add('REVOCATION_OR_REVIEW_ROLLBACK');
      }
    }
    const due=timestamp(w.refreshBy);
    if(due<=nowMs){expired++;reasons.add('EVIDENCE_REVIEW_EXPIRED');}
    else if(due-nowMs<=24*HOUR)dueSoon++;
    if(w.revocationState==='REVOKED'||w.revokedAt!==null){
      revoked++;reasons.add('REVOKED_CLAIM_PRESENT');
    }else if(w.revocationState==='NOT_CHECKED'||w.revocationState==='UNKNOWN'){
      unknown++;reasons.add('REVOCATION_UNKNOWN_OR_UNCHECKED');
    }
  }
  reasons.add('NO_AUTHENTICATED_EXTERNAL_PROVIDER_OR_LEGAL_APPROVAL');
  return {
    ...result,currentInventoryInspected:true,baselineInventoryInspected:baseline!==null,
    policyDriftDetected:[...reasons].some(r=>[
      'PUBLIC_INCIDENT_INVENTORY_CHANGED','PUBLIC_CPS_REFERENCE_MISMATCH',
      'POLICY_REFERENCE_DRIFT','SHA_CLAIM_CHANGED_REVIEW_REQUIRED'
    ].includes(r)),
    changedClaimCount:changed,expiredEvidenceCount:expired,
    dueSoonEvidenceCount:dueSoon,revokedEvidenceCount:revoked,
    unknownRevocationCount:unknown,evidenceReviewRollbackDetected:rollback,
    incidenceInventoryChanged:reasons.has('PUBLIC_INCIDENT_INVENTORY_CHANGED'),
    currentCpsReferenceMismatch:reasons.has('PUBLIC_CPS_REFERENCE_MISMATCH'),
    blockers:[...reasons].sort()
  };
}
