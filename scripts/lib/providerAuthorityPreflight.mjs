import {createHash} from 'node:crypto';

// Phase 1AP SHA-only *claims inventory* never verifies external provider authority.
export const PROVIDER_CODE='EMUDHRA_CCA_EVALUATION_ONLY';
export const REQUESTED_SCOPE='SUPPLIER_WAREHOUSE_EVIDENCE_SANDBOX';
export const AUTHORITY_DIGEST_FIELDS=Object.freeze([
 'signedAgreementSha256','providerSandboxServiceGrantSha256',
 'providerServiceAuthorizationSha256','rcaiRootCertificateSha256',
 'emudhraIssuerChainSha256','providerCertificatePolicySha256',
 'authenticatedCrlSnapshotSha256','authenticatedOcspSnapshotSha256',
 'mcaCorporateRegistrySha256','lawfulSignatoryDelegationSha256'
]);
export const INDEPENDENT_REVIEW_DIGEST_FIELDS=Object.freeze([
 'providerOutOfBandConfirmationSha256','legalReviewSha256','securityReviewSha256',
 'rcaiChainVerificationSha256','mcaRegistryVerificationSha256',
 'signatoryAuthorityVerificationSha256'
]);
export const PENDING_EXTERNAL_REQUIREMENTS=Object.freeze([
 'Independent legal verification of signed provider agreement and explicit sandbox service authorization',
 'Approved least-privilege application credentials in authorized secrets manager; never Git, chat or this packet',
 'Out-of-band authenticated RCAI/eMudhra CA hierarchy, certificate policies, chain and RFC 5280 validation',
 'Current genuinely authenticated CRL/OCSP publisher, responder, serial, signature, freshness and revocation',
 'Primary-source MCA corporate record and legally effective signer delegation',
 'Actual supplier/warehouse signatures, physical GRN, operational ledger and production approvals'
]);
function exactObject(value,keys){
 if(value===null||typeof value!=='object'||Array.isArray(value)||
    Object.getPrototypeOf(value)!==Object.prototype)
  throw Error('Expected plain administrative digest record');
 const actual=Object.keys(value);
 if(actual.length!==keys.length||actual.some(k=>!keys.includes(k)))
  throw Error('Unknown or missing field; credentials and activation switches are forbidden');
}
function digest(value){
 if(typeof value!=='string'||!/^[a-f0-9]{64}$/.test(value)||/^0{64}$/.test(value))
  throw Error('Only nonzero lowercase SHA-256 document fingerprints accepted');
 return value;
}
function hold(){
 return {
  phase:'1AP',provider:PROVIDER_CODE,sandboxServiceAuthorized:false,
  externalProviderIdentityVerified:false,authorizedCredentialsBound:false,
  independentlyAuthenticatedRcaiCaChain:false,authenticatedLiveCrlOcsp:false,
  legallyVerifiedMcaAndSignatory:false,approvedSupplierOrWarehouseProof:false,
  officialGrnVerified:false,stockPostingEnabled:false,availableToSell:null,
  productionReleaseAuthorized:false,releaseDecision:'HOLD',
  blockers:[...PENDING_EXTERNAL_REQUIREMENTS]
 };
}
/** Digests alone cannot attest a signed agreement, delegated authority or issuer identity.
 * Intentionally NO feature flag, environment override or production activation path. */
export function reviewPhase1ApDigestInventory(packet){
 const held=hold();
 if(packet==null)return {...held,packetInspected:false,declaredDigestCount:0,
  inventoryFingerprintSha256:null};
 exactObject(packet,['schemaVersion','providerCode','requestedScope','artifactDigests','reviewDigests']);
 if(packet.schemaVersion!==1||packet.providerCode!==PROVIDER_CODE||
    packet.requestedScope!==REQUESTED_SCOPE)
  throw Error('Unknown version, provider or sandbox purpose');
 exactObject(packet.artifactDigests,AUTHORITY_DIGEST_FIELDS);
 exactObject(packet.reviewDigests,INDEPENDENT_REVIEW_DIGEST_FIELDS);
 const values=[...AUTHORITY_DIGEST_FIELDS.map(k=>digest(packet.artifactDigests[k])),
  ...INDEPENDENT_REVIEW_DIGEST_FIELDS.map(k=>digest(packet.reviewDigests[k]))];
 if(new Set(values).size!==values.length)
  throw Error('Distinct evidence fields require distinct fingerprints');
 const canonical=JSON.stringify([1,PROVIDER_CODE,REQUESTED_SCOPE,...values]);
 return {...held,packetInspected:true,declaredDigestCount:values.length,
  inventoryFingerprintSha256:createHash('sha256').update(canonical).digest('hex')};
}
