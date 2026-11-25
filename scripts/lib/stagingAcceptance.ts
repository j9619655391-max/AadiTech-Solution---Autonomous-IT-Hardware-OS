import {assessRecoveryReviewPackage,type RecoveryReviewPackage} from './recoveryReadiness';
import type {ProbeTarget} from './stagingHttpsProbe';

export interface StagingAcceptancePackage{
 changeTicket:string;
 stagingOrigin:string;
 probe:{
  targetOrigin:string;
  changeTicket:string;
  observedAt:string;
  observedChecksPassed:boolean;
  failures:string[];
  proxyIpOverwriteIndependentlyVerified:boolean;
  directListenerIsolationIndependentlyVerified:boolean;
  databaseTlsIndependentlyVerified:boolean;
  productionReleaseAuthorized:boolean;
 };
 operatorId:string;
 independentSecurityReviewerId:string;
 independentInfrastructureReviewerId:string;
 securityApprovalReference:string;
 infrastructureApprovalReference:string;
 reviewerSignedAt:string;
 networkIsolationEvidenceRef:string;
 proxyHeaderRewriteEvidenceRef:string;
 mysqlCaEvidenceRef:string;
 realHttpsBrowserMfaEvidenceRef:string;
 outboundDispatchHeldEvidenceRef:string;
 actualRestoreReview:RecoveryReviewPackage;
}
export function assessStagingAcceptance(input:StagingAcceptancePackage,now=new Date()){
 const issues:string[]=[];
 const refs=[
  'changeTicket','operatorId','independentSecurityReviewerId',
  'independentInfrastructureReviewerId','securityApprovalReference',
  'infrastructureApprovalReference','networkIsolationEvidenceRef',
  'proxyHeaderRewriteEvidenceRef','mysqlCaEvidenceRef',
  'realHttpsBrowserMfaEvidenceRef','outboundDispatchHeldEvidenceRef'
 ] as const;
 for(const field of refs){
  const value=input?.[field];
  if(typeof value!=='string'||value.trim().length<8||value.length>256)
   issues.push('Missing or invalid private evidence reference: '+field);
 }
 if(input.operatorId===input.independentSecurityReviewerId||
    input.operatorId===input.independentInfrastructureReviewerId||
    input.independentSecurityReviewerId===input.independentInfrastructureReviewerId)
  issues.push('Operator, security reviewer and infrastructure reviewer must be distinct');
 let originValid=false;
 try{
  const origin=new URL(input.stagingOrigin);
  originValid=origin.protocol==='https:'&&origin.origin===input.stagingOrigin&&
    (origin.hostname.startsWith('staging.')||origin.hostname.startsWith('staging-'));
 }catch{}
 if(!originValid)issues.push('Non-staging or invalid HTTPS origin');
 const probe=input?.probe;
 if(!probe||probe.targetOrigin!==input.stagingOrigin||probe.changeTicket!==input.changeTicket)
  issues.push('HTTPS probe target or change ticket differs from evidence package');
 if(!probe||probe.observedChecksPassed!==true||!Array.isArray(probe.failures)||
   probe.failures.length!==0)
  issues.push('Read-only HTTPS observation checks failed or missing');
 if(probe?.productionReleaseAuthorized!==false)
  issues.push('Probe must not claim production approval');
 const observedAt=Date.parse(probe?.observedAt??'');
 const signedAt=Date.parse(input?.reviewerSignedAt??'');
 const nowMs=now.getTime();
 if(!Number.isFinite(observedAt)||observedAt>nowMs||
    nowMs-observedAt>24*60*60*1000)
  issues.push('TLS/proxy observation is absent, future-dated or older than 24 hours');
 if(!Number.isFinite(signedAt)||signedAt<observedAt||signedAt>nowMs)
  issues.push('Staging reviewer signoff time is invalid');
 // A GET-only probe cannot independently establish these network/TLS claims.
 // External evidence is required even if the submitted flags are true.
 for(const field of ['proxyIpOverwriteIndependentlyVerified',
  'directListenerIsolationIndependentlyVerified',
  'databaseTlsIndependentlyVerified'] as const){
  if(probe?.[field]!==true)
   issues.push('External verification required: '+field);
 }
 const recovery=input?.actualRestoreReview;
 let restore;
 try{restore=assessRecoveryReviewPackage(recovery);}
 catch{issues.push('Invalid recovery rehearsal evidence package');}
 if(!restore?.reportedEvidenceComplete)
  issues.push('Independent restore/recovery review incomplete');
 if(recovery?.changeTicket!==input?.changeTicket)
  issues.push('Recovery rehearsal and ingress evidence use different change tickets');
 if(recovery?.operatorId!==input?.operatorId)
  issues.push('Recovery rehearsal operator differs from signed staging package');
 if(!recovery||recovery.independentWitnessId===input?.independentSecurityReviewerId||
    recovery.independentWitnessId===input?.independentInfrastructureReviewerId)
  issues.push('Restore witness must be distinct from ingress reviewers');
 return {
  submittedEvidenceComplete:issues.length===0,
  issues,
  restoreRtoMinutes:restore?.measuredRtoMinutes??null,
  restoreRpoMinutes:restore?.measuredRpoMinutes??null,
  // A JSON file can contain fabricated approvals. Do not conflate field
  // completeness with actually observed third-party signed approvals.
  independentIdentityAndSignaturesVerified:false,
  providerInfrastructureVerified:false,
  actualRestoreIndependentlyVerified:false,
  productionReleaseAuthorized:false
 };
}
