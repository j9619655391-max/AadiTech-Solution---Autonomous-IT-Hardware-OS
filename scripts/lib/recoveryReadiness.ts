import {evaluateRestoreEvidence,type RestoreEvidence,type Objectives} from './restoreEvidence';

export interface RecoveryReviewPackage{
 changeTicket:string;
 evidenceLocation:string;
 operatorId:string;
 independentWitnessId:string;
 witnessApprovalReference:string;
 isolatedNetworkVerified:boolean;
 outboundDispatchDisabled:boolean;
 stagingTlsVerified:boolean;
 evidence:RestoreEvidence;
 objectives:Objectives;
}
export function assessRecoveryReviewPackage(input:RecoveryReviewPackage){
 const issues:string[]=[];
 for(const key of ['changeTicket','evidenceLocation','operatorId',
  'independentWitnessId','witnessApprovalReference'] as const){
  if(typeof input?.[key]!=='string'||input[key].trim().length<8)
   issues.push('Missing or insufficient evidence reference: '+key);
 }
 if(input?.operatorId===input?.independentWitnessId)
  issues.push('Recovery witness cannot also be operator');
 if(input?.isolatedNetworkVerified!==true)
  issues.push('Staging isolation not independently attested');
 if(input?.outboundDispatchDisabled!==true)
  issues.push('Outbound dispatch not attested disabled');
 if(input?.stagingTlsVerified!==true)
  issues.push('Staging TLS validation not attested');
 let values:ReturnType<typeof evaluateRestoreEvidence>|undefined;
 try{values=evaluateRestoreEvidence(input.evidence,input.objectives);}
 catch{issues.push('Invalid RTO/RPO objectives or evidence schema');}
 if(values&&!values.accepted)issues.push(...values.problems);
 return {
  reportedEvidenceComplete:issues.length===0,
  // No on-disk JSON or CI fixture can independently establish a real restore.
  externallyWitnessedRestoreVerified:false,
  productionReleaseAuthorized:false,
  measuredRtoMinutes:values?.rtoMinutes??null,
  measuredRpoMinutes:values?.rpoMinutes??null,
  issues
 };
}
