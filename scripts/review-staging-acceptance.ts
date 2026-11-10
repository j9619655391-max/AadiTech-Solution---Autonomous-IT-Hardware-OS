import 'dotenv/config';
import {readFileSync} from 'node:fs';
import {assessStagingAcceptance,type StagingAcceptancePackage} from './lib/stagingAcceptance';

if(process.env.STAGING_ACCEPTANCE_REVIEW!=='YES'){
 console.error('Review is disabled without STAGING_ACCEPTANCE_REVIEW=YES');
 process.exitCode=1;
}else{
 try{
  const file=process.argv[2];
  if(!file||process.argv.length!==3)
   throw Error('Provide an approved private local evidence JSON file');
  const input=JSON.parse(readFileSync(file,'utf8')) as StagingAcceptancePackage;
  const report=assessStagingAcceptance(input);
  console.log(JSON.stringify(report,null,2));
  if(!report.submittedEvidenceComplete)process.exitCode=1;
 }catch(e){
  console.error('Staging acceptance evidence review refused:',
   e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 }
}
