import 'dotenv/config';
import {performStagingProbe,validateStagingProbeTarget} from './lib/stagingHttpsProbe';

async function main(){
 const target=validateStagingProbeTarget(process.env);
 const result=await performStagingProbe(target);
 console.log(JSON.stringify(result,null,2));
 if(!result.observedChecksPassed)process.exitCode=1;
}
main().catch(e=>{
 console.error('Staging HTTPS acceptance probe refused:',
  e instanceof Error?e.message:'Unknown');
 process.exitCode=1;
});
