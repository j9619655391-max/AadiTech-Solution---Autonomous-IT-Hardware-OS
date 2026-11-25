import 'dotenv/config';
import {resolveDeploymentSecurity} from '../server/security/deploymentGuards';

if(process.env.DEPLOYMENT_PREFLIGHT!=='1'){
 console.error('Refusing preflight without DEPLOYMENT_PREFLIGHT=1');
 process.exitCode=1;
}else{
 try{
  // Only validates configuration; never opens network sockets or verifies real
  // deployment/firewalls/proxy headers/TLS certificates.
  const config=resolveDeploymentSecurity({...process.env,NODE_ENV:'production'});
  console.log(JSON.stringify({
   configurationValid:true,
   productionReleaseAuthorized:false,
   tlsIngressExternallyVerified:false,
   proxyHeaderOverwriteExternallyVerified:false,
   networkIsolationExternallyVerified:false,
   verifiedProxyEntryCount:config.trustedProxyCidrs.length,
   bindLoopback:!config.publicBind,
   httpsRequired:config.httpsRequired
  },null,2));
 }catch(e){
  console.error('Deployment preflight failed:',e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 }
}
