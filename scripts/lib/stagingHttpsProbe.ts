import {request} from 'node:https';
import {isIP} from 'node:net';
import type {IncomingHttpHeaders} from 'node:http';

export interface ProbeTarget{
 origin:string;
 changeTicket:string;
}
export function validateStagingProbeTarget(env:NodeJS.ProcessEnv):ProbeTarget{
 if(env.STAGING_HTTPS_PROBE!=='YES'||env.STAGING_PROBE_APPROVED!=='YES')
  throw Error('Explicit staging HTTPS probe authorization required');
 const target=env.STAGING_HTTPS_ORIGIN??'';
 const approved=env.STAGING_APPROVED_HOST??'';
 const ticket=env.STAGING_CHANGE_TICKET??'';
 if(!/^[a-zA-Z0-9_-]{8,100}$/.test(ticket))
  throw Error('Approved staging change ticket reference required');
 let url:URL;
 try{url=new URL(target);}catch{throw Error('Staging target must be a valid HTTPS origin');}
 if(url.protocol!=='https:'||url.port||url.username||url.password||
  url.pathname!=='/'||url.search||url.hash)
  throw Error('Probe target must be an HTTPS origin on standard port without credentials');
 const host=url.hostname.toLowerCase();
 if(!/^[a-z0-9.-]+$/.test(host)||isIP(host)||!host.includes('.')||
  (!host.startsWith('staging.')&&!host.startsWith('staging-'))||
  host.endsWith('.localhost')||host.endsWith('.local')||
  host.endsWith('.test')||host.endsWith('.example')||host.endsWith('.invalid')||
  host.includes('production')||host.includes('prod-')||host.includes('-prod.'))
  throw Error('Target must be an explicitly named non-example staging hostname');
 if(approved!==host)throw Error('Approved hostname must exactly match staging target');
 return {origin:url.origin,changeTicket:ticket};
}
export interface ProbeObservation{
 tlsPeerAuthorized:boolean;
 status:number;
 headers:IncomingHttpHeaders;
}
type Fetcher=(origin:string,path:string,headers?:Record<string,string>)=>Promise<ProbeObservation>;
export function checkProbeObservations(health:ProbeObservation,auth:ProbeObservation,
 spoofed:ProbeObservation){
 const failures:string[]=[];
 if(!health.tlsPeerAuthorized||!auth.tlsPeerAuthorized||!spoofed.tlsPeerAuthorized)
  failures.push('At least one TLS peer was not certificate-authorized');
 if(health.status!==200)failures.push('Staging health did not return HTTP 200');
 if(auth.status!==401)failures.push('Anonymous session endpoint did not return HTTP 401');
 if(spoofed.status!==200)failures.push('Ingress did not overwrite forged forwarded protocol');
 for(const [name,observation] of [['health',health],['auth',auth],['spoofed',spoofed]] as const){
  const hsts=observation.headers['strict-transport-security'];
  const maxAge=typeof hsts==='string'?Number(hsts.match(/(?:^|;)\s*max-age=(\d+)(?:;|$)/i)?.[1]):NaN;
  if(!Number.isSafeInteger(maxAge)||maxAge<31536000)
   failures.push(name+' missing year-long HSTS');
  if(observation.headers['x-content-type-options']!=='nosniff')
   failures.push(name+' missing nosniff');
  if(observation.headers['x-powered-by'])failures.push(name+' leaks X-Powered-By');
 }
 if(!/^no-store(?:,|$)/i.test(String(auth.headers['cache-control']??'')))
  failures.push('Anonymous authentication response must prohibit caching');
 return {
  observedChecksPassed:failures.length===0,
  failures,
  // These cannot be proven by a GET /health probe.
  proxyIpOverwriteIndependentlyVerified:false,
  directListenerIsolationIndependentlyVerified:false,
  databaseTlsIndependentlyVerified:false,
  productionReleaseAuthorized:false
 };
}
async function get(url:string,path:string,headers:Record<string,string>={}):Promise<ProbeObservation>{
 return await new Promise((resolve,reject)=>{
  const req=request(url+path,{
   method:'GET',timeout:5000,rejectUnauthorized:true,
   headers:{'User-Agent':'aaditech-staging-acceptance-probe/1.0',
    'Accept':'application/json',...headers}
  },res=>{
   let bytes=0;
   res.on('data',(chunk:Buffer)=>{
    bytes+=chunk.length;
    if(bytes>16384)req.destroy(Error('Probe response body exceeded 16 KiB'));
   });
   res.on('end',()=>{
    // Deliberately never follow redirects, print response bodies or persist cookies.
    const socket=res.socket as import('node:tls').TLSSocket;
    resolve({tlsPeerAuthorized:socket.authorized===true,
     status:res.statusCode??0,headers:res.headers});
   });
  });
  req.on('timeout',()=>req.destroy(Error('HTTPS staging probe timed out')));
  req.on('error',reject);
  req.end();
 });
}
export async function performStagingProbe(target:ProbeTarget,fetcher:Fetcher=get){
 const health=await fetcher(target.origin,'/api/health');
 const auth=await fetcher(target.origin,'/api/auth/me');
 const spoofed=await fetcher(target.origin,'/api/health',{
  'X-Forwarded-Proto':'http','X-Forwarded-For':'198.51.100.77'
 });
 return {targetOrigin:target.origin,changeTicket:target.changeTicket,
  observedAt:new Date().toISOString(),...checkProbeObservations(health,auth,spoofed)};
}
