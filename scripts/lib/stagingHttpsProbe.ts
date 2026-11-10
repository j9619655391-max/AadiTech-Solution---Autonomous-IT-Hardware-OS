import {request} from 'node:https';
import {lookup} from 'node:dns/promises';
import {isIP} from 'node:net';
import type {IncomingHttpHeaders} from 'node:http';
import type {TLSSocket} from 'node:tls';

export interface ProbeTarget{
 origin:string;
 changeTicket:string;
 approvedIPv4s:string[];
}
export function isPublicIPv4(address:string):boolean{
 if(isIP(address)!==4)return false;
 const n=address.split('.').map(Number),[a,b,c]=n;
 if(a===0||a===10||a===127||a>=224)return false;
 if(a===100&&b>=64&&b<=127)return false;
 if(a===169&&b===254)return false;
 if(a===172&&b>=16&&b<=31)return false;
 if(a===192&&(b===0||b===168||b===88&&c===99||b===0&&c===2))return false;
 if(a===192&&b===0&&c===2)return false;
 if(a===198&&(b===18||b===19||b===51&&c===100))return false;
 if(a===203&&b===0&&c===113)return false;
 return true;
}
export function parseApprovedIPv4s(value:string|undefined):string[]{
 if(!value)throw Error('STAGING_APPROVED_IPV4S must list verified public staging IPv4 addresses');
 const ips=value.split(',').map(s=>s.trim());
 if(ips.length===0||ips.length>8||new Set(ips).size!==ips.length||
    ips.some(ip=>!isPublicIPv4(ip)))
  throw Error('Approved addresses must be 1-8 distinct public IPv4 literals');
 return ips.sort();
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
 return {origin:url.origin,changeTicket:ticket,
  approvedIPv4s:parseApprovedIPv4s(env.STAGING_APPROVED_IPV4S)};
}
export type ProbeResolver=(hostname:string)=>Promise<string[]>;
async function liveResolver(hostname:string):Promise<string[]>{
 const results=await lookup(hostname,{all:true,verbatim:true});
 return results.map(x=>x.address);
}
export async function resolvePinnedStagingIPv4(target:ProbeTarget,resolver:ProbeResolver=liveResolver):Promise<string>{
 const hostname=new URL(target.origin).hostname;
 if(!Array.isArray(target.approvedIPv4s)||target.approvedIPv4s.length===0||
    target.approvedIPv4s.length>8||target.approvedIPv4s.some(ip=>!isPublicIPv4(ip))||
    new Set(target.approvedIPv4s).size!==target.approvedIPv4s.length)
  throw Error('Approved IPv4 inventory absent or unsafe');
 const dns=await resolver(hostname);
 if(!Array.isArray(dns)||!dns.length||dns.length>8||dns.some(ip=>!isPublicIPv4(ip))||
    new Set(dns).size!==dns.length)
  throw Error('DNS result missing, ambiguous, private, reserved or IPv6-only');
 if(dns.slice().sort().join(',')!==target.approvedIPv4s.slice().sort().join(','))
  throw Error('Staging DNS answers differ from independently approved IPv4 inventory');
 return dns.slice().sort()[0];
}
export interface ProbeObservation{
 tlsPeerAuthorized:boolean;
 certificateValidUntil?:string|null;
 status:number;
 headers:IncomingHttpHeaders;
}
type Fetcher=(origin:string,path:string,headers:Record<string,string>,
 pinnedIPv4:string)=>Promise<ProbeObservation>;
export function checkProbeObservations(health:ProbeObservation,auth:ProbeObservation,
 spoofed:ProbeObservation,now=new Date()){
 const failures:string[]=[];
 if(!health.tlsPeerAuthorized||!auth.tlsPeerAuthorized||!spoofed.tlsPeerAuthorized)
  failures.push('At least one TLS peer was not certificate-authorized');
 if(health.status!==200)failures.push('Staging health did not return HTTP 200');
 if(auth.status!==401)failures.push('Anonymous session endpoint did not return HTTP 401');
 if(spoofed.status!==200)failures.push('Ingress did not overwrite forged forwarded protocol');
 for(const [name,observation] of [['health',health],['auth',auth],['spoofed',spoofed]] as const){
  const age=Date.parse(observation.certificateValidUntil??'');
  if(!Number.isFinite(age)||age-now.getTime()<14*86400000)
   failures.push(name+' TLS certificate expires within 14 days or validity is missing');
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
  proxyIpOverwriteIndependentlyVerified:false,
  directListenerIsolationIndependentlyVerified:false,
  databaseTlsIndependentlyVerified:false,
  productionReleaseAuthorized:false
 };
}
async function get(origin:string,path:string,headers:Record<string,string>,pinnedIPv4:string):Promise<ProbeObservation>{
 return await new Promise((resolve,reject)=>{
  // DNS is resolved and verified exactly once, BEFORE any request. Connecting to
  // an IP literal prevents DNS rebinding between the approval check and TLS.
  const host=new URL(origin).hostname;
  const req=request({
   protocol:'https:',hostname:pinnedIPv4,port:443,servername:host,path,
   method:'GET',timeout:5000,rejectUnauthorized:true,
   headers:{'User-Agent':'aaditech-staging-acceptance-probe/1.1',
    'Accept':'application/json',...headers,Host:host}
  },res=>{
   const tls=res.socket as TLSSocket;
   const authorized=tls.authorized===true;
   const rawDate=tls.getPeerCertificate()?.valid_to;
   const expiry=rawDate?Date.parse(rawDate):NaN;
   let bytes=0;
   res.on('data',(chunk:Buffer)=>{
    bytes+=chunk.length;
    if(bytes>16384)req.destroy(Error('Probe response body exceeded 16 KiB'));
   });
   res.on('end',()=>resolve({
    tlsPeerAuthorized:authorized,
    certificateValidUntil:Number.isFinite(expiry)?new Date(expiry).toISOString():null,
    status:res.statusCode??0,headers:res.headers
   }));
  });
  req.on('timeout',()=>req.destroy(Error('HTTPS staging probe timed out')));
  req.on('error',reject);
  req.end();
 });
}
export async function performStagingProbe(target:ProbeTarget,fetcher:Fetcher=get,
 resolver:ProbeResolver=liveResolver){
 const pinnedIPv4=await resolvePinnedStagingIPv4(target,resolver);
 const health=await fetcher(target.origin,'/api/health',{},pinnedIPv4);
 const auth=await fetcher(target.origin,'/api/auth/me',{},pinnedIPv4);
 const spoofed=await fetcher(target.origin,'/api/health',{
  'X-Forwarded-Proto':'http','X-Forwarded-For':'198.51.100.77'
 },pinnedIPv4);
 return {targetOrigin:target.origin,changeTicket:target.changeTicket,
  approvedIPv4Count:target.approvedIPv4s.length,pinnedIPv4,
  certificateValidUntil:health.certificateValidUntil??null,
  observedAt:new Date().toISOString(),...checkProbeObservations(health,auth,spoofed)};
}
