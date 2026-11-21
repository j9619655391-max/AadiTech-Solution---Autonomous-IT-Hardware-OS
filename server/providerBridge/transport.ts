import https from 'node:https';
import {createHash,X509Certificate,timingSafeEqual} from 'node:crypto';
import {checkServerIdentity} from 'node:tls';
import type {PeerCertificate} from 'node:tls';
import {ChainConflictError,ChainInputError,pinConfig} from './validation';
export const REVOCATION_PATH='/.well-known/aaditech/revocations/latest';
export function transportAllowed(env:NodeJS.ProcessEnv){
 if(env.PROVIDER_PINNED_FETCH_ENABLED!=='YES'||
  env.PROVIDER_PIN_FETCH_SCOPE!=='ISOLATED_STAGING'||
  env.NODE_ENV==='production'||
  env.STAGING_DISPOSABLE_CONFIRMED!=='YES'||
  env.DB_SSL!=='true'||
  !/^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??''))
  throw new ChainConflictError('Pinned read-only transport disabled outside approved isolated TLS staging');
 return pinConfig(env);
}
export function validateTlsPeer(hostname:string,cert:PeerCertificate,expectedSha:string){
 const systemCheck=checkServerIdentity(hostname,cert);
 if(systemCheck)throw systemCheck;
 if(!cert.raw)throw new ChainConflictError('Missing authenticated TLS peer certificate bytes');
 let actual:Buffer;
 try{
  const x=new X509Certificate(cert.raw);
  const spki=x.publicKey.export({format:'der',type:'spki'});
  actual=createHash('sha256').update(spki).digest();
 }catch{throw new ChainConflictError('Cannot inspect TLS peer SPKI');}
 const expected=Buffer.from(expectedSha,'hex');
 if(expected.length!==32||!timingSafeEqual(actual,expected))
  throw new ChainConflictError('TLS peer SPKI not the separately pre-pinned provider key');
}
export async function fetchPinnedRevocationEnvelope(env:NodeJS.ProcessEnv):Promise<unknown>{
 const cfg=transportAllowed(env);
 const url=new URL(REVOCATION_PATH,cfg.origin);
 if(url.origin!==cfg.origin||url.protocol!=='https:')
  throw new ChainInputError('Pinned provider URL escaped allowed origin');
 return new Promise((resolve,reject)=>{
  let settled=false;
  const settle=(error?:unknown,data?:unknown)=>{
   if(settled)return;settled=true;
   if(error)reject(error);else resolve(data);
  };
  const request=https.request(url,{
   method:'GET',timeout:4000,rejectUnauthorized:true,
   headers:{accept:'application/json','accept-encoding':'identity',
    'user-agent':'AadiTech-ReadOnly-Provider-Bridge/1AL'},
   maxHeaderSize:8192,
   checkServerIdentity:(hostname,cert)=>{
    try{validateTlsPeer(hostname,cert,cfg.tlsFingerprint);}
    catch(e){return e instanceof Error?e:new ChainConflictError('Invalid provider TLS pin');}
    return undefined;
   }
  },response=>{
   if(response.statusCode!==200||
     !/^application\/json(?:;|$)/i.test(String(response.headers['content-type']??''))||
     response.headers['content-encoding']||
     response.headers.location){
    response.resume();settle(new ChainConflictError('Provider response not direct JSON HTTP 200'));return;
   }
   let body='';let length=0;
   response.setEncoding('utf8');
   response.on('data',(chunk:string)=>{
    length+=Buffer.byteLength(chunk);
    if(length>65536){request.destroy(new ChainConflictError('Provider response exceeds 64 KiB'));return;}
    body+=chunk;
   });
   response.on('end',()=>{
    if(settled)return;
    try{
     if(!body)throw new ChainConflictError('Provider feed empty');
     settle(undefined,JSON.parse(body) as unknown);
    }catch{settle(new ChainConflictError('Invalid provider JSON'));}
   });
   response.on('error',e=>settle(e));
  });
  request.on('error',e=>settle(e));
  request.on('timeout',()=>request.destroy(new ChainConflictError('Provider TLS request timed out')));
  request.end();
 });
}
