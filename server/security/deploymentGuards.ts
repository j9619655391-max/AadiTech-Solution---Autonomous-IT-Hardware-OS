import {isIP} from 'node:net';
import type {RequestHandler} from 'express';

export interface DeploymentSecurityConfig {
 production:boolean;
 bindHost:string;
 trustedProxyCidrs:string[];
 httpsRequired:boolean;
 publicBind:boolean;
 appOrigin:string|null;
}
export function parseTrustedProxyCidrs(value:string|undefined):string[]{
 if(!value)return [];
 const entries=value.split(',').map(x=>x.trim());
 if(entries.length>8||entries.some(x=>!x)||new Set(entries).size!==entries.length)
  throw Error('APP_TRUSTED_PROXY_CIDRS requires 1–8 distinct explicit IP/CIDR entries');
 for(const entry of entries){
  const parts=entry.split('/');
  if(parts.length>2)throw Error('Invalid trusted proxy address');
  const version=isIP(parts[0]);
  if(!version)throw Error('Trusted proxy must be an IP or CIDR, not a hostname');
  if(parts.length===2){
   const max=version===4?32:128;
   if(!/^(0|[1-9][0-9]*)$/.test(parts[1]))throw Error('Invalid trusted proxy mask');
   const bits=Number(parts[1]);
   // A broad private range is an unsafe trust boundary; use specific ingress addresses.
   if(bits< (version===4?24:64)||bits>max)
    throw Error('Trusted proxy CIDR range is too broad');
  }
 }
 return entries;
}
export function resolveDeploymentSecurity(env:NodeJS.ProcessEnv):DeploymentSecurityConfig{
 const production=env.NODE_ENV==='production';
 if(!production){
  return {production:false,bindHost:env.APP_BIND_HOST||'127.0.0.1',
   trustedProxyCidrs:[],httpsRequired:false,publicBind:false,appOrigin:null};
 }
 const errors:string[]=[];
 let proxies:string[]=[];
 try{proxies=parseTrustedProxyCidrs(env.APP_TRUSTED_PROXY_CIDRS);}
 catch{errors.push('APP_TRUSTED_PROXY_CIDRS must contain narrow trusted ingress IP/CIDRs');}
 if(!proxies.length)errors.push('APP_TRUSTED_PROXY_CIDRS must specify the actual reverse proxy');
 let origin:string|null=null;
 try{
  if(!env.APP_URL)throw Error('missing');
  const url=new URL(env.APP_URL);
  if(url.protocol!=='https:'||url.username||url.password||url.pathname!=='/'||
     url.search||url.hash||!url.hostname)throw Error('invalid');
  origin=url.origin;
 }catch{errors.push('APP_URL must be a clean HTTPS origin');}
 if(env.APP_REQUIRE_HTTPS!=='true')errors.push('APP_REQUIRE_HTTPS=true required');
 if(env.DB_SSL!=='true')errors.push('DB_SSL=true required');
 if(env.MFA_REQUIRE_PRIVILEGED!=='true')
  errors.push('MFA_REQUIRE_PRIVILEGED=true required');
 if(!/^[a-fA-F0-9]{64}$/.test(env.MFA_ENCRYPTION_KEY||''))
  errors.push('MFA_ENCRYPTION_KEY must be 32-byte hex');
 for(const key of ['DB_HOST','DB_PORT','DB_USER','DB_NAME','DB_PASSWORD']){
  if(!env[key])errors.push(key+' required');
 }
 if(env.DB_PORT && (!/^[0-9]+$/.test(env.DB_PORT)||Number(env.DB_PORT)<1||Number(env.DB_PORT)>65535))
  errors.push('DB_PORT must be valid TCP port');
 if(env.APP_ALLOW_PUBLIC_BIND && env.APP_ALLOW_PUBLIC_BIND!=='true')
  errors.push('APP_ALLOW_PUBLIC_BIND must be true or unset');
 const bindHost=env.APP_BIND_HOST||'127.0.0.1';
 const publicBind=!['127.0.0.1','::1'].includes(bindHost);
 if(isIP(bindHost)===0)errors.push('APP_BIND_HOST must be a literal IPv4/IPv6 address');
 if(publicBind&&env.APP_ALLOW_PUBLIC_BIND!=='true')
  errors.push('Non-loopback bind requires APP_ALLOW_PUBLIC_BIND=true and network firewall review');
 if(errors.length)throw Error('Production deployment security configuration invalid: '+errors.join('; '));
 return {production:true,bindHost,trustedProxyCidrs:proxies,
  httpsRequired:true,publicBind,appOrigin:origin};
}
export function securityTransportMiddleware(config:DeploymentSecurityConfig):RequestHandler{
 return (req,res,next)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  if(req.path.startsWith('/api/auth'))res.setHeader('Cache-Control','no-store');
  if(!config.httpsRequired){next();return;}
  // Never redirect using the untrusted Host header; reject insecure transport.
  // Proxy must overwrite X-Forwarded-Proto, not append client-supplied values.
  const forwarded=req.get('x-forwarded-proto');
  if(!req.secure || forwarded!=='https'){
   res.setHeader('Cache-Control','no-store');
   res.status(403).json({error:'Verified HTTPS ingress required'});
   return;
  }
  res.setHeader('Strict-Transport-Security','max-age=31536000');
  next();
 };
}
