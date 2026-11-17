import {isIP} from 'node:net';
import type {RequestHandler} from 'express';

// Phase 1BU: diagnostic/developer Vite tooling must never bind a LAN/public
// interface or become reachable by DNS rebinding / forwarded Host tricks.
// Security boundaries here cover the local dev server; they do NOT fix the
// unpatched picomatch ReDoS or authorize real staging/production operation.
export type DevToolExposure={
 bindHost:'127.0.0.1'|'::1';
 port:number;
 allowedOrigins:readonly string[];
 prodAuthorityEstablished:false;
 vulnerableDevToolingStillInstalled:true;
 independentSecurityApprovalVerified:false;
 productionReleaseAuthorized:false;
 releaseDecision:'HOLD'
};

export function resolveDevToolExposure(
 env:NodeJS.ProcessEnv,port:number
):DevToolExposure{
 if(env.NODE_ENV==='production')throw Error('Phase 1BU tooling disabled in production');
 if(env.NODE_ENV!==undefined&&!['development','test'].includes(env.NODE_ENV))
  throw Error('Phase 1BU unknown nonproduction NODE_ENV is not authorized');
 if(!Number.isSafeInteger(port)||port<1||port>65535)
  throw Error('Phase 1BU invalid developer listener port');
 const bind=env.APP_BIND_HOST??'127.0.0.1';
 if(bind!=='127.0.0.1'&&bind!=='::1')
  throw Error('Phase 1BU developer tooling must bind literal loopback only');
 if(env.APP_ALLOW_PUBLIC_BIND==='true'||
    (env.VITE_HOST!==undefined&&env.VITE_HOST!==bind)||
    (env.HOST!==undefined&&env.HOST!==bind)||
    env.__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS||
    env.VITE_ADDITIONAL_ALLOWED_HOSTS||
    env.DEV_SERVER_PUBLIC==='true')
  throw Error('Phase 1BU public/dev host override forbidden');
 if(isIP(bind)===0)throw Error('Phase 1BU no hostname or wildcard bind');
 const localPort=':'+port;
 return Object.freeze({
  bindHost:bind,port,
  allowedOrigins:Object.freeze([
   'http://127.0.0.1'+localPort,
   'http://localhost'+localPort,
   'http://[::1]'+localPort
  ]),
  prodAuthorityEstablished:false,
  vulnerableDevToolingStillInstalled:true,
  independentSecurityApprovalVerified:false,
  productionReleaseAuthorized:false,
  releaseDecision:'HOLD' as const
 });
}
export function devToolHostGate(config:DevToolExposure):RequestHandler{
 const allowedHosts=new Set(config.allowedOrigins.map(o=>new URL(o).host));
 const allowedOrigins=new Set(config.allowedOrigins);
 return (req,res,next)=>{
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Cache-Control','no-store');
  const host=req.headers.host;
  const origin=req.headers.origin;
  if(typeof host!=='string'||!allowedHosts.has(host)||
     (origin!==undefined&&(
       typeof origin!=='string'||!allowedOrigins.has(origin)
     ))||
     req.headers['x-forwarded-host']!==undefined||
     req.headers['x-original-host']!==undefined||
     req.headers['forwarded']!==undefined||
     req.headers['x-forwarded-proto']!==undefined||
     req.headers['x-forwarded-for']!==undefined){
   res.status(403).json({error:'Local-only developer tooling request denied'});
   return;
  }
  next();
 };
}
