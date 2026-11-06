import React,{useEffect,useState} from 'react';
import {authenticatedFetch,verifyCurrentPassword,sensitiveFetch} from '../services/authClient';
type Enrollment={secret:string;otpauthUri:string;expiresInSeconds:number};
async function parse<T>(response:Response):Promise<T>{
 const value:unknown=await response.json();
 if(!response.ok)throw Error(value&&typeof value==='object'&&'error' in value?String(value.error):'MFA request failed');
 return value as T;
}
export function MFASettings(){
 const [enabled,setEnabled]=useState<boolean|null>(null);
 const [password,setPassword]=useState('');
 const [code,setCode]=useState('');
 const [rotationPassword,setRotationPassword]=useState('');
 const [rotationCode,setRotationCode]=useState('');
 const [pending,setPending]=useState<Enrollment|null>(null);
 const [recovery,setRecovery]=useState<string[]>([]);
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState('');
 useEffect(()=>{
  let alive=true;
  authenticatedFetch('/api/auth/mfa/status').then(r=>parse<{enabled:boolean}>(r))
   .then(v=>{if(alive)setEnabled(v.enabled);})
   .catch(e=>{if(alive)setError(String(e));});
  return()=>{alive=false;};
 },[]);
 async function start(event:React.FormEvent){
  event.preventDefault();setBusy(true);setError('');
  try{
   await verifyCurrentPassword(password);
   const result=await parse<Enrollment>(await sensitiveFetch('/api/auth/mfa/enroll/start',{method:'POST'}));
   setPending(result);setPassword('');
  }catch(e){setError(e instanceof Error?e.message:'Enrollment failed');}
  finally{setBusy(false);}
 }
 async function activate(event:React.FormEvent){
  event.preventDefault();setBusy(true);setError('');
  try{
   const response=await sensitiveFetch('/api/auth/mfa/enroll/activate',{
    method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code})
   });
   const value=await parse<{recoveryCodes:string[];enabled:boolean;signInRequired:boolean}>(response);
   setRecovery(value.recoveryCodes);setPending(null);setCode('');setEnabled(true);
  }catch(e){setError(e instanceof Error?e.message:'Could not activate MFA');}
  finally{setBusy(false);}
 }
 async function rotate(event:React.FormEvent){
  event.preventDefault();setBusy(true);setError('');
  try{
   await verifyCurrentPassword(rotationPassword);
   const value=await parse<{recoveryCodes:string[];rotated:boolean}>(await sensitiveFetch('/api/auth/mfa/recovery/rotate',{
    method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:rotationCode})
   }));
   setRecovery(value.recoveryCodes);setRotationPassword('');setRotationCode('');
  }catch(e){setError(e instanceof Error?e.message:'Rotation failed');}
  finally{setBusy(false);}
 }
 return <section className="border border-slate-700 bg-slate-900 rounded-xl p-5 space-y-4 max-w-3xl mx-auto" aria-label="Authenticator MFA settings">
  <h2 className="text-lg font-semibold">Authenticator MFA</h2>
  <p className="text-sm text-slate-400">Optional TOTP security. Only you can enable MFA for your signed-in account. The encryption key must be configured on the server.</p>
  {error&&<p role="alert" className="text-rose-300 text-sm">{error}</p>}
  {enabled===null&&<p className="text-sm">Loading MFA status…</p>}
  {enabled&&!recovery.length&&<p className="text-emerald-300 text-sm">Authenticator MFA is enabled. Sign-in requires a second factor.</p>}
  {recovery.length>0&&<div role="status" className="border border-amber-700 p-4 rounded space-y-2">
   <h3 className="font-semibold text-amber-200">Save these one-time recovery codes NOW</h3>
   <p className="text-xs text-amber-200">Each code works once. Codes are not stored in plaintext or shown again. After initial MFA enrollment your prior sessions were revoked. After code rotation, store the new codes securely.</p>
   <pre className="text-sm select-text whitespace-pre-wrap">{recovery.join('\n')}</pre>
   <button type="button" className="border rounded px-3 py-2 text-sm"
    onClick={()=>{void navigator.clipboard.writeText(recovery.join('\n'));}}>Copy recovery codes</button>
   <button type="button" onClick={()=>window.location.reload()} className="block bg-cyan-700 p-2 rounded">I have safely stored them</button>
  </div>}
  {enabled===true&&recovery.length===0&&<form onSubmit={rotate} className="border-t border-slate-700 pt-3 space-y-3">
   <h3 className="text-sm font-semibold">Replace lost or exposed recovery codes</h3>
   <p className="text-xs text-amber-300">Requires your current password, an MFA-verified session and a fresh authenticator code. All old codes become invalid immediately; do not proceed without access to your authenticator.</p>
   <label className="block text-sm">Current password
    <input type="password" autoComplete="current-password" required value={rotationPassword}
     onChange={e=>setRotationPassword(e.target.value)}
     className="block w-full bg-slate-950 border border-slate-600 rounded p-2 mt-1"/>
   </label>
   <label className="block text-sm">Fresh authenticator code
    <input inputMode="numeric" pattern="[0-9]{6}" maxLength={6} required value={rotationCode}
     onChange={e=>setRotationCode(e.target.value)}
     className="block w-full bg-slate-950 border border-slate-600 rounded p-2 mt-1"/>
   </label>
   <button type="submit" disabled={busy} className="bg-amber-700 rounded p-2 disabled:opacity-40">Rotate all recovery codes</button>
  </form>}
  {enabled===false&&!pending&&<form onSubmit={start} className="space-y-3">
   <label className="block text-sm">Confirm current password to start enrollment
    <input type="password" autoComplete="current-password" value={password} required
     onChange={e=>setPassword(e.target.value)} className="block w-full bg-slate-950 border border-slate-600 rounded p-2 mt-1"/>
   </label>
   <button type="submit" disabled={busy} className="bg-cyan-700 p-2 rounded disabled:opacity-40">Start TOTP enrollment</button>
  </form>}
  {pending&&<form onSubmit={activate} className="space-y-3">
   <p className="text-sm text-amber-200">Add this secret manually to an authenticator (30 seconds, 6 digits). Do not share it.</p>
   <code className="block bg-slate-950 break-all border border-slate-700 p-3 rounded text-sm">{pending.secret}</code>
   <p className="text-xs text-slate-500">Setup URI: {pending.otpauthUri}</p>
   <label className="block text-sm">First authenticator code
    <input value={code} required inputMode="numeric" pattern="[0-9]{6}" maxLength={6}
     onChange={e=>setCode(e.target.value)} className="block w-full bg-slate-950 border border-slate-600 rounded p-2 mt-1"/>
   </label>
   <button type="submit" disabled={busy} className="bg-cyan-700 p-2 rounded disabled:opacity-40">Verify code and enable MFA</button>
  </form>}
 </section>;
}
