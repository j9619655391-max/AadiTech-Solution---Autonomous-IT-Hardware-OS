import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Pin={id:string;providerCode:string;providerOrigin:string;rootFingerprint:string;
 tlsFingerprint:string;provisionedBy:string;evidenceRef:string;status:string;frozen:string|null};
type Credential={id:string;pinId:string;issuerId:string;submittedBy:string;purpose:string;
 messageSha256:string;status:string};
type Detail={id:string;status:string;rootFingerprint:string;organizationFingerprint:string;
 message:Record<string,unknown>;rootSignatureMathMatched:boolean;
 externallyAuthenticated:boolean;corporateIdentityVerified:boolean};
async function decode<T>(r:Response):Promise<T>{
 const raw:unknown=await r.json();
 if(!r.ok)throw Error(raw&&typeof raw==='object'&&'error' in raw?String(raw.error):'Pinned provider independent review unavailable');
 return raw as T;
}
export function ProviderBridgeReviewerPanel(){
 const [pins,setPins]=useState<Pin[]>([]),[credentials,setCredentials]=useState<Credential[]>([]);
 const [selectedPin,setSelectedPin]=useState<Pin|null>(null),
 [selectedCredential,setSelectedCredential]=useState<Detail|null>(null);
 const [password,setPassword]=useState(''),[verified,setVerified]=useState(false),
 [reason,setReason]=useState(''),[evidence,setEvidence]=useState(''),
 [inspection,setInspection]=useState(false),[decision,setDecision]=useState('REJECTED_INTERNAL'),
 [error,setError]=useState(''),[notice,setNotice]=useState(''),[busy,setBusy]=useState(false);
 const refresh=useCallback(async()=>{
  const [a,b]=await Promise.all([
   decode<{items:Pin[]}>(await authenticatedFetch('/api/provider-bridge/review/pins')),
   decode<{items:Credential[]}>(await authenticatedFetch('/api/provider-bridge/review/credentials'))]);
  setPins(a.items);setCredentials(b.items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 function reset(){setDecision('REJECTED_INTERNAL');setReason('');setEvidence('');setInspection(false);}
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setVerified(true);setPassword('');
   setNotice('Current reviewer password verified; privileged MFA still required.');}
  catch(e){setVerified(false);setError(String(e));}finally{setBusy(false);}
 }
 function inspectPin(v:Pin){setSelectedPin(v);setSelectedCredential(null);reset();setError('');}
 async function inspectCredential(id:string){
  setBusy(true);setError('');
  try{
   const v=await decode<Detail>(await authenticatedFetch(
    '/api/provider-bridge/review/credentials/'+encodeURIComponent(id)));
   setSelectedCredential(v);setSelectedPin(null);reset();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function decide(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{
   if(!verified||!hasRecentVerification())throw Error('Recent reviewer password verification required');
   if(!selectedPin&&!selectedCredential)throw Error('Select an internal pin or signed credential');
   if(!window.confirm('Commit one-time INTERNAL HELD decision? This is NOT corporate KYC, certified root or official GRN.'))return;
   const path=selectedPin?'pins/'+encodeURIComponent(selectedPin.id)+'/decide':
    'credentials/'+encodeURIComponent(selectedCredential!.id)+'/decide';
   const data=await decode<{status:string}>(await sensitiveFetch('/api/provider-bridge/review/'+path,{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({decision,reason,evidenceRef:evidence,evidenceInspected:inspection})}));
   setNotice(data.status+' recorded. External provider/organization authority still UNVERIFIED.');
   setSelectedPin(null);setSelectedCredential(null);await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 const positive=selectedPin?'REVIEWED_HELD':'REVIEWED_CRYPTO_HELD';
 return <section aria-label="Phase 1AL independent provider evidence review"
  className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="font-semibold text-lg">Phase 1AL · Independent server-pinned evidence review</h2>
  <p className="text-xs text-amber-200">A server-configured root and correctly verified Ed25519 signature
   are not independent authentication of a corporate trust provider. Review only the internal source
   and cryptographic math. No corporate KYC, legal issuer authority, genuine GRN or stock posting.</p>
  {error&&<p role="alert" className="text-xs text-rose-200 border border-rose-700 rounded p-2">{error}</p>}
  {notice&&<p role="status" className="text-xs text-cyan-200 border border-cyan-700 rounded p-2">{notice}</p>}
  <button type="button" className="text-cyan-300 text-xs" disabled={busy}
   onClick={()=>void refresh().catch(e=>setError(String(e)))}>Refresh independent queues</button>
  <form onSubmit={verify} className="border border-slate-700 rounded p-3 flex gap-2 flex-wrap items-end">
   <label className="text-xs block">Reviewer current password
    <input required type="password" autoComplete="current-password"
     value={password} onChange={e=>setPassword(e.target.value)}
     className="block mt-1 p-2 rounded bg-slate-950 border border-slate-700"/></label>
   <button disabled={busy} className="rounded bg-amber-800 px-3 py-2 text-xs">Verify</button>
  </form>
  <div className="grid md:grid-cols-2 gap-3">
   <div className="border border-slate-700 rounded p-3 text-xs">
    <h3 className="text-sm font-semibold">Environment-provisioned PUBLIC pin candidates</h3>
    {pins.map(p=><div key={p.id} className="border-t border-slate-700 py-2">
     <p>{p.id.slice(0,14)} · {p.providerCode} · {p.status} · {p.frozen?'FROZEN':'UNVERIFIED'}</p>
     <p className="break-all">Root SHA-256: {p.rootFingerprint}</p>
     <p className="break-all">TLS SHA-256: {p.tlsFingerprint}</p>
     {p.status==='PENDING_INTERNAL'&&!p.frozen&&
      <button type="button" className="text-cyan-300" onClick={()=>inspectPin(p)}>
       Inspect preprovisioned pins only</button>}
    </div>)}
   </div>
   <div className="border border-slate-700 rounded p-3 text-xs">
    <h3 className="text-sm font-semibold">Offline root-signed corporate authority candidates</h3>
    {credentials.map(c=><div key={c.id} className="border-t border-slate-700 py-2">
     <p>{c.id.slice(0,14)} · {c.purpose} · {c.status}</p>
     <p className="break-all">Digest: {c.messageSha256}</p>
     {c.status==='PENDING_INTERNAL'&&
      <button type="button" className="text-cyan-300"
       onClick={()=>void inspectCredential(c.id)}>Inspect canonical root signature</button>}
    </div>)}
   </div>
  </div>
  {selectedPin&&<div className="rounded border border-amber-700 p-3 text-xs space-y-2">
   <h3 className="text-sm font-semibold">Review independently preprovisioned candidate pin</h3>
   <p>Provider label: {selectedPin.providerCode}</p>
   <p>Source origin: {selectedPin.providerOrigin}</p>
   <p>Registered by internal owner: {selectedPin.provisionedBy}</p>
   <p>Evidence ticket: {selectedPin.evidenceRef}</p>
   <p className="break-all">Root SPKI SHA-256: {selectedPin.rootFingerprint}</p>
   <p className="break-all">TLS SPKI SHA-256: {selectedPin.tlsFingerprint}</p>
   <p className="text-amber-200">This review DOES NOT independently contact or certify the real provider.</p>
  </div>}
  {selectedCredential&&<div className="rounded border border-amber-700 p-3 text-xs space-y-2">
   <h3 className="text-sm font-semibold">Review root signature and internal organization linkage</h3>
   <p className="break-all">Root SHA-256: {selectedCredential.rootFingerprint}</p>
   <p className="break-all">Issuer SHA-256: {selectedCredential.organizationFingerprint}</p>
   <p>Detached signature matched: {String(selectedCredential.rootSignatureMathMatched)}</p>
   <p>External root authenticated: {String(selectedCredential.externallyAuthenticated)}
    · Corporate KYC verified: {String(selectedCredential.corporateIdentityVerified)}</p>
   <textarea readOnly rows={8} value={JSON.stringify(selectedCredential.message,null,2)}
    className="block w-full bg-slate-950 border border-slate-700 rounded p-2 font-mono text-xs"/>
  </div>}
  {(selectedPin||selectedCredential)&&<form onSubmit={decide}
   className="border border-slate-700 rounded p-3 space-y-2">
   <label className="text-xs block">Internal-only decision
    <select value={decision} onChange={e=>setDecision(e.target.value)}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2">
     <option value="REJECTED_INTERNAL">REJECTED_INTERNAL</option>
     <option value={positive}>{positive} (NOT external trust)</option>
    </select></label>
   <label className="text-xs block">Detailed inspection reason
    <textarea required minLength={12} maxLength={1000} rows={3}
     value={reason} onChange={e=>setReason(e.target.value)}
     className="block mt-1 w-full rounded p-2 bg-slate-950 border border-slate-700"/></label>
   <label className="text-xs block">Independent internal evidence ticket
    <input required value={evidence} onChange={e=>setEvidence(e.target.value)}
     className="block mt-1 w-full rounded p-2 bg-slate-950 border border-slate-700"/></label>
   <label className="flex gap-2 text-xs text-amber-200">
    <input type="checkbox" checked={inspection} onChange={e=>setInspection(e.target.checked)}/>
    I inspected available INTERNAL key/source documents and math only; not external provider identity.
   </label>
   <button disabled={busy||!verified||(decision===positive&&!inspection)}
    className="rounded bg-amber-800 px-3 py-2 text-xs disabled:opacity-50">
    Commit one-time INTERNAL HELD review</button>
  </form>}
 </section>;
}
