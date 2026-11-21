import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Issuer={id:string;partyKind:string;partyId:string;registeredBy:string;
 fingerprint:string;organizationRegistration:string;evidenceRef:string;status:string;frozen:string|null};
type Attest={id:string;issuerId:string;keyId:string;preparedBy:string;
 purpose:string;digest:string;status:string};
type Detail={id:string;status:string;issuerFingerprint:string;
 candidateKeyFingerprint:string;statement:Record<string,unknown>;digest:string;
 signatureMathematicallyMatched:boolean;externalIssuerAuthenticated:boolean};
async function json<T>(r:Response):Promise<T>{
 const v:unknown=await r.json();
 if(!r.ok)throw Error(v&&typeof v==='object'&&'error' in v?String(v.error):'Independent external trust review unavailable');
 return v as T;
}
export function ExternalTrustReviewerPanel(){
 const [issuers,setIssuers]=useState<Issuer[]>([]),[attest,setAttest]=useState<Attest[]>([]);
 const [selectedIssuer,setSelectedIssuer]=useState<Issuer|null>(null),
 [selectedAttest,setSelectedAttest]=useState<Detail|null>(null);
 const [password,setPassword]=useState(''),[verified,setVerified]=useState(false),
 [decision,setDecision]=useState('REJECTED_INTERNAL'),[reason,setReason]=useState(''),
 [evidence,setEvidence]=useState(''),[inspected,setInspected]=useState(false),
 [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  const [a,b]=await Promise.all([
   json<{items:Issuer[]}>(await authenticatedFetch('/api/external-trust/review/issuers')),
   json<{items:Attest[]}>(await authenticatedFetch('/api/external-trust/review/attestations'))]);
  setIssuers(a.items);setAttest(b.items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 function clear(){setDecision('REJECTED_INTERNAL');setReason('');setEvidence('');setInspected(false);}
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setPassword('');setVerified(true);
   setNotice('Independent reviewer step-up verified; MFA still server enforced.');}
  catch(e){setVerified(false);setError(String(e));}finally{setBusy(false);}
 }
 function selectIssuer(v:Issuer){setSelectedIssuer(v);setSelectedAttest(null);clear();}
 async function selectAttest(id:string){
  setBusy(true);setError('');
  try{
   const v=await json<Detail>(await authenticatedFetch(
    '/api/external-trust/review/attestations/'+encodeURIComponent(id)));
   setSelectedAttest(v);setSelectedIssuer(null);clear();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function decide(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{
   if(!verified||!hasRecentVerification())throw Error('Recent password step-up required');
   if(!selectedIssuer&&!selectedAttest)throw Error('Select an untrusted issuer or signed authority');
   if(!window.confirm('Approve INTERNAL HELD evidence ONLY? This is NOT verified external organization authority.'))return;
   const path=selectedIssuer?
    'issuers/'+encodeURIComponent(selectedIssuer.id)+'/decide':
    'attestations/'+encodeURIComponent(selectedAttest!.id)+'/decide';
   const v=await json<{status:string}>(await sensitiveFetch(
    '/api/external-trust/review/'+path,
    {method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({decision,reason,evidenceRef:evidence,evidenceInspected:inspected})}));
   setNotice(v.status+' recorded. No external root authentication or GRN/stock authorization.');
   setSelectedIssuer(null);setSelectedAttest(null);await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 const pos=selectedIssuer?'REVIEWED_HELD':'REVIEWED_CRYPTO_HELD';
 return <section aria-label="Independent external trust prerequisite reviewer"
  className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="font-semibold text-lg">Phase 1AK · Independent external evidence prerequisite review</h2>
  <p className="text-xs text-amber-200">Reviewing a claimed registry ID and offline issuer signature
   cannot authenticate the real issuing organization without a separately established external root.
   Positive decisions are only INTERNAL HELD, never supplier KYC, official GRN or sellable stock.</p>
  {error&&<p role="alert" className="border border-rose-700 rounded p-2 text-rose-200 text-xs">{error}</p>}
  {notice&&<p role="status" className="border border-cyan-700 rounded p-2 text-cyan-200 text-xs">{notice}</p>}
  <button type="button" disabled={busy} onClick={()=>void refresh().catch(e=>setError(String(e)))}
   className="text-cyan-300 text-xs">Refresh independent review queues</button>
  <form onSubmit={verify} className="border border-slate-700 rounded p-3 flex items-end flex-wrap gap-2">
   <label className="block text-xs">Reviewer current password
    <input required type="password" autoComplete="current-password" value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block mt-1 p-2 rounded bg-slate-950 border border-slate-700"/></label>
   <button disabled={busy} className="rounded px-3 py-2 text-xs bg-amber-800">Verify</button>
  </form>
  <div className="grid md:grid-cols-2 gap-3">
   <div className="border border-slate-700 rounded p-3 text-xs">
    <h3 className="font-semibold text-sm">Self-entered issuer candidates</h3>
    {issuers.map(i=><div key={i.id} className="border-t border-slate-700 py-2">
     <p>{i.id.slice(0,15)} · {i.partyKind} · {i.status} · {i.frozen?'FROZEN':'UNVERIFIED'}</p>
     <p className="break-all">{i.fingerprint}</p>
     {i.status==='PENDING_INTERNAL'&&!i.frozen&&
      <button type="button" onClick={()=>selectIssuer(i)} className="text-cyan-300">
       Inspect internal registry claim</button>}
    </div>)}
   </div>
   <div className="border border-slate-700 rounded p-3 text-xs">
    <h3 className="font-semibold text-sm">Issuer-signed organizational assertions</h3>
    {attest.map(a=><div key={a.id} className="border-t border-slate-700 py-2">
     <p>{a.id.slice(0,15)} · {a.purpose} · {a.status}</p>
     <p className="break-all">{a.digest}</p>
     {a.status==='PENDING_INTERNAL'&&<button type="button"
      className="text-cyan-300" onClick={()=>void selectAttest(a.id)}>
      Independently recheck signed bytes</button>}
    </div>)}
   </div>
  </div>
  {selectedIssuer&&<div className="border border-amber-700 rounded p-3 text-xs space-y-1">
   <h3 className="font-semibold text-sm">Offline issuer candidate, NOT trusted root</h3>
   <p>Party: {selectedIssuer.partyKind} · {selectedIssuer.partyId}</p>
   <p>Claimed registration: {selectedIssuer.organizationRegistration}</p>
   <p>Claimed evidence ticket: {selectedIssuer.evidenceRef}</p>
   <p>Internal owner: {selectedIssuer.registeredBy}</p>
   <p className="break-all">SPKI fingerprint: {selectedIssuer.fingerprint}</p>
  </div>}
  {selectedAttest&&<div className="border border-amber-700 rounded p-3 space-y-2 text-xs">
   <h3 className="font-semibold text-sm">Internally cryptographically matched issuer signature</h3>
   <p className="break-all">Issuer SHA-256: {selectedAttest.issuerFingerprint}</p>
   <p className="break-all">Candidate SHA-256: {selectedAttest.candidateKeyFingerprint}</p>
   <p>Signature math: {String(selectedAttest.signatureMathematicallyMatched)}
    · External issuer authenticated: {String(selectedAttest.externalIssuerAuthenticated)}</p>
   <textarea readOnly rows={7} value={JSON.stringify(selectedAttest.statement,null,2)}
    className="block w-full p-2 rounded bg-slate-950 border border-slate-700 font-mono text-xs"/>
  </div>}
  {(selectedIssuer||selectedAttest)&&<form onSubmit={decide}
   className="border border-slate-700 rounded p-3 space-y-2">
   <label className="block text-xs">One-time independent decision
    <select value={decision} onChange={e=>setDecision(e.target.value)}
     className="block w-full rounded mt-1 p-2 bg-slate-950 border border-slate-700">
     <option value="REJECTED_INTERNAL">REJECTED_INTERNAL</option>
     <option value={pos}>{pos} (internal only)</option>
    </select></label>
   <label className="block text-xs">Written reason (12–1000 chars)
    <textarea required minLength={12} maxLength={1000} rows={3}
     value={reason} onChange={e=>setReason(e.target.value)}
     className="block w-full mt-1 rounded p-2 bg-slate-950 border border-slate-700"/></label>
   <label className="block text-xs">Internal evidence reference
    <input required value={evidence} onChange={e=>setEvidence(e.target.value)}
     className="block w-full mt-1 rounded p-2 bg-slate-950 border border-slate-700"/></label>
   <label className="flex gap-2 text-xs text-amber-200">
    <input type="checkbox" checked={inspected} onChange={e=>setInspected(e.target.checked)}/>
    I inspected available internal registry/source documents and signature math, NOT real external identity.
   </label>
   <button disabled={busy||!verified||(decision===pos&&!inspected)}
    className="rounded px-3 py-2 text-xs bg-amber-800 disabled:opacity-50">
    Record internal-only review</button>
  </form>}
 </section>;
}
