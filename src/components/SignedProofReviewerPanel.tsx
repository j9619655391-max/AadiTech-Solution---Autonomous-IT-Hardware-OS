import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Key={id:string;partyKind:string;supplierId:string|null;siteId:string|null;
 fingerprintSha256:string;registeredBy:string;evidenceRef:string;status:string};
type Claim={id:string;kind:string;keyId:string;createdBy:string;status:string;
 messageSha256:string;signatureMatched:boolean};
type Details={claim:{id:string;kind:string;status:string};sourceId:string;
 message:Record<string,unknown>;messageSha256:string;
 candidateKeyFingerprint:string;cryptographicSignatureMatched:boolean;
 externalIdentityAuthenticated:boolean;officialGrnAuthenticated:boolean};
async function json<T>(r:Response):Promise<T>{
 const v:unknown=await r.json();
 if(!r.ok)throw Error(v&&typeof v==='object'&&'error' in v?String(v.error):'Independent review unavailable');
 return v as T;
}
export function SignedProofReviewerPanel(){
 const [keys,setKeys]=useState<Key[]>([]),[claims,setClaims]=useState<Claim[]>([]);
 const [selectedKey,setSelectedKey]=useState<Key|null>(null),[selectedClaim,setSelectedClaim]=useState<Details|null>(null);
 const [password,setPassword]=useState(''),[verified,setVerified]=useState(false);
 const [decision,setDecision]=useState('REJECTED_INTERNAL'),[reason,setReason]=useState(''),
 [evidence,setEvidence]=useState(''),[inspected,setInspected]=useState(false),
 [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  const [k,c]=await Promise.all([
   json<{items:Key[]}>(await authenticatedFetch('/api/proof-foundation/review/keys')),
   json<{items:Claim[]}>(await authenticatedFetch('/api/proof-foundation/review/claims'))]);
  setKeys(k.items);setClaims(c.items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 function chooseKey(k:Key){
  setSelectedKey(k);setSelectedClaim(null);setDecision('REJECTED_INTERNAL');
  setReason('');setEvidence('');setInspected(false);setError('');
 }
 async function chooseClaim(c:Claim){
  setBusy(true);setError('');
  try{
   const v=await json<Details>(await authenticatedFetch(
    '/api/proof-foundation/review/claims/'+encodeURIComponent(c.id)));
   setSelectedClaim(v);setSelectedKey(null);setDecision('REJECTED_INTERNAL');
   setReason('');setEvidence('');setInspected(false);
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setVerified(true);setPassword('');
   setNotice('Independent reviewer password reverified; privileged MFA remains enforced.');}
  catch(e){setVerified(false);setError(String(e));}finally{setBusy(false);}
 }
 async function decide(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{
   if(!verified||!hasRecentVerification())throw Error('Reverify current reviewer password');
   if(!selectedKey&&!selectedClaim)throw Error('Select a key candidate or offline claim');
   if(!window.confirm('Record INTERNAL key-format/signature review ONLY? It cannot authenticate vendor identity or official warehouse GRN.'))return;
   const path=selectedKey?
    '/api/proof-foundation/review/keys/'+encodeURIComponent(selectedKey.id)+'/decide':
    '/api/proof-foundation/review/claims/'+encodeURIComponent(selectedClaim!.claim.id)+'/decide';
   const r=await json<{status:string}>(await sensitiveFetch(path,{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({decision,reason,evidenceRef:evidence,documentInspected:inspected})}));
   setNotice('Internal '+r.status+' recorded. External provenance remains UNVERIFIED.');
   setSelectedKey(null);setSelectedClaim(null);await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 const isKey=!!selectedKey,positive=isKey?'REVIEWED_UNTRUSTED':'REVIEWED_CRYPTO_ONLY';
 return <section aria-label="Independent offline cryptographic proof reviewer"
  className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="text-lg font-semibold">Phase 1AI · Candidate public-key / signature review</h2>
  <p className="text-xs text-amber-200">A valid signature proves only possession of a SELF-REGISTERED key.
   Even independent internal approval is not supplier authentication, official PO issuance,
   vendor acceptance, legal warehouse GRN or stock posting authority.</p>
  {error&&<p role="alert" className="border border-rose-700 text-rose-200 rounded p-3 text-xs">{error}</p>}
  {notice&&<p role="status" className="border border-cyan-700 text-cyan-200 rounded p-3 text-xs">{notice}</p>}
  <button type="button" disabled={busy} className="text-xs text-cyan-300"
   onClick={()=>void refresh().catch(e=>setError(String(e)))}>
   Refresh internal evidence queues</button>
  <form onSubmit={verify} className="flex gap-3 flex-wrap items-end border border-slate-700 p-3 rounded">
   <label className="text-xs">Current reviewer password
    <input required autoComplete="current-password" type="password" value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block mt-1 rounded p-2 bg-slate-950 border border-slate-700"/></label>
   <button type="submit" disabled={busy} className="rounded px-3 py-2 text-xs bg-amber-800">Verify</button>
   <span className="text-xs text-slate-400">{verified&&hasRecentVerification()?'Step-up active':'Step-up required'}</span>
  </form>
  <div className="grid md:grid-cols-2 gap-3">
   <div className="rounded border border-slate-700 p-3">
    <h3 className="font-semibold text-sm">Owner-submitted public-key CANDIDATES</h3>
    {keys.length===0?<p className="text-xs text-slate-400">No candidate keys.</p>:
     keys.map(k=><div key={k.id} className="border-t border-slate-700 py-2 text-xs">
      <p>{k.id.slice(0,14)} · {k.partyKind} · {k.status}</p>
      <p className="break-all">SHA-256 {k.fingerprintSha256}</p>
      {k.status==='PENDING_INTERNAL'&&<button type="button"
       onClick={()=>chooseKey(k)} className="text-cyan-300">Inspect key-format evidence</button>}
     </div>)}
   </div>
   <div className="rounded border border-slate-700 p-3">
    <h3 className="font-semibold text-sm">Offline signature CLAIMS (not supplier verification)</h3>
    {claims.length===0?<p className="text-xs text-slate-400">No signed claims.</p>:
     claims.map(c=><div key={c.id} className="border-t border-slate-700 py-2 text-xs">
      <p>{c.id.slice(0,14)} · {c.kind} · {c.status}</p>
      <button type="button" className="text-cyan-300" onClick={()=>void chooseClaim(c)}>
       Recheck source-bound detached signature</button>
     </div>)}
   </div>
  </div>
  {selectedKey&&<div className="rounded border border-amber-700 p-3 space-y-1 text-xs">
   <h3 className="font-semibold text-sm">Inspect UNTRUSTED public key</h3>
   <p>Candidate {selectedKey.id} · {selectedKey.partyKind}</p>
   <p>Registered by {selectedKey.registeredBy}</p>
   <p className="break-all">SPKI fingerprint {selectedKey.fingerprintSha256}</p>
   <p>Offline ticket {selectedKey.evidenceRef}</p>
   <p className="text-amber-200">Document inspection is INTERNAL ONLY; never confirm external key ownership.</p>
  </div>}
  {selectedClaim&&<div className="rounded border border-amber-700 p-3 space-y-2 text-xs">
   <h3 className="font-semibold text-sm">Reverified detached cryptographic claim</h3>
   <p>{selectedClaim.claim.kind} · source {selectedClaim.sourceId}</p>
   <p className="break-all">Message digest {selectedClaim.messageSha256}</p>
   <p className="break-all">Candidate key digest {selectedClaim.candidateKeyFingerprint}</p>
   <p>Signature math matched: {String(selectedClaim.cryptographicSignatureMatched)}</p>
   <p>External identity trusted: {String(selectedClaim.externalIdentityAuthenticated)}
    · Official GRN: {String(selectedClaim.officialGrnAuthenticated)}</p>
   <textarea readOnly rows={6} value={JSON.stringify(selectedClaim.message,null,2)}
    className="block w-full bg-slate-950 border border-slate-700 rounded p-2 font-mono text-xs"/>
  </div>}
  {(selectedKey||selectedClaim)&&
   (selectedKey?.status==='PENDING_INTERNAL'||selectedClaim?.claim.status==='PENDING_INTERNAL')&&
   <form onSubmit={decide} className="rounded border border-slate-700 p-3 space-y-3">
    <label className="block text-xs">Independent INTERNAL outcome (never EXTERNALLY TRUSTED)
     <select value={decision} onChange={e=>setDecision(e.target.value)}
      className="block w-full mt-1 bg-slate-950 border border-slate-700 rounded p-2">
      <option value="REJECTED_INTERNAL">Reject candidate evidence</option>
      <option value={positive}>{positive} (NO external authority)</option>
     </select></label>
    <label className="block text-xs">Independent review ticket
     <input required value={evidence} onChange={e=>setEvidence(e.target.value)}
      className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>
    <label className="block text-xs">Detailed rationale (12–1000 characters)
     <textarea required rows={3} minLength={12} maxLength={1000} value={reason}
      onChange={e=>setReason(e.target.value)}
      className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>
    <label className="flex gap-2 text-xs text-amber-200">
     <input type="checkbox" checked={inspected} onChange={e=>setInspected(e.target.checked)}/>
     I inspected the internal key format, signature math and frozen-source evidence
     (mandatory for a positive INTERNAL review).</label>
    <button type="submit" disabled={busy||!verified||(decision===positive&&!inspected)}
     className="rounded bg-amber-800 px-3 py-2 text-xs disabled:opacity-50">
     Record irreversible internal review (no authentication)</button>
   </form>}
 </section>;
}
