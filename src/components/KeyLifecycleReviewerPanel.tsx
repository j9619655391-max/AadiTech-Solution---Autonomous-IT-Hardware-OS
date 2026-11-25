import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Receipt={receiptId:string;keyId:string;fingerprint:string;partyKind:string;
 registeredBy:string;reviewState:string|null;status:string};
type Rotation={rotationId:string;oldKeyId:string;newKeyId:string;
 oldFingerprint:string;newFingerprint:string;preparedBy:string;status:string;
 reason:string;evidenceRef:string};
type ReceiptDetail={receiptId:string;message:Record<string,unknown>;
 candidateFingerprint:string;signatureMatched:boolean;actualSupplierIdentityVerified:boolean};
async function decoded<T>(r:Response):Promise<T>{
 const x:unknown=await r.json();
 if(!r.ok)throw Error(x&&typeof x==='object'&&'error' in x?String(x.error):'Key lifecycle review unavailable');
 return x as T;
}
export function KeyLifecycleReviewerPanel(){
 const [receipts,setReceipts]=useState<Receipt[]>([]),[rotations,setRotations]=useState<Rotation[]>([]);
 const [selectedReceipt,setSelectedReceipt]=useState<ReceiptDetail|null>(null),
 [selectedRotation,setSelectedRotation]=useState<Rotation|null>(null);
 const [decision,setDecision]=useState<'REVIEWED_UNTRUSTED'|'REJECTED_INTERNAL'>('REJECTED_INTERNAL'),
 [reason,setReason]=useState(''),[evidence,setEvidence]=useState(''),[inspected,setInspected]=useState(false),
 [password,setPassword]=useState(''),[verified,setVerified]=useState(false),
 [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  const [a,b]=await Promise.all([
   decoded<{items:Receipt[]}>(await authenticatedFetch('/api/key-lifecycle/review/receipts')),
   decoded<{items:Rotation[]}>(await authenticatedFetch('/api/key-lifecycle/review/rotations'))]);
  setReceipts(a.items);setRotations(b.items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setPassword('');setVerified(true);
   setNotice('Recent reviewer step-up verified. Privileged MFA still enforced by server.');}
  catch(e){setVerified(false);setError(String(e));}finally{setBusy(false);}
 }
 async function openReceipt(id:string){
  setBusy(true);setError('');
  try{
   const v=await decoded<ReceiptDetail>(await authenticatedFetch(
    '/api/key-lifecycle/review/receipts/'+encodeURIComponent(id)));
   setSelectedReceipt(v);setSelectedRotation(null);
   setDecision('REJECTED_INTERNAL');setReason('');setEvidence('');setInspected(false);
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 function openRotation(item:Rotation){
  setSelectedRotation(item);setSelectedReceipt(null);setDecision('REJECTED_INTERNAL');
  setReason('');setEvidence('');setInspected(false);setError('');
 }
 async function decide(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{
   if(!verified||!hasRecentVerification())throw Error('Recent password verification required');
   if(!selectedReceipt&&!selectedRotation)throw Error('Select internal proof or rotation');
   if(!window.confirm('Confirm INTERNAL-only review? Positive rotation immediately retires the old key. External supplier/warehouse trust remains UNVERIFIED.'))return;
   const route=selectedReceipt?
    '/api/key-lifecycle/review/receipts/'+encodeURIComponent(selectedReceipt.receiptId)+'/decide':
    '/api/key-lifecycle/review/rotations/'+encodeURIComponent(selectedRotation!.rotationId)+'/decide';
   const result=await decoded<{status?:string;decision?:string;oldKeyRetired?:boolean}>(
    await sensitiveFetch(route,{method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({decision,reason,evidenceRef:evidence,possessionInspected:inspected})}));
   setNotice((result.status??result.decision)+' · old key retired: '+
    String(result.oldKeyRetired??false)+'. No identity authentication or GRN/stock credit.');
   setSelectedReceipt(null);setSelectedRotation(null);await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 return <section aria-label="Independent offline key lifecycle reviewer"
  className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="text-lg font-semibold">Phase 1AJ · Independent possession & rotation review</h2>
  <p className="text-xs text-amber-200">A matched offline signature verifies private-key control only.
   It does NOT authenticate supplier/warehouse identity, issue a PO, certify goods receipt,
   transfer serial title or make stock available. Rotation approval permanently retires the old candidate.</p>
  {error&&<p role="alert" className="border border-rose-700 rounded p-2 text-xs text-rose-200">{error}</p>}
  {notice&&<p role="status" className="border border-cyan-700 rounded p-2 text-xs text-cyan-200">{notice}</p>}
  <button type="button" disabled={busy} className="text-xs text-cyan-300"
   onClick={()=>void refresh().catch(e=>setError(String(e)))}>Refresh review queues</button>
  <form onSubmit={verify} className="rounded border border-slate-700 p-3 flex gap-2 flex-wrap items-end">
   <label className="text-xs block">Reviewer current password
    <input required autoComplete="current-password" type="password" value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block mt-1 p-2 rounded bg-slate-950 border border-slate-700"/></label>
   <button disabled={busy} className="text-xs rounded bg-amber-800 px-3 py-2">Verify</button>
  </form>
  <div className="grid md:grid-cols-2 gap-3">
   <div className="border border-slate-700 rounded p-3 space-y-2">
    <h3 className="text-sm font-semibold">One-time possession receipts</h3>
    {receipts.length===0?<p className="text-xs text-slate-400">No possession receipts yet.</p>:
     receipts.map(r=><div key={r.receiptId} className="border-t border-slate-700 py-2 text-xs">
      <p>{r.receiptId.slice(0,14)} · {r.partyKind} · {r.reviewState??'AWAITING REVIEW'}</p>
      <p className="break-all">Candidate SHA {r.fingerprint}</p>
      {!r.reviewState&&<button type="button" className="text-cyan-300"
       onClick={()=>void openReceipt(r.receiptId)}>Inspect detached signature and nonce</button>}
     </div>)}
   </div>
   <div className="border border-slate-700 rounded p-3 space-y-2">
    <h3 className="text-sm font-semibold">Dual-key rotation requests</h3>
    {rotations.length===0?<p className="text-xs text-slate-400">No rotation proposals.</p>:
     rotations.map(x=><div key={x.rotationId} className="border-t border-slate-700 py-2 text-xs">
      <p>{x.rotationId.slice(0,14)} · {x.status}</p>
      <p className="break-all">Old {x.oldFingerprint} → New {x.newFingerprint}</p>
      {x.status==='PENDING_INTERNAL'&&<button type="button" className="text-cyan-300"
       onClick={()=>openRotation(x)}>Inspect keys and retirement authority</button>}
     </div>)}
   </div>
  </div>
  {selectedReceipt&&<div className="border border-amber-700 rounded p-3 text-xs space-y-2">
   <h3 className="text-sm font-semibold">Signed one-time nonce evidence</h3>
   <p className="break-all">Candidate SHA {selectedReceipt.candidateFingerprint}</p>
   <p>Ed25519 signature matched: {String(selectedReceipt.signatureMatched)}
    · Supplier identity authenticated: {String(selectedReceipt.actualSupplierIdentityVerified)}</p>
   <textarea readOnly rows={6} value={JSON.stringify(selectedReceipt.message,null,2)}
    className="block w-full rounded bg-slate-950 border border-slate-700 p-2 font-mono text-xs"/>
  </div>}
  {selectedRotation&&<div className="border border-amber-700 rounded p-3 space-y-2 text-xs">
   <h3 className="text-sm font-semibold">Dual-possession retirement change</h3>
   <p className="break-all">Old SHA: {selectedRotation.oldFingerprint}</p>
   <p className="break-all">New SHA: {selectedRotation.newFingerprint}</p>
   <p>Owner: {selectedRotation.preparedBy}</p>
   <p>Original reason: {selectedRotation.reason}</p>
   <p>Source ticket: {selectedRotation.evidenceRef}</p>
   <p className="text-amber-200">Positive decision retires old key permanently.
    New key remains self-registered and EXTERNALLY UNVERIFIED.</p>
  </div>}
  {(selectedReceipt||selectedRotation)&&<form onSubmit={decide}
   className="border border-slate-700 rounded p-3 space-y-2">
   <label className="text-xs block">One-time independent INTERNAL decision
    <select value={decision} onChange={e=>setDecision(e.target.value as typeof decision)}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2">
     <option value="REJECTED_INTERNAL">REJECTED_INTERNAL</option>
     <option value="REVIEWED_UNTRUSTED">REVIEWED_UNTRUSTED (no external trust)</option>
    </select></label>
   <label className="text-xs block">Written reviewer reason (12–1000 characters)
    <textarea required minLength={12} maxLength={1000} value={reason} rows={3}
     onChange={e=>setReason(e.target.value)}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>
   <label className="text-xs block">Independent evidence ticket
    <input required value={evidence} onChange={e=>setEvidence(e.target.value)}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>
   <label className="flex gap-2 text-xs text-amber-200">
    <input type="checkbox" checked={inspected} onChange={e=>setInspected(e.target.checked)}/>
    I independently inspected key fingerprints, matching nonce receipts and change rationale;
    this does not certify external party identity.</label>
   <button disabled={busy||!verified||(decision==='REVIEWED_UNTRUSTED'&&!inspected)}
    className="text-xs bg-amber-800 rounded px-4 py-2 disabled:opacity-50">
    Record irreversible internal review</button>
  </form>}
 </section>;
}
