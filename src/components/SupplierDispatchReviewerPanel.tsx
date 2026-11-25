import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,hasRecentVerification,sensitiveFetch,verifyCurrentPassword} from '../services/authClient';
type Destination={id:string;supplierCode:string;email:string;status:string;evidenceRef:string};
type Dispatch={id:string;holdId:string;status:string;manifestSha256:string;email:string;
 supplierCode:string;destinationStatus:string};
type Detail={preparation:{id:string;status:string;destinationStatus:string};
 manifest:{email:string;supplierId:string;holdId:string;holdSha256:string;
  authorizationEvidenceRef:string;dispatchState:string;externalOrderIssued:boolean}};
async function read<T>(r:Response):Promise<T>{
 const payload:unknown=await r.json();
 if(!r.ok)throw Error(payload&&typeof payload==='object'&&'error' in payload?String(payload.error):'Review unavailable');
 return payload as T;
}
export function SupplierDispatchReviewerPanel(){
 const [destinations,setDestinations]=useState<Destination[]>([]),[requests,setRequests]=useState<Dispatch[]>([]);
 const [selected,setSelected]=useState<Detail|null>(null),[password,setPassword]=useState('');
 const [activeDestination,setActiveDestination]=useState<Destination|null>(null);
 const [verified,setVerified]=useState(false),[busy,setBusy]=useState(false);
 const [decision,setDecision]=useState<'APPROVED_INTERNAL'|'REJECTED_INTERNAL'>('REJECTED_INTERNAL');
 const [destinationDecision,setDestinationDecision]=useState<'REVIEWED_INTERNAL'|'REJECTED_INTERNAL'>('REJECTED_INTERNAL');
 const [reason,setReason]=useState(''),[evidence,setEvidence]=useState(''),[attest,setAttest]=useState(false);
 const [error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  const [a,b]=await Promise.all([
   read<{items:Destination[]}>(await authenticatedFetch('/api/po-dispatch/review/destinations')),
   read<{items:Dispatch[]}>(await authenticatedFetch('/api/po-dispatch/review/requests'))
  ]);
  setDestinations(a.items);setRequests(b.items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(e instanceof Error?e.message:'Dispatch review data unavailable'));},[refresh]);
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{await verifyCurrentPassword(password);setPassword('');setVerified(true);
   setNotice('Recent password verified; privileged MFA policy remains enforced server-side.');}
  catch(e){setVerified(false);setError(e instanceof Error?e.message:'Password verification failed');}
  finally{setBusy(false);}
 }
 function stepUp(){
  if(!verified||!hasRecentVerification())throw Error('Verify current reviewer password first');
 }
 async function decideDestination(d:Destination){
  setBusy(true);setError('');setNotice('');
  try{
   stepUp();
   if(!window.confirm('Record INTERNAL destination review only? Supplier inbox control has NOT been externally confirmed.'))return;
   const value=await read<{status:string}>(await sensitiveFetch(
    '/api/po-dispatch/review/destinations/'+encodeURIComponent(d.id)+'/decide',{
     method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({decision:destinationDecision,reason,evidenceRef:evidence,
      identityAttested:attest})}));
   setNotice(d.email+': '+value.status+'. No supplier mail sent.');
   setReason('');setEvidence('');setAttest(false);await refresh();
  }catch(e){setError(e instanceof Error?e.message:'Destination review refused');}
  finally{setBusy(false);}
 }
 async function open(id:string){
  setBusy(true);setError('');setNotice('');
  try{
   const detail=await read<Detail>(await authenticatedFetch(
    '/api/po-dispatch/review/requests/'+encodeURIComponent(id)));
   setSelected(detail);setDecision('REJECTED_INTERNAL');setReason('');setEvidence('');setAttest(false);
  }catch(e){setError(e instanceof Error?e.message:'Cannot inspect immutable dispatch manifest');}
  finally{setBusy(false);}
 }
 async function submit(e:React.FormEvent){
  e.preventDefault();if(!selected||busy)return;
  setBusy(true);setError('');setNotice('');
  try{
   stepUp();
   if(!window.confirm('Record INTERNAL PO dispatch review? Any approval produces only a DISABLED outbox HOLD, not a supplier order.'))return;
   const value=await read<{status:string;outboxState:string|null}>(await sensitiveFetch(
    '/api/po-dispatch/review/requests/'+encodeURIComponent(selected.preparation.id)+'/decide',{
     method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({decision,reason,evidenceRef:evidence,destinationAttested:attest})}));
   setNotice(value.status+(value.outboxState?' · HELD outbox, dispatch DISABLED':' · no outbox')+
    '. Nothing issued or acknowledged.');
   setSelected(null);setReason('');setEvidence('');setAttest(false);await refresh();
  }catch(e){setError(e instanceof Error?e.message:'Internal dispatch review failed');}
  finally{setBusy(false);}
 }
 return <section className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4" aria-label="Independent supplier dispatch reviewer">
  <h2 className="text-lg font-semibold">Phase 1AE · Independent Supplier Destination / Dispatch HOLD Review</h2>
  <p className="text-xs text-amber-200">No review causes supplier delivery, official purchase-order issue,
   vendor acknowledgment, GRN, stock reservation, payment or financial journal. Internal approval
   is only authorization evidence for a permanently HELD and DISABLED outbox.</p>
  {error&&<p role="alert" className="border border-rose-700 text-rose-200 text-sm p-3 rounded">{error}</p>}
  {notice&&<p role="status" className="border border-cyan-700 text-cyan-200 text-sm p-3 rounded">{notice}</p>}
  <button type="button" onClick={()=>void refresh().catch(e=>setError(String(e)))}
   disabled={busy} className="text-cyan-300 text-xs">Refresh review queues</button>
  <form onSubmit={verify} className="border border-slate-700 rounded p-3 flex flex-wrap gap-2 items-end">
   <label className="text-xs">Reviewer password
    <input type="password" required autoComplete="current-password" value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block bg-slate-950 border border-slate-700 rounded p-2 mt-1"/></label>
   <button type="submit" disabled={busy} className="bg-amber-800 px-3 py-2 rounded text-xs">Verify</button>
   <span className="text-xs text-slate-400">{verified&&hasRecentVerification()?'Step-up active':'Step-up required'}</span>
  </form>
  <div className="grid md:grid-cols-2 gap-4">
   <section className="border border-slate-700 rounded p-3 space-y-2">
    <h3 className="text-sm font-semibold">Destination review queue</h3>
    {destinations.length===0?<p className="text-xs text-slate-400">No destination proposals.</p>:
     destinations.map(d=><p key={d.id} className="border-t border-slate-700 py-2 text-xs">
      {d.supplierCode} · {d.email} · {d.status} · Ref {d.evidenceRef}
      {d.status==='PENDING_INTERNAL'&&<button type="button" onClick={()=>{
       setSelected(null);setReason('');setEvidence('');setAttest(false);
       setActiveDestination(d);
      }} className="block text-cyan-300 mt-1">Review destination</button>}</p>)}
   </section>
   <section className="border border-slate-700 rounded p-3 space-y-2">
    <h3 className="text-sm font-semibold">Internal dispatch requests</h3>
    {requests.length===0?<p className="text-xs text-slate-400">No requests.</p>:
     requests.map(r=><button key={r.id} type="button" onClick={()=>{setActiveDestination(null);void open(r.id);}}
      className="block w-full border-t border-slate-700 py-2 text-left text-xs hover:text-cyan-300">
      {r.supplierCode} · {r.id.slice(0,12)} · {r.status}
      <span className="block">{r.email} · {r.destinationStatus}</span>
     </button>)}
   </section>
  </div>
  {activeDestination&&<div className="border border-amber-700 rounded p-4 space-y-3">
   <h3 className="text-sm font-semibold">Review destination {activeDestination.email}</h3>
   <p className="text-xs">Supplier {activeDestination.supplierCode} · evidence {activeDestination.evidenceRef}.
    Independently inspect the supplier's claimed address before any internal attestation.</p>
   <label className="block text-xs">Decision
    <select value={destinationDecision} onChange={e=>setDestinationDecision(e.target.value as typeof destinationDecision)}
     className="block bg-slate-950 border border-slate-700 rounded p-2 mt-1">
     <option value="REJECTED_INTERNAL">Reject address internally</option>
     <option value="REVIEWED_INTERNAL">Attest address internally only</option>
    </select></label>
   <button type="button" disabled={busy||!verified||!reason||!evidence||(
    destinationDecision==='REVIEWED_INTERNAL'&&!attest)}
    onClick={()=>void decideDestination(activeDestination)}
    className="bg-amber-800 rounded px-3 py-2 text-xs disabled:opacity-50">Record destination review</button>
  </div>}
  {selected&&<form onSubmit={submit} className="rounded border border-amber-700 p-4 space-y-3">
   <h3 className="font-semibold text-sm">Review immutable HELD dispatch manifest</h3>
   <p className="text-xs">Preparation: {selected.preparation.id} · {selected.preparation.status}</p>
   <p className="text-xs">To: {selected.manifest.email} · HELD PO {selected.manifest.holdId}
    · Supplier ID {selected.manifest.supplierId}</p>
   <p className="text-xs break-all">HELD PO SHA-256: {selected.manifest.holdSha256}
    · Owner authorization ref: {selected.manifest.authorizationEvidenceRef}</p>
   <p className="text-xs text-amber-200">Dispatch: {selected.manifest.dispatchState} · External issued:
    {String(selected.manifest.externalOrderIssued)}</p>
   {selected.preparation.status==='PENDING_INTERNAL'?<>
    <label className="block text-xs">Independent decision
     <select value={decision} onChange={e=>setDecision(e.target.value as typeof decision)}
      className="block bg-slate-950 border border-slate-700 rounded p-2 mt-1">
      <option value="REJECTED_INTERNAL">Reject internally</option>
      <option value="APPROVED_INTERNAL">Approve HELD outbox only</option>
     </select></label>
    <button type="submit" disabled={busy||!verified||!reason||!evidence||(decision==='APPROVED_INTERNAL'&&!attest)}
     className="bg-amber-800 px-3 py-2 rounded text-xs disabled:opacity-50">Record immutable internal decision</button>
   </>:<p className="text-xs text-amber-200">Immutable decision already recorded.</p>}
  </form>}
  {(activeDestination||selected)&&<div className="border border-slate-700 rounded p-3 space-y-3">
   <label className="block text-xs">Evidence review ticket
    <input required value={evidence} maxLength={160} onChange={e=>setEvidence(e.target.value)}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>
   <label className="block text-xs">Detailed justification (12–1000 chars)
    <textarea required value={reason} minLength={12} maxLength={1000}
     onChange={e=>setReason(e.target.value)} rows={3}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>
   <label className="flex gap-2 text-xs text-amber-200"><input type="checkbox" checked={attest}
    onChange={e=>setAttest(e.target.checked)}/>
    I independently inspected cited destination/held-PO evidence (required for internal approval).</label>
  </div>}
  <p className="text-xs text-amber-200">No supplier-send or acknowledgment endpoint exists; dispatch stays disabled.</p>
 </section>;
}
