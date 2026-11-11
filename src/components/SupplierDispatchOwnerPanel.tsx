import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,hasRecentVerification,sensitiveFetch,verifyCurrentPassword} from '../services/authClient';
type Supplier={id:string;code:string;legalName:string;status:string};
type Destination={id:string;supplierId:string;supplierCode:string;email:string;status:string};
type Hold={holdId:string;supplierCode:string;requestId:string;holdStatus:string;
 destinationId:string|null;destinationStatus:string|null;destinationEmail:string|null;
 preparationId:string|null;preparationStatus:string|null};
type Preparation={id:string;holdId:string;status:string;manifestSha256:string;
 outboxState:string|null;dispatchState:string|null};
async function read<T>(r:Response):Promise<T>{
 const v:unknown=await r.json();
 if(!r.ok)throw Error(v&&typeof v==='object'&&'error' in v?String(v.error):'Server unavailable');
 return v as T;
}
export function SupplierDispatchOwnerPanel(){
 const [suppliers,setSuppliers]=useState<Supplier[]>([]),[destinations,setDestinations]=useState<Destination[]>([]);
 const [holds,setHolds]=useState<Hold[]>([]),[requests,setRequests]=useState<Preparation[]>([]);
 const [supplierId,setSupplierId]=useState(''),[email,setEmail]=useState('');
 const [evidenceRef,setEvidenceRef]=useState(''),[holdId,setHoldId]=useState('');
 const [authorizationRef,setAuthorizationRef]=useState(''),[password,setPassword]=useState('');
 const [verified,setVerified]=useState(false),[busy,setBusy]=useState(false);
 const [error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  try{
   const [s,d,h,p]=await Promise.all([
    read<{items:Supplier[]}>(await authenticatedFetch('/api/procurement/suppliers')),
    read<{items:Destination[]}>(await authenticatedFetch('/api/po-dispatch/destinations')),
    read<{items:Hold[]}>(await authenticatedFetch('/api/po-dispatch/holds')),
    read<{items:Preparation[]}>(await authenticatedFetch('/api/po-dispatch/requests'))
   ]);
   setSuppliers(s.items);setDestinations(d.items);setHolds(h.items);setRequests(p.items);
  }catch(e){setError(e instanceof Error?e.message:'Could not fetch MySQL dispatch holds');
   setSuppliers([]);setHolds([]);setDestinations([]);setRequests([]);}
 },[]);
 useEffect(()=>{void refresh();},[refresh]);
 function requireVerified(){
  if(!verified||!hasRecentVerification())throw Error('Recent current-password verification required');
 }
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{await verifyCurrentPassword(password);setVerified(true);setPassword('');
   setNotice('Password verified for up to five minutes. Server-side privileged MFA policy still applies.');}
  catch(e){setVerified(false);setError(e instanceof Error?e.message:'Password verification failed');}
  finally{setBusy(false);}
 }
 async function propose(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{
   requireVerified();
   if(!window.confirm('Record an INTERNAL supplier email proposal only? This does not verify inbox ownership or send anything.'))return;
   const result=await read<{id:string}>(await sensitiveFetch('/api/po-dispatch/destinations',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({supplierId,email,evidenceRef})
   }));
   setNotice('Destination '+result.id+' recorded as pending review; no dispatch.');
   setEmail('');setEvidenceRef('');await refresh();
  }catch(e){setError(e instanceof Error?e.message:'Destination proposal refused');}
  finally{setBusy(false);}
 }
 async function prepare(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{
   requireVerified();
   const hold=holds.find(h=>h.holdId===holdId);
   if(!hold?.destinationId||hold.destinationStatus!=='REVIEWED_INTERNAL')
    throw Error('A reviewed destination matching the held supplier is required');
   if(!window.confirm('Prepare an INTERNAL supplier PO dispatch review request only? No order, email, delivery or goods receipt will occur.'))return;
   const v=await read<{id:string;status:string;manifestSha256:string}>(await sensitiveFetch('/api/po-dispatch/requests',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({holdId,destinationId:hold.destinationId,
     authorizationEvidenceRef:authorizationRef})
   }));
   setNotice('Request '+v.id+' '+v.status+'; SHA-256 '+v.manifestSha256+'. Sending permanently DISABLED.');
   setHoldId('');setAuthorizationRef('');await refresh();
  }catch(e){setError(e instanceof Error?e.message:'Held PO dispatch request refused');}
  finally{setBusy(false);}
 }
 return <section className="rounded-xl border border-slate-700 bg-slate-900 p-5 space-y-4" aria-label="Internal supplier PO dispatch holds">
  <h2 className="font-semibold text-xl">Phase 1AE · Supplier Destination & PO Dispatch HOLD</h2>
  <p className="text-sm text-amber-200">Internal supplier destination review and outbox HOLD only.
   Not a supplier-issued PO, delivery confirmation, shipment, GRN, stock movement, available inventory or payment.
   External delivery integrations and dispatch are DISABLED.</p>
  {error&&<p role="alert" className="text-sm text-rose-200 border border-rose-700 rounded p-3">{error}</p>}
  {notice&&<p role="status" className="text-sm text-cyan-200 border border-cyan-700 rounded p-3">{notice}</p>}
  <button type="button" onClick={()=>void refresh()} disabled={busy}
   className="text-cyan-300 text-sm disabled:opacity-50">Refresh live MySQL dispatch holds</button>
  <form onSubmit={verify} className="border border-slate-700 rounded p-3 flex flex-wrap gap-2 items-end">
   <label className="text-xs">Verify current password
    <input required type="password" autoComplete="current-password" value={password} onChange={e=>setPassword(e.target.value)}
     className="block bg-slate-950 border border-slate-700 rounded p-2 mt-1"/></label>
   <button disabled={busy} type="submit" className="bg-cyan-700 rounded px-3 py-2 text-xs">Verify</button>
   <span className="text-xs text-slate-400">{verified&&hasRecentVerification()?'Step-up current':'Step-up required for writes'}</span>
  </form>
  <form onSubmit={propose} className="border border-slate-700 rounded p-3 space-y-2">
   <h3 className="text-sm font-semibold">Propose ONE immutable supplier destination</h3>
   <div className="grid md:grid-cols-3 gap-3">
    <label className="text-xs">Your internally reviewed supplier
     <select required value={supplierId} onChange={e=>setSupplierId(e.target.value)}
      className="block w-full mt-1 bg-slate-950 border border-slate-700 rounded p-2">
      <option value="">Select supplier</option>
      {suppliers.filter(s=>s.status==='REVIEWED_INTERNAL'&&!destinations.some(d=>d.supplierId===s.id))
       .map(s=><option key={s.id} value={s.id}>{s.code} · {s.legalName}</option>)}
     </select></label>
    <label className="text-xs">Lowercase supplier email (NOT verified)
     <input required type="email" value={email} onChange={e=>setEmail(e.target.value)}
      maxLength={254} className="block w-full mt-1 bg-slate-950 border border-slate-700 rounded p-2"/></label>
    <label className="text-xs">Provenance ticket reference
     <input required maxLength={160} value={evidenceRef} onChange={e=>setEvidenceRef(e.target.value)}
      className="block w-full mt-1 bg-slate-950 border border-slate-700 rounded p-2"/></label>
   </div>
   <button disabled={busy||!verified||!supplierId} type="submit"
    className="rounded bg-amber-800 px-3 py-2 text-xs disabled:opacity-50">Propose internally, no email</button>
  </form>
  <div className="border border-slate-700 p-3 rounded">
   <h3 className="text-sm font-semibold mb-2">Supplier destinations</h3>
   {destinations.length===0?<p className="text-xs text-slate-400">No destination evidence yet.</p>:
    destinations.map(d=><p key={d.id} className="text-xs py-2 border-t border-slate-700">
     {d.supplierCode} · {d.email} · {d.status} · external verification NOT established</p>)}
  </div>
  <form onSubmit={prepare} className="border border-slate-700 rounded p-3 space-y-2">
   <h3 className="text-sm font-semibold">Prepare supplier dispatch approval request (NOT an issued PO)</h3>
   <div className="grid md:grid-cols-2 gap-3">
    <label className="text-xs">Eligible HELD internal PO + reviewed destination
     <select required value={holdId} onChange={e=>setHoldId(e.target.value)}
      className="block w-full mt-1 bg-slate-950 border border-slate-700 rounded p-2">
      <option value="">Select a held PO</option>
      {holds.filter(h=>h.destinationStatus==='REVIEWED_INTERNAL'&&!h.preparationId)
       .map(h=><option key={h.holdId} value={h.holdId}>
        {h.supplierCode} · {h.holdId.slice(0,12)} · {h.destinationEmail}</option>)}
     </select></label>
    <label className="text-xs">Owner authorization evidence ticket
     <input required maxLength={160} value={authorizationRef}
      onChange={e=>setAuthorizationRef(e.target.value)}
      className="block w-full mt-1 bg-slate-950 border border-slate-700 rounded p-2"/></label>
   </div>
   <button disabled={busy||!verified||!holdId} type="submit"
    className="rounded bg-amber-800 px-3 py-2 text-xs disabled:opacity-50">
    Submit independent dispatch REVIEW (no send)</button>
  </form>
  <div className="rounded border border-slate-700 p-3 space-y-2">
   <h3 className="text-sm font-semibold">Server-backed immutable preparations</h3>
   {requests.length===0?<p className="text-xs text-slate-400">No dispatch requests saved.</p>:
    requests.map(r=><p key={r.id} className="border-t border-slate-700 py-2 text-xs break-words">
     {r.id.slice(0,12)} · {r.status} · {r.outboxState?'OUTBOX HELD / DISABLED':'No outbox'} ·
     SHA-256 {r.manifestSha256}</p>)}
  </div>
  <p className="text-xs text-amber-200">No send action exists. Supplier acknowledgments and independently verified
   delivery proofs require a future trusted external workflow. Existing 1AD quarantine evidence is not a GRN.</p>
 </section>;
}
