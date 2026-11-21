import React,{useCallback,useEffect,useRef,useState} from 'react';
import {authenticatedFetch,hasRecentVerification,sensitiveFetch,verifyCurrentPassword} from '../services/authClient';

type Candidate={holdId:string;requestId:string;siteCode:string;supplierCode:string;
 observationId:string|null;observationStatus:string|null};
type Line={productId:string;sku:string;name:string;quantity:number;
 trackingMode:'LOT'|'SERIAL';lotCode:string;serialText:string};
type Observed={id:string;status:string;holdId:string;deliveryEvidenceRef:string};
type Summary={items:{productId:string;sku:string;siteCode:string;attestedQuantity:string}[];
 internalLedgerConsistent:boolean;internalDiscrepancies:number;availableToSell:null};
async function read<T>(response:Response):Promise<T>{
 const body:unknown=await response.json();
 if(!response.ok)throw Error(body&&typeof body==='object'&&'error' in body?String(body.error):'Inbound service unavailable');
 return body as T;
}
export function InboundObservationWorkspace(){
 const [holds,setHolds]=useState<Candidate[]>([]);
 const [observations,setObservations]=useState<Observed[]>([]);
 const [summary,setSummary]=useState<Summary|null>(null);
 const [selected,setSelected]=useState<Candidate|null>(null);
 const [lines,setLines]=useState<Line[]>([]);
 const [deliveryEvidenceRef,setDeliveryEvidenceRef]=useState('');
 const [physicalCountRef,setPhysicalCountRef]=useState('');
 const [password,setPassword]=useState(''),[verified,setVerified]=useState(false);
 const [busy,setBusy]=useState(false),[loading,setLoading]=useState(false);
 const [error,setError]=useState(''),[notice,setNotice]=useState('');
 const pending=useRef<{body:string;key:string}|null>(null);
 const refresh=useCallback(async()=>{
  setLoading(true);setError('');
  try{
   const [h,o,s]=await Promise.all([
    read<{items:Candidate[]}>(await authenticatedFetch('/api/intake/eligible')),
    read<{items:Observed[]}>(await authenticatedFetch('/api/intake/observations')),
    read<Summary>(await authenticatedFetch('/api/intake/quarantine-summary'))
   ]);
   setHolds(h.items);setObservations(o.items);setSummary(s);
  }catch(e){setHolds([]);setObservations([]);setSummary(null);
   setError(e instanceof Error?e.message:'MySQL intake unavailable');
  }finally{setLoading(false);}
 },[]);
 useEffect(()=>{void refresh();},[refresh]);
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setVerified(true);setPassword('');
   setNotice('Recent password verification available for five minutes; production MFA still required.');}
  catch(e){setVerified(false);setError(e instanceof Error?e.message:'Verification failed');}
  finally{setBusy(false);}
 }
 async function choose(candidate:Candidate){
  setBusy(true);setError('');setSelected(null);setLines([]);pending.current=null;
  try{
   if(candidate.observationId)throw Error('This held PO already has an inbound observation');
   const result=await read<{items:{productId:string;sku:string;name:string;quantity:number}[]}>(
    await authenticatedFetch('/api/procurement/requests/'+encodeURIComponent(candidate.requestId)));
   if(!result.items.length)throw Error('Held purchase has no line snapshots');
   setLines(result.items.map(x=>({
    productId:x.productId,sku:x.sku,name:x.name,quantity:Number(x.quantity),
    trackingMode:'LOT',lotCode:'',serialText:''})));
   setDeliveryEvidenceRef('');setPhysicalCountRef('');
   setSelected(candidate);
  }catch(e){setError(e instanceof Error?e.message:'Unable to load internal PO detail');}
  finally{setBusy(false);}
 }
 function updateLine(productId:string,fields:Partial<Line>){
  setLines(all=>all.map(l=>l.productId===productId?{...l,...fields}:l));
  pending.current=null;
 }
 async function submit(e:React.FormEvent){
  e.preventDefault();if(!selected||busy)return;
  setBusy(true);setError('');setNotice('');
  try{
   if(!verified||!hasRecentVerification())throw Error('Verify current password first');
   const items=lines.map(l=>({
    productId:l.productId,quantity:l.quantity,trackingMode:l.trackingMode,
    lotCode:l.trackingMode==='LOT'?l.lotCode.trim():null,
    serialNumbers:l.trackingMode==='SERIAL'?l.serialText.split(/[\n,]+/).map(x=>x.trim()).filter(Boolean):[]
   }));
   if(!window.confirm('Record UNVERIFIED inbound observation for independent witness? HELD PO was not supplier-issued; no official goods receipt or available stock will be created.'))return;
   const body=JSON.stringify({holdId:selected.holdId,deliveryEvidenceRef:deliveryEvidenceRef.trim(),
    physicalCountRef:physicalCountRef.trim(),items});
   if(!pending.current||pending.current.body!==body)
    pending.current={body,key:crypto.randomUUID()};
   const result=await read<{id:string;status:string}>(await sensitiveFetch('/api/intake/observations',{
    method:'POST',headers:{'Content-Type':'application/json','Idempotency-Key':pending.current.key},
    body
   }));
   setNotice('Observation '+result.id+' '+result.status+'. Await independent witness; zero available stock.');
   pending.current=null;setSelected(null);setLines([]);await refresh();
  }catch(e){setError((e instanceof Error?e.message:'Observation save failed')+
    '. Retry unchanged form with same idempotency key if the network response was uncertain.');}
  finally{setBusy(false);}
 }
 return <section aria-label="Internal quarantine intake observations" className="p-5 bg-slate-900 border border-slate-700 rounded-xl space-y-4">
  <h2 className="text-xl font-semibold">Phase 1AD · Inbound Observation / Quarantine Evidence</h2>
  <p className="text-xs text-amber-200">HELD purchase preparation is NOT an issued supplier PO.
   Record evidence and full-quantity physical observations for review only. This is not a recognized
   delivery, stock receipt, reservation, available-to-sell quantity, supplier invoice or financial booking.
   Partial receipts and corrections remain disabled.</p>
  {error&&<p role="alert" className="rounded border border-rose-700 p-3 text-sm text-rose-200">{error}</p>}
  {notice&&<p role="status" className="rounded border border-cyan-700 p-3 text-sm text-cyan-200">{notice}</p>}
  <button type="button" onClick={()=>void refresh()} disabled={busy||loading}
   className="text-cyan-300 text-sm disabled:opacity-40">Refresh evidence and quarantine summary</button>
  <form onSubmit={verify} className="flex flex-wrap items-end gap-3 border border-slate-700 p-3 rounded">
   <label className="text-xs">Current password
    <input type="password" autoComplete="current-password" required value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block bg-slate-950 border border-slate-600 rounded p-2 mt-1"/></label>
   <button type="submit" disabled={busy} className="bg-cyan-700 rounded px-3 py-2 text-xs disabled:opacity-40">Verify for witness submissions</button>
   <span className="text-xs text-slate-400">{verified&&hasRecentVerification()?'Verification active':'Step-up required'}</span>
  </form>
  <div className="border border-slate-700 p-3 rounded space-y-2">
   <h3 className="text-sm font-semibold">Own held PO snapshots · {holds.length}</h3>
   {holds.length===0?<p className="text-xs text-slate-400">No HELD internal purchase preparation found.</p>:
    holds.map(h=><div key={h.holdId} className="border-t border-slate-700 py-2 flex flex-wrap justify-between items-center gap-2 text-xs">
     <span>{h.holdId.slice(0,12)} · {h.supplierCode} · {h.siteCode} · {h.observationStatus??'NO OBSERVATION'}</span>
     {!h.observationId&&<button disabled={busy} type="button" onClick={()=>void choose(h)}
      className="border border-amber-600 rounded px-3 py-2 text-amber-200 disabled:opacity-40">Record inbound observation</button>}
    </div>)}
  </div>
  {selected&&<form onSubmit={submit} className="border border-amber-800 rounded p-4 space-y-3">
   <h3 className="font-semibold">Observe complete held snapshot · {selected.holdId.slice(0,18)}</h3>
   <p className="text-xs text-amber-200">Each SKU quantity must equal the complete held PO line exactly.
    Use SERIAL for individual identifiers or LOT for a batch identifier. No partial receipt.</p>
   <div className="grid sm:grid-cols-2 gap-3">
    <label className="text-xs">Delivery document ticket (not external verification)
     <input required maxLength={160} value={deliveryEvidenceRef} onChange={e=>{setDeliveryEvidenceRef(e.target.value);pending.current=null;}}
      className="block w-full mt-1 bg-slate-950 border border-slate-700 rounded p-2"/></label>
    <label className="text-xs">Physical count evidence reference
     <input required maxLength={160} value={physicalCountRef} onChange={e=>{setPhysicalCountRef(e.target.value);pending.current=null;}}
      className="block w-full mt-1 bg-slate-950 border border-slate-700 rounded p-2"/></label>
   </div>
   {lines.map(l=><div key={l.productId} className="border-t border-slate-700 pt-3 space-y-2">
    <p className="text-sm">{l.sku} · {l.name} · <strong>Exact observed qty {l.quantity}</strong></p>
    <label className="text-xs block">Tracking
     <select value={l.trackingMode} onChange={e=>updateLine(l.productId,{
      trackingMode:e.target.value as Line['trackingMode'],lotCode:'',serialText:''})}
      className="block mt-1 bg-slate-950 border border-slate-700 rounded p-2">
      <option value="LOT">LOT (batch code)</option><option value="SERIAL">SERIAL (one per unit)</option>
     </select></label>
    {l.trackingMode==='LOT'?<label className="text-xs block">Uppercase lot code
     <input required value={l.lotCode} maxLength={80} onChange={e=>updateLine(l.productId,{lotCode:e.target.value})}
      className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>:
     <label className="text-xs block">One uppercase serial per unit; separate with newline or comma
      <textarea required value={l.serialText} rows={3} onChange={e=>updateLine(l.productId,{serialText:e.target.value})}
       className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>}
   </div>)}
   <div className="flex flex-wrap gap-2">
    <button type="submit" disabled={busy||!verified} className="rounded bg-amber-800 px-4 py-2 text-sm disabled:opacity-40">
     Record UNVERIFIED observation</button>
    <button type="button" onClick={()=>{setSelected(null);pending.current=null;}} className="rounded border border-slate-600 px-3 py-2 text-sm">Cancel</button>
   </div>
  </form>}
  <div className="border border-slate-700 rounded p-3 space-y-2">
   <h3 className="text-sm font-semibold">Saved internal observations · {observations.length}</h3>
   {observations.length===0?<p className="text-xs text-slate-400">No observations yet.</p>:
    observations.map(o=><p key={o.id} className="text-xs border-t border-slate-700 py-2">
     {o.id.slice(0,12)} · {o.status} · Evidence {o.deliveryEvidenceRef}</p>)}
  </div>
  <div className="border border-amber-700 rounded p-3 space-y-2">
   <h3 className="text-sm font-semibold">Quarantine custody evidence (NOT inventory availability)</h3>
   {summary?<p className="text-xs">Internal database reconciliation: {summary.internalLedgerConsistent?'No detected ledger inconsistencies':'REQUIRES INVESTIGATION'}
    · Discrepancies {summary.internalDiscrepancies}</p>:<p className="text-xs">No authoritative summary available.</p>}
   {summary?.items.map(x=><p key={x.siteCode+x.productId} className="text-xs border-t border-slate-700 py-2">
    {x.siteCode} · {x.sku} · internally witnessed quarantined units {x.attestedQuantity}</p>)}
   <p className="text-xs text-amber-200">Available-to-sell: NOT CALCULATED. Reservations and financial value: NOT IMPLEMENTED.
    Internal ledger consistency does not verify warehouse reality or supplier delivery.</p>
  </div>
 </section>;
}
