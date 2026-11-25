import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Held={heldGrnId:string;observationId:string;postingState:string;releaseIntentId:string|null};
type Release={id:string;heldGrnId:string;status:string;intentSha256:string;postingState:string|null};
type Plan={id:string;releaseIntentId:string;productId:string;requestedQuantity:number;
 reservationState:string};
type Position={siteId:string;productId:string;available:number;reserved:number;posted:number};
async function response<T>(r:Response):Promise<T>{
 const x:unknown=await r.json();
 if(!r.ok)throw Error(x&&typeof x==='object'&&'error' in x?String(x.error):'Server unavailable');
 return x as T;
}
export function StockFoundationOwnerPanel(){
 const [eligible,setEligible]=useState<Held[]>([]),[releases,setReleases]=useState<Release[]>([]);
 const [plans,setPlans]=useState<Plan[]>([]),[positions,setPositions]=useState<Position[]>([]);
 const [heldId,setHeldId]=useState(''),[releaseId,setReleaseId]=useState('');
 const [productId,setProductId]=useState(''),[quantity,setQuantity]=useState(1);
 const [planningRef,setPlanningRef]=useState(''),[password,setPassword]=useState('');
 const [verified,setVerified]=useState(false),[busy,setBusy]=useState(false),
 [error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  const [a,b,c,d]=await Promise.all([
   response<{items:Held[]}>(await authenticatedFetch('/api/stock-foundation/held-grn')),
   response<{items:Release[]}>(await authenticatedFetch('/api/stock-foundation/release-intents')),
   response<{items:Plan[]}>(await authenticatedFetch('/api/stock-foundation/reservation-plans')),
   response<{items:Position[]}>(await authenticatedFetch('/api/stock-foundation/positions'))
  ]);
  setEligible(a.items);setReleases(b.items);setPlans(c.items);setPositions(d.items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 function stepUp(){
  if(!verified||!hasRecentVerification())throw Error('Recent password verification required');
 }
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setVerified(true);setPassword('');
   setNotice('Password verified for recent sensitive writes; MFA policy remains server-enforced.');}
  catch(e){setVerified(false);setError(String(e));}finally{setBusy(false);}
 }
 async function createRelease(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{
   stepUp();
   if(!window.confirm('Create INTERNAL release-review intent from HELD GRN evidence only? NO stock posting, saleable quantity or movement will occur.'))return;
   const v=await response<{id:string;status:string}>(await sensitiveFetch(
    '/api/stock-foundation/release-intents',{
     method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({heldGrnId:heldId})}));
   setNotice('Internal release intent '+v.id+' is '+v.status+'; posting DISABLED.');
   setHeldId('');await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function createPlan(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{
   stepUp();
   if(!window.confirm('Record a HELD, NON-ALLOCATING demand plan only? There are ZERO available stock units.'))return;
   const v=await response<{id:string;reservationState:string}>(await sensitiveFetch(
    '/api/stock-foundation/reservation-plans',{
     method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({releaseIntentId:releaseId,productId,quantity,planningRef})}));
   setNotice('Demand plan '+v.id+' saved; reservations '+v.reservationState+' and allocated quantity ZERO.');
   setReleaseId('');setProductId('');setPlanningRef('');setQuantity(1);await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 return <section aria-label="Internal inventory release foundation" className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="font-semibold text-xl">Phase 1AG · Stock ledger / no-negative gate (FOUNDATION ONLY)</h2>
  <p className="text-sm text-amber-200">No official supplier GRN or operational stock receipt exists.
   All site/SKU available, posted, picked and reserved positions are SQL-constrained to ZERO.
   Release approval and reservation planning never post or allocate a unit.</p>
  {error&&<p role="alert" className="border border-rose-700 rounded p-3 text-sm text-rose-200">{error}</p>}
  {notice&&<p role="status" className="border border-cyan-700 rounded p-3 text-sm text-cyan-200">{notice}</p>}
  <button type="button" disabled={busy} onClick={()=>void refresh().catch(e=>setError(String(e)))}
   className="text-cyan-300 text-xs">Refresh verified MySQL evidence and zero positions</button>
  <form onSubmit={verify} className="rounded border border-slate-700 p-3 flex flex-wrap items-end gap-2">
   <label className="text-xs">Current owner password
    <input type="password" autoComplete="current-password" required value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block bg-slate-950 border border-slate-700 p-2 rounded mt-1"/></label>
   <button type="submit" disabled={busy} className="rounded px-3 py-2 bg-amber-800 text-xs">Verify</button>
   <span className="text-xs text-slate-400">{verified&&hasRecentVerification()?'Recent step-up':'Step-up required'}</span>
  </form>
  <form onSubmit={createRelease} className="rounded border border-slate-700 p-3 space-y-2">
   <h3 className="font-semibold text-sm">Prepare independent stock-release evidence review (NOT release)</h3>
   <select required aria-label="Held non-official GRN evidence" value={heldId}
    onChange={e=>setHeldId(e.target.value)}
    className="block bg-slate-950 w-full border border-slate-700 rounded p-2 text-xs">
    <option value="">Select own 1AF HELD reconciliation</option>
    {eligible.filter(x=>!x.releaseIntentId).map(x=><option key={x.heldGrnId} value={x.heldGrnId}>
     {x.heldGrnId.slice(0,16)} · {x.postingState} · observation {x.observationId.slice(0,8)}</option>)}
   </select>
   <button type="submit" disabled={busy||!verified||!heldId}
    className="rounded bg-amber-800 px-3 py-2 text-xs disabled:opacity-50">
    Submit release intention for independent review (no posting)</button>
  </form>
  <div className="rounded border border-slate-700 p-3 space-y-2">
   <h3 className="font-semibold text-sm">Internal release intentions</h3>
   {releases.length===0?<p className="text-xs text-slate-400">No release intentions yet.</p>:
    releases.map(r=><p key={r.id} className="border-t border-slate-700 pt-2 text-xs break-words">
     {r.id.slice(0,12)} · {r.status} · {r.postingState??'Not reviewed'} · SHA {r.intentSha256}</p>)}
  </div>
  <form onSubmit={createPlan} className="rounded border border-slate-700 p-3 space-y-3">
   <h3 className="font-semibold text-sm">Non-allocating reservation planning</h3>
   <p className="text-xs text-amber-200">Planning demand against an internal HELD source does NOT reserve, pick,
    consume or promise inventory. Quantity is checked against observed evidence, not an available balance.</p>
   <label className="block text-xs">Internally reviewed HELD release
    <select required value={releaseId} onChange={e=>setReleaseId(e.target.value)}
     className="block bg-slate-950 w-full border border-slate-700 rounded p-2 mt-1">
     <option value="">Select HELD release</option>
     {releases.filter(x=>x.status==='REVIEWED_HELD').map(x=><option key={x.id} value={x.id}>
      {x.id.slice(0,14)} · posting DISABLED</option>)}
    </select></label>
   <label className="block text-xs">Exact product UUID from observed GRN evidence
    <input required value={productId} onChange={e=>setProductId(e.target.value)}
     className="block bg-slate-950 w-full border border-slate-700 rounded p-2 mt-1"/></label>
   <div className="grid md:grid-cols-2 gap-3">
    <label className="block text-xs">Hypothetical units (1–1000)
     <input type="number" required min={1} max={1000} step={1} value={quantity}
      onChange={e=>setQuantity(Number(e.target.value))}
      className="block bg-slate-950 w-full border border-slate-700 rounded p-2 mt-1"/></label>
    <label className="block text-xs">Demand planning evidence reference
     <input required value={planningRef} onChange={e=>setPlanningRef(e.target.value)}
      className="block bg-slate-950 w-full border border-slate-700 rounded p-2 mt-1"/></label>
   </div>
   <button type="submit" disabled={busy||!verified||!releaseId||!productId}
    className="rounded bg-amber-800 px-3 py-2 text-xs disabled:opacity-50">
    Record HELD plan (no reservation)</button>
  </form>
  <div className="rounded border border-slate-700 p-3">
   <h3 className="font-semibold text-sm">Authoritative site / SKU gates — all ZERO</h3>
   {positions.length===0?<p className="text-xs text-slate-400">No registered stock-position gates yet.</p>:
    positions.map(p=><p key={p.siteId+p.productId} className="border-t border-slate-700 py-2 text-xs">
     {p.siteId.slice(0,8)} / {p.productId.slice(0,8)} · available {p.available} ·
     reserved {p.reserved} · posted {p.posted}</p>)}
   <p className="text-xs text-amber-200">Recorded plans: {plans.length} (all DISABLED). Available-to-sell is undefined,
    not equal to quarantine, not inferred from 1AB opening counts or 1AF held reconciliation.</p>
  </div>
 </section>;
}
