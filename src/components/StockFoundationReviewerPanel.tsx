import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Item={id:string;heldGrnId:string;observationId:string;preparedBy:string;intentSha256:string;status:string};
type Detail={intent:{id:string;status:string;sha256:string};
 source:{heldGrnId:string;observationId:string;siteId:string;holdId:string;
 lines:{productId:string;quantity:number;trackingMode:string;lotCode:string|null;
 serialNumbers:string[]}[]};postingState:string};
async function response<T>(r:Response):Promise<T>{
 const x:unknown=await r.json();
 if(!r.ok)throw Error(x&&typeof x==='object'&&'error' in x?String(x.error):'Review unavailable');
 return x as T;
}
export function StockFoundationReviewerPanel(){
 const [items,setItems]=useState<Item[]>([]),[selected,setSelected]=useState<Detail|null>(null);
 const [password,setPassword]=useState(''),[verified,setVerified]=useState(false);
 const [decision,setDecision]=useState<'REVIEWED_HELD'|'REJECTED_INTERNAL'>('REJECTED_INTERNAL');
 const [reason,setReason]=useState(''),[evidence,setEvidence]=useState(''),
 [inspected,setInspected]=useState(false),[busy,setBusy]=useState(false),
 [error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  setItems((await response<{items:Item[]}>(await authenticatedFetch(
   '/api/stock-foundation/review/release-intents'))).items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setPassword('');setVerified(true);
   setNotice('Independent reviewer step-up verified. MFA policy server-enforced.');}
  catch(e){setVerified(false);setError(String(e));}finally{setBusy(false);}
 }
 async function open(item:Item){
  setBusy(true);setError('');
  try{setSelected(await response<Detail>(await authenticatedFetch(
   '/api/stock-foundation/review/release-intents/'+encodeURIComponent(item.id))));
   setReason('');setEvidence('');setInspected(false);setDecision('REJECTED_INTERNAL');
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function decide(e:React.FormEvent){
  e.preventDefault();if(!selected)return;
  setBusy(true);setError('');setNotice('');
  try{
   if(!verified||!hasRecentVerification())throw Error('Reverify reviewer password');
   if(!window.confirm('Record INTERNAL stock release review? Any approval remains HELD and stock posting DISABLED.'))return;
   const v=await response<{status:string;postingState:string}>(await sensitiveFetch(
    '/api/stock-foundation/review/release-intents/'+encodeURIComponent(selected.intent.id)+'/decide',{
     method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({decision,reason,evidenceRef:evidence,sourceInspected:inspected})
    }));
   setNotice(v.status+' · '+v.postingState+'. No stock was posted, reserved, or made available.');
   setSelected(null);await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 return <section aria-label="Independent stock release foundation reviewer"
  className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="font-semibold text-lg">Phase 1AG · Independent stock-release intention review</h2>
  <p className="text-xs text-amber-200">Review of INTERNAL quarantined custody and GRN-reconciliation evidence only.
   Approval never authenticates an external GRN, creates sellable stock, posts a movement or reserves units.
   All stock gates remain exactly zero.</p>
  {error&&<p role="alert" className="border border-rose-700 text-rose-200 p-3 rounded">{error}</p>}
  {notice&&<p role="status" className="border border-cyan-700 text-cyan-200 p-3 rounded">{notice}</p>}
  <button type="button" className="text-xs text-cyan-300" disabled={busy}
   onClick={()=>void refresh().catch(e=>setError(String(e)))}>Refresh internal release reviews</button>
  <form onSubmit={verify} className="flex flex-wrap items-end gap-3 rounded border border-slate-700 p-3">
   <label className="text-xs">Reviewer current password
    <input type="password" autoComplete="current-password" required value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block mt-1 p-2 rounded bg-slate-950 border border-slate-700"/></label>
   <button type="submit" disabled={busy} className="rounded bg-amber-800 px-3 py-2 text-xs">Verify</button>
  </form>
  {items.length===0?<p className="text-xs text-slate-400">No internal release intentions.</p>:
   items.map(x=><button type="button" key={x.id} onClick={()=>void open(x)}
    className="block w-full text-left border-t border-slate-700 py-2 text-xs text-cyan-300">
    {x.id.slice(0,14)} · {x.status} · witness source {x.observationId.slice(0,12)}</button>)}
  {selected&&<div className="rounded border border-slate-700 p-3 space-y-2">
   <h3 className="font-semibold text-sm">Reconcile frozen source and serial identity</h3>
   <p className="text-xs break-all">Release SHA-256 {selected.intent.sha256} · Held GRN evidence {selected.source.heldGrnId}</p>
   <p className="text-xs">Site {selected.source.siteId} · Quarantine observation {selected.source.observationId}</p>
   {selected.source.lines.map(line=><p key={line.productId} className="text-xs border-t border-slate-700 py-2">
    SKU UUID {line.productId} · quantity {line.quantity} · tracking {line.trackingMode}
    · lot {line.lotCode??'—'} · serials {line.serialNumbers.join(', ')||'—'}</p>)}
   <p className="text-amber-200 text-xs">Official GRN unavailable; review state must remain HELD / DISABLED.</p>
  </div>}
  {selected?.intent.status==='PENDING_INTERNAL'&&<form onSubmit={decide}
   className="rounded border border-amber-800 p-3 space-y-3">
   <label className="block text-xs">Independent INTERNAL review outcome
    <select value={decision} onChange={e=>setDecision(e.target.value as typeof decision)}
     className="block mt-1 p-2 w-full rounded bg-slate-950 border border-slate-700">
     <option value="REJECTED_INTERNAL">Reject internal release intention</option>
     <option value="REVIEWED_HELD">Accept HELD evidence, NO stock release</option>
    </select></label>
   <label className="block text-xs">Independent physical/source evidence ticket
    <input required value={evidence} maxLength={160} onChange={e=>setEvidence(e.target.value)}
     className="block mt-1 p-2 w-full rounded bg-slate-950 border border-slate-700"/></label>
   <label className="block text-xs">Written independent review reason (12–1000)
    <textarea required value={reason} minLength={12} maxLength={1000} rows={3}
     onChange={e=>setReason(e.target.value)}
     className="block mt-1 p-2 w-full rounded bg-slate-950 border border-slate-700"/></label>
   <label className="flex gap-2 text-xs text-amber-200">
    <input type="checkbox" checked={inspected} onChange={e=>setInspected(e.target.checked)}/>
    I independently inspected the cited internal SKU, custody and serial/lot evidence.</label>
   <button type="submit" disabled={busy||!verified||(decision==='REVIEWED_HELD'&&!inspected)}
    className="rounded bg-amber-800 px-4 py-2 text-xs disabled:opacity-50">
    Record immutable internal HOLD decision</button>
  </form>}
 </section>;
}
