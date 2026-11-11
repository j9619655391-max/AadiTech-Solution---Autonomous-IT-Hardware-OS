import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Item={id:string;releaseIntentId:string;status:string;manifestSha256:string;preparedBy:string};
type Leg={productId:string;accountCode:string;side:string;quantity:number;
 trackingMode:string;lotCode:string|null;serialNumbers:string[]};
type Detail={journal:{id:string;status:string;manifestSha256:string};
 manifest:{siteId:string;legs:Leg[];postingState:string;officialGrnVerified:boolean};
 totals:{skuCount:number;legCount:number;evidenceUnits:number;postedUnits:number}};
async function json<T>(r:Response):Promise<T>{
 const v:unknown=await r.json();
 if(!r.ok)throw Error(v&&typeof v==='object'&&'error' in v?String(v.error):'Independent review unavailable');
 return v as T;
}
export function JournalFoundationReviewerPanel(){
 const [items,setItems]=useState<Item[]>([]),[selected,setSelected]=useState<Detail|null>(null),
 [password,setPassword]=useState(''),[verified,setVerified]=useState(false),
 [reason,setReason]=useState(''),[evidence,setEvidence]=useState(''),
 [inspected,setInspected]=useState(false),[decision,setDecision]=
 useState<'REVIEWED_HELD'|'REJECTED_INTERNAL'>('REJECTED_INTERNAL'),
 [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  setItems((await json<{items:Item[]}>(await authenticatedFetch(
   '/api/journal-foundation/review/journals'))).items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setVerified(true);setPassword('');
   setNotice('Independent reviewer step-up active; MFA remains server-enforced.');}
  catch(e){setVerified(false);setError(String(e));}finally{setBusy(false);}
 }
 async function open(id:string){
  setBusy(true);setError('');setSelected(null);
  try{
   setSelected(await json<Detail>(await authenticatedFetch(
    '/api/journal-foundation/review/journals/'+encodeURIComponent(id))));
   setDecision('REJECTED_INTERNAL');setReason('');setEvidence('');setInspected(false);
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function decide(e:React.FormEvent){
  e.preventDefault();if(!selected)return;
  setBusy(true);setError('');setNotice('');
  try{
   if(!verified||!hasRecentVerification())throw Error('Recent password re-verification required');
   if(!window.confirm('Record an INTERNAL review of UNPOSTED balanced evidence only? Stock, serial title and actual movements remain disabled.'))return;
   const v=await json<{status:string;postingState:string;stockPosted:number}>(
    await sensitiveFetch('/api/journal-foundation/review/journals/'+
     encodeURIComponent(selected.journal.id)+'/decide',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({decision,reason,evidenceRef:evidence,balancingInspected:inspected})
     }));
   setNotice('Internal '+v.status+' · '+v.postingState+' · physical stock posted: '+v.stockPosted);
   setSelected(null);await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 return <section aria-label="Independent unposted inventory journal reviewer"
  className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="text-lg font-semibold">Phase 1AH · Independent balanced evidence journal review</h2>
  <p className="text-xs text-amber-200">Only internally attested quarantine/release intentions are inspectable.
   Balanced evidence is NOT an official goods receipt, accounting posting, serial title, stock credit,
   warehouse movement or sellable inventory.</p>
  {error&&<p role="alert" className="border border-rose-700 text-rose-200 rounded p-3 text-xs">{error}</p>}
  {notice&&<p role="status" className="border border-cyan-700 text-cyan-200 rounded p-3 text-xs">{notice}</p>}
  <button type="button" disabled={busy} onClick={()=>void refresh().catch(e=>setError(String(e)))}
   className="text-cyan-300 text-xs">Refresh internal review queue</button>
  <form onSubmit={verify} className="flex flex-wrap items-end gap-3 border border-slate-700 rounded p-3">
   <label className="text-xs">Reviewer current password
    <input required type="password" autoComplete="current-password" value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block mt-1 rounded bg-slate-950 border border-slate-700 p-2"/></label>
   <button type="submit" disabled={busy} className="rounded bg-amber-800 px-3 py-2 text-xs">Verify</button>
  </form>
  {items.length===0?<p className="text-xs text-slate-400">No internal journals to review.</p>:
   items.map(i=><button type="button" key={i.id} onClick={()=>void open(i.id)}
    className="text-xs text-left text-cyan-300 border-t border-slate-700 py-2 block w-full">
    {i.id.slice(0,14)} · {i.status} · source {i.releaseIntentId.slice(0,12)}</button>)}
  {selected&&<div className="rounded border border-slate-700 p-3 space-y-2">
   <h3 className="font-semibold text-sm">Inspect every paired debit/credit evidence leg</h3>
   <p className="text-xs break-all">Journal SHA-256: {selected.journal.manifestSha256}</p>
   <p className="text-xs">SKUs: {selected.totals.skuCount} · legs: {selected.totals.legCount}
    · unverified evidence units: {selected.totals.evidenceUnits}
    · stock posted: {selected.totals.postedUnits}</p>
   {selected.manifest.legs.map((l,i)=><p key={l.productId+l.accountCode+i}
    className="text-xs border-t border-slate-700 py-2 break-all">
    {l.productId} · {l.accountCode} · {l.side} {l.quantity}
    · {l.trackingMode} · lot {l.lotCode??'—'}
    · candidate serials {l.serialNumbers.join(', ')||'—'}</p>)}
   <p className="text-xs text-amber-200">External official GRN: {String(selected.manifest.officialGrnVerified)}
    · Journal posting: {selected.manifest.postingState}. Serial evidence is NOT ownership.</p>
  </div>}
  {selected?.journal.status==='PENDING_INTERNAL'&&<form onSubmit={decide}
   className="border border-amber-800 rounded p-3 space-y-3">
   <label className="block text-xs">Independent review outcome
    <select value={decision} onChange={e=>setDecision(e.target.value as typeof decision)}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2">
     <option value="REJECTED_INTERNAL">Reject unposted journal proposal</option>
     <option value="REVIEWED_HELD">Accept paired evidence to HELD only (no posting)</option>
    </select></label>
   <label className="block text-xs">Independent review evidence ticket
    <input required value={evidence} maxLength={160} onChange={e=>setEvidence(e.target.value)}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2"/></label>
   <label className="block text-xs">Review reason (12–1000 characters)
    <textarea required value={reason} minLength={12} maxLength={1000}
     onChange={e=>setReason(e.target.value)} rows={3}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2"/></label>
   <label className="flex gap-2 text-xs text-amber-200">
    <input type="checkbox" checked={inspected} onChange={e=>setInspected(e.target.checked)}/>
    I independently inspected the balancing, source, SKU quantities and unverified serial evidence.
   </label>
   <button type="submit" disabled={busy||!verified||(decision==='REVIEWED_HELD'&&!inspected)}
    className="bg-amber-800 rounded px-4 py-2 text-xs disabled:opacity-50">
    Record irreversible internal journal HOLD decision</button>
  </form>}
 </section>;
}
