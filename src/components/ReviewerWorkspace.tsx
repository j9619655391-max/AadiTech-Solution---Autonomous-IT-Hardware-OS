import React,{useEffect,useState} from 'react';
import {authenticatedFetch} from '../services/authClient';
import {ProcurementReviewerPanel} from './ProcurementReviewerPanel';
import {InboundWitnessPanel} from './InboundWitnessPanel';
import {SupplierDispatchReviewerPanel} from './SupplierDispatchReviewerPanel';
import {SupplierEvidenceReviewerPanel} from './SupplierEvidenceReviewerPanel';
import {StockFoundationReviewerPanel} from './StockFoundationReviewerPanel';
import {JournalFoundationReviewerPanel} from './JournalFoundationReviewerPanel';
import {SignedProofReviewerPanel} from './SignedProofReviewerPanel';
import {KeyLifecycleReviewerPanel} from './KeyLifecycleReviewerPanel';
type Queued={id:string;created_by:string;current_revision:number;review_state:string};
type Brief={draftId:string;drafterId:string;revision:number;subtotal:string;taxEstimate:string;totalEstimate:string;items:unknown[]};
type Review={currentRevision:number;effectiveDecision:unknown;history:{revision_number:number;decision:string;reason:string}[]};
async function read<T>(path:string):Promise<T>{
 const response=await authenticatedFetch(path);const value=await response.json();
 if(!response.ok)throw Error(value.error||'Request failed');return value as T;
}
export function ReviewerWorkspace(){
 const [items,setItems]=useState<Queued[]>([]);
 const [selected,setSelected]=useState<Queued|null>(null);
 const [brief,setBrief]=useState<Brief|null>(null);
 const [review,setReview]=useState<Review|null>(null);
 const [decision,setDecision]=useState<'APPROVED_INTERNAL'|'REJECTED_INTERNAL'>('REJECTED_INTERNAL');
 const [reason,setReason]=useState('');
 const [override,setOverride]=useState(false);
 const [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 async function queue(){const list=await read<{items:Queued[]}>('/api/quotes/reviews/queue');setItems(list.items);}
 useEffect(()=>{let active=true;read<{items:Queued[]}>('/api/quotes/reviews/queue')
  .then(v=>{if(active)setItems(v.items);}).catch(e=>{if(active)setError(String(e));});
  return()=>{active=false;};},[]);
 async function open(item:Queued){
  setBusy(true);setError('');setNotice('');
  try{
   const [a,b]=await Promise.all([
    read<Brief>('/api/quotes/reviews/'+item.id+'/brief'),
    read<Review>('/api/quotes/reviews/'+item.id)
   ]);
   setSelected(item);setBrief(a);setReview(b);setReason('');setOverride(false);
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function submit(event:React.FormEvent){
  event.preventDefault();
  if(!selected||!review||review.effectiveDecision||busy)return;
  if(!window.confirm('Record independent INTERNAL review only? This does not deliver customer documents.'))return;
  setBusy(true);setError('');setNotice('');
  try{
   const response=await authenticatedFetch('/api/quotes/reviews/'+selected.id,{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({expectedRevision:review.currentRevision,decision,reason,overrideRequested:override})
   });
   const value=await response.json();
   if(!response.ok)throw Error(value.error||'Review failed');
   setNotice('Independent internal decision recorded: '+value.reviewStatus+'. No external delivery.');
   await queue();await open(selected);
  }catch(e){setError(String(e)+'. Refresh before retrying.');}finally{setBusy(false);}
 }
 return <main className="min-h-screen bg-slate-950 text-slate-100 p-5 sm:p-8 space-y-5">
  <div><h1 className="text-2xl font-bold">AadiTech · Independent Reviewer</h1>
   <p className="text-sm text-slate-400">Restricted access: quotation review queue only. CRM editing, order creation and external sending are not available.</p>
  </div>
  {error&&<p role="alert" className="border border-rose-700 rounded p-3 text-rose-300">{error}</p>}
  {notice&&<p role="status" className="border border-emerald-700 rounded p-3 text-emerald-300">{notice}</p>}
  <button type="button" onClick={()=>void queue().catch(e=>setError(String(e)))} className="text-cyan-300">Refresh review queue</button>
  <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
   <section className="border border-slate-700 rounded-xl bg-slate-900 p-4 space-y-3">
    <h2 className="font-semibold">Awaiting / completed reviews</h2>
    {items.length===0&&<p className="text-sm text-slate-400">No internal drafts available for independent review.</p>}
    {items.map(item=><button key={item.id} type="button" onClick={()=>void open(item)}
      className="w-full text-left border border-slate-700 rounded-lg p-3 hover:border-cyan-600">
      <strong className="text-xs font-mono">ADQ-{item.id}</strong>
      <p className="text-xs text-slate-400">Revision {item.current_revision} · {item.review_state}</p>
    </button>)}
   </section>
   <section className="border border-slate-700 rounded-xl bg-slate-900 p-4 space-y-3">
    <h2 className="font-semibold">Review verified snapshot</h2>
    {!selected||!brief||!review?<p className="text-sm text-slate-400">Select a draft to inspect.</p>:<>
     <p className="text-sm">Revision {brief.revision} · Subtotal ₹{brief.subtotal} · Tax estimate ₹{brief.taxEstimate} · Total estimate ₹{brief.totalEstimate}</p>
     <pre className="text-xs bg-slate-950 border border-slate-700 rounded p-3 max-h-52 overflow-auto whitespace-pre-wrap">{JSON.stringify(brief.items,null,2)}</pre>
     <p className="text-sm">Current decision: {review.effectiveDecision?'Already reviewed':'Not yet reviewed'}</p>
     {!review.effectiveDecision&&<form onSubmit={submit} className="space-y-3">
      <label className="block text-sm">Decision
       <select value={decision} onChange={e=>setDecision(e.target.value as typeof decision)} className="block w-full bg-slate-950 border border-slate-700 rounded p-2 mt-1">
        <option value="REJECTED_INTERNAL">Reject internally</option>
        <option value="APPROVED_INTERNAL">Mark reviewed internally</option>
       </select>
      </label>
      <label className="block text-sm">Reason
       <textarea value={reason} onChange={e=>setReason(e.target.value)} minLength={5} maxLength={1000} required
        className="block w-full bg-slate-950 border border-slate-700 rounded p-2 mt-1" rows={3}/>
      </label>
      {decision==='APPROVED_INTERNAL'&&<label className="flex items-start gap-2 text-amber-300 text-sm">
       <input type="checkbox" checked={override} onChange={e=>setOverride(e.target.checked)}/>
       Request below-policy margin override (minimum 20-character justification enforced by server)
      </label>}
      <button disabled={busy} type="submit" className="rounded bg-cyan-700 px-4 py-2 disabled:opacity-40">Record independent decision</button>
     </form>}
     <h3 className="text-sm font-semibold">Decision history</h3>
     {review.history.map(h=><p key={h.revision_number} className="border border-slate-700 rounded p-2 text-xs">Revision {h.revision_number} · {h.decision} · {h.reason}</p>)}
    </>}
   </section>
  </div>
  <ProcurementReviewerPanel />
  <InboundWitnessPanel />
  <SupplierDispatchReviewerPanel />
  <SupplierEvidenceReviewerPanel />
  <StockFoundationReviewerPanel />
  <JournalFoundationReviewerPanel />
  <SignedProofReviewerPanel />
  <KeyLifecycleReviewerPanel />
  <p className="text-xs text-amber-300">Independent internal approval does not authorize customer communication or supplier purchase orders. Outbound dispatch remains disabled.</p>
 </main>;
}
