import React, { useCallback, useEffect, useState } from 'react';
import { authenticatedFetch } from '../services/authClient';

type Decision={revision_number:number;decision:'APPROVED_INTERNAL'|'REJECTED_INTERNAL';reason:string;gross_margin_bps:number;minimum_margin_bps:number;created_at:string};
type Review={currentRevision:number;effectiveDecision:Decision|null;history:Decision[]};
async function parse<T>(response:Response):Promise<T>{
  const value:unknown=await response.json();
  if(!response.ok)throw Error(value && typeof value==='object' && 'error' in value?String(value.error):'Review unavailable');
  return value as T;
}
export function DraftOwnerReviewPanel({draftId}:{draftId:string}){
  const [review,setReview]=useState<Review|null>(null);
  const [decision,setDecision]=useState<'APPROVED_INTERNAL'|'REJECTED_INTERNAL'>('REJECTED_INTERNAL');
  const [reason,setReason]=useState('');
  const [override,setOverride]=useState(false);
  const [error,setError]=useState('');
  const [message,setMessage]=useState('');
  const [busy,setBusy]=useState(false);
  const refresh=useCallback(async()=>{
    const data=await parse<Review>(await authenticatedFetch('/api/quotes/reviews/'+draftId));
    setReview(data);
  },[draftId]);
  useEffect(()=>{
    let active=true;setReview(null);setError('');setMessage('');
    fetchGuard('/api/quotes/reviews/'+draftId).then(response=>parse<Review>(response))
      .then(result=>{if(active)setReview(result);})
      .catch(e=>{if(active)setError(e instanceof Error?e.message:'Failed to load decisions');});
    return()=>{active=false;};
  },[draftId]);
  async function decide(e:React.FormEvent){
    e.preventDefault();
    if(busy || !review || review.effectiveDecision)return;
    if(!window.confirm('Record an INTERNAL owner review decision? This will NOT send or approve a customer-facing quotation.'))return;
    setBusy(true);setError('');setMessage('');
    try{
      const result=await parse<{reviewStatus:string;grossMarginBps:number}>(await authenticatedFetch('/api/quotes/reviews/'+draftId,{
        method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({expectedRevision:review.currentRevision,decision,reason,overrideRequested:override})
      }));
      setMessage('Saved '+result.reviewStatus+' · gross margin '+result.grossMarginBps/100+'%. No external action taken.');
      setReason('');setOverride(false);await refresh();
    }catch(e){setError((e instanceof Error?e.message:'Review failed')+'. Refresh before retrying.');}
    finally{setBusy(false);}
  }
  return <section className="rounded-xl border border-amber-700/70 bg-slate-900 p-5 space-y-3">
    <h3 className="font-semibold">Internal Owner Review · ADQ-{draftId}</h3>
    <p className="text-xs text-amber-300">Only the latest revision may be reviewed. Decision history is immutable. Internal approval does not permit sending, invoicing, purchase orders or stock movement.</p>
    <button type="button" onClick={()=>void refresh().catch(e=>setError(String(e)))} className="text-sm text-cyan-300">Refresh current revision / decisions</button>
    {error&&<p role="alert" className="text-sm text-rose-300">{error}</p>}
    {message&&<p role="status" className="text-sm text-emerald-300">{message}</p>}
    {!review?<p className="text-slate-400 text-sm">Loading owner reviews…</p>:<>
      <p className="text-sm">Latest revision: {review.currentRevision} · Effective review: <strong>{review.effectiveDecision?.decision??'NONE / NOT REVIEWED'}</strong></p>
      {!review.effectiveDecision&&<form onSubmit={decide} className="space-y-3">
        <label className="block text-sm">Review decision
          <select value={decision} onChange={e=>setDecision(e.target.value as typeof decision)}
            className="block bg-slate-950 border border-slate-700 rounded p-2 mt-1">
            <option value="REJECTED_INTERNAL">Reject internally</option>
            <option value="APPROVED_INTERNAL">Mark reviewed internally</option>
          </select>
        </label>
        <label className="block text-sm">Review justification
          <textarea value={reason} onChange={e=>setReason(e.target.value)} required minLength={5} maxLength={1000}
            className="block bg-slate-950 border border-slate-700 rounded p-2 mt-1 w-full" rows={3}/>
        </label>
        {decision==='APPROVED_INTERNAL'&&<label className="flex gap-2 text-sm text-amber-200">
          <input type="checkbox" checked={override} onChange={e=>setOverride(e.target.checked)}/>
          Explicitly request below-minimum-margin override (server validates actual margin and requires detailed reason)
        </label>}
        <button type="submit" disabled={busy} className="px-4 py-2 rounded bg-amber-700 disabled:opacity-50">
          {busy?'Recording…':'Record internal decision'}
        </button>
      </form>}
      <h4 className="text-sm font-semibold">Audit history</h4>
      {review.history.length===0?<p className="text-xs text-slate-400">No decisions recorded.</p>:
        review.history.map(d=><div key={d.revision_number} className="border border-slate-700 rounded p-3 text-xs">
          <strong>Revision {d.revision_number} · {d.decision}</strong>
          <p>{d.reason}</p>
          <p>Margin {d.gross_margin_bps/100}% · policy {d.minimum_margin_bps/100}%</p>
        </div>)}
    </>}
  </section>;
}
function fetchGuard(url:string){return authenticatedFetch(url);}
