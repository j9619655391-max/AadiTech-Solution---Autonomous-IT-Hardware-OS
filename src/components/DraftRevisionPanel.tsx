import React, { useEffect, useState } from 'react';
import { authenticatedFetch } from '../services/authClient';

type DraftItem={product_id:string;sku_snapshot:string;name_snapshot:string;quantity:number;unit_price:string};
type Revision={revision_number:number;reason:string;subtotal:string;tax_estimate:string;total_estimate:string;gross_margin_bps:number;review_status:string;line_snapshot:{productId:string;quantity:number}[]};
type Props={draftId:string};

async function json<T>(response:Response):Promise<T>{
  const result:unknown=await response.json();
  if(!response.ok)throw Error(result && typeof result==='object' && 'error' in result?String(result.error):'Request failed');
  return result as T;
}
export function DraftRevisionPanel({draftId}:Props){
  const [items,setItems]=useState<DraftItem[]>([]);
  const [quantities,setQuantities]=useState<Record<string,number>>({});
  const [history,setHistory]=useState<Revision[]>([]);
  const [reason,setReason]=useState('');
  const [error,setError]=useState('');
  const [success,setSuccess]=useState('');
  const [busy,setBusy]=useState(false);
  const [loaded,setLoaded]=useState(false);

  async function refresh(){
    const [detail,log]=await Promise.all([
      json<{items:DraftItem[]}>(await authenticatedFetch('/api/quotes/drafts/'+draftId)),
      json<{revisions:Revision[]}>(await authenticatedFetch('/api/quotes/drafts/'+draftId+'/revisions'))
    ]);
    setItems(detail.items);setHistory(log.revisions);
    const latest=log.revisions[log.revisions.length-1]?.line_snapshot;
    setQuantities(Object.fromEntries(detail.items.map(item=>[
      item.product_id,latest?.find(v=>v.productId===item.product_id)?.quantity??item.quantity
    ])));
    setLoaded(true);
  }
  useEffect(()=>{
    let cancelled=false;
    setLoaded(false);setError('');setSuccess('');
    Promise.all([
      authenticatedFetch('/api/quotes/drafts/'+draftId).then(r=>json<{items:DraftItem[]}>(r)),
      authenticatedFetch('/api/quotes/drafts/'+draftId+'/revisions').then(r=>json<{revisions:Revision[]}>(r))
    ]).then(([detail,log])=>{
      if(cancelled)return;
      setItems(detail.items);setHistory(log.revisions);
      const latest=log.revisions[log.revisions.length-1]?.line_snapshot;
      setQuantities(Object.fromEntries(detail.items.map(item=>[
        item.product_id,latest?.find(v=>v.productId===item.product_id)?.quantity??item.quantity
      ])));
      setLoaded(true);
    }).catch(e=>{if(!cancelled)setError(e instanceof Error?e.message:'Could not load draft');});
    return()=>{cancelled=true;};
  },[draftId]);

  async function save(event:React.FormEvent){
    event.preventDefault();
    if(!reason.trim() || busy || items.length===0)return;
    if(!window.confirm('Save one NEW INTERNAL revision? This does NOT approve or send a quote.'))return;
    setBusy(true);setError('');setSuccess('');
    try{
      const lines=items.map(item=>({productId:item.product_id,quantity:quantities[item.product_id]}));
      const response=await authenticatedFetch('/api/quotes/drafts/'+draftId+'/revisions',{
        method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({expectedRevision:history.length,reason:reason.trim(),items:lines})
      });
      const saved=await json<{revision:number;reviewStatus:string;totalEstimate:string}>(response);
      setSuccess('Revision '+saved.revision+' recorded. '+saved.reviewStatus+' · Estimated total ₹'+saved.totalEstimate);
      setReason('');
      await refresh();
    }catch(e){setError((e instanceof Error?e.message:'Failed to save revision')+
      '. Refresh history before retrying after an uncertain network error.');}
    finally{setBusy(false);}
  }

  return <section className="rounded-xl border border-cyan-800 bg-slate-900 p-5 space-y-3">
    <div className="flex justify-between gap-3">
      <h3 className="font-semibold">Revision history · ADQ-{draftId}</h3>
      <button type="button" disabled={busy} className="text-cyan-300 text-xs"
        onClick={()=>void refresh().catch(e=>setError(e instanceof Error?e.message:'Refresh failed'))}>Refresh</button>
    </div>
    <p className="text-xs text-amber-300">Only quantities can change. Product prices and GST remain the original saved snapshots.
      Margin warnings are not approvals; nothing is sent to customers.</p>
    {error && <p role="alert" className="text-rose-300 text-sm">{error}</p>}
    {success && <p role="status" className="text-emerald-300 text-sm">{success}</p>}
    {!loaded?<p role="status" className="text-slate-400 text-sm">Loading revisions…</p>:
      <form onSubmit={save} className="space-y-3">
        {items.map(item=><label key={item.product_id} className="flex gap-3 items-center text-sm">
          <span className="flex-1">{item.sku_snapshot} · {item.name_snapshot} · ₹{item.unit_price}</span>
          <input type="number" aria-label={'Quantity '+item.sku_snapshot} required min={1} max={1000} step={1}
            value={quantities[item.product_id]??item.quantity}
            onChange={e=>setQuantities(v=>({...v,[item.product_id]:Number(e.target.value)}))}
            className="bg-slate-950 border border-slate-700 rounded p-2 w-24"/>
        </label>)}
        <label className="block text-sm">Revision reason
          <input value={reason} onChange={e=>setReason(e.target.value)} maxLength={500} required
            className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/>
        </label>
        <button type="submit" disabled={busy} className="bg-cyan-700 rounded px-4 py-2 disabled:opacity-40">
          {busy?'Recording…':'Save internal revision'}
        </button>
      </form>}
    <div className="border-t border-slate-700 pt-3 space-y-2">
      <h4 className="text-sm font-semibold">Saved history</h4>
      {history.length===0?<p className="text-slate-400 text-xs">Original draft: revision 0. No revisions saved.</p>:
        history.map(row=><div key={row.revision_number} className="rounded border border-slate-700 p-3 text-xs">
          <strong>Revision {row.revision_number}</strong> · {row.reason}
          <p>Subtotal ₹{row.subtotal} · GST estimate ₹{row.tax_estimate} · Total ₹{row.total_estimate}</p>
          <p>Gross margin {row.gross_margin_bps/100}% · {row.review_status} (advisory)</p>
        </div>)}
    </div>
  </section>;
}
