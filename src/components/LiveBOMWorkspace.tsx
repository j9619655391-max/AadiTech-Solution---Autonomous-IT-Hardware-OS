import React, { useCallback, useEffect, useRef, useState } from 'react';
import { crmClient, type CRMRecord } from '../services/crmClient';
import { authenticatedFetch } from '../services/authClient';
import { DraftRevisionPanel } from './DraftRevisionPanel';
import { DraftOwnerReviewPanel } from './DraftOwnerReviewPanel';
import { DraftReleaseHoldPanel } from './DraftReleaseHoldPanel';

type Line = { productId: string; quantity: number };
type DraftSummary = { id: string; draftNumber: string; customer_name: string; subtotal: string; tax_estimate: string; total_estimate: string; created_at: string };
type DraftResponse = {id:string;draftNumber:string;replayed:boolean;status:'DRAFT';subtotal:string;taxEstimate:string;totalEstimate:string;message:string};
async function allRecords(kind: 'customers' | 'products'): Promise<CRMRecord[]> {
  const first=await crmClient.list(kind,1,100);
  if(first.total>2000)throw Error('Too many '+kind+' to safely select from; refine the catalog first.');
  const records=[...first.items];
  for(let page=2;page<=Math.ceil(first.total/100);page++){
    const response=await crmClient.list(kind,page,100);
    records.push(...response.items);
  }
  if(records.length!==first.total)throw Error('CRM changed while loading. Refresh and try again.');
  return records;
}
async function parseResponse<T>(response:Response):Promise<T>{
  const payload:unknown=await response.json();
  if(!response.ok){
    const err=payload && typeof payload==='object' && 'error' in payload ? String(payload.error) : 'Request failed';
    throw Error(err);
  }
  return payload as T;
}

export function LiveBOMWorkspace(){
  const [customers,setCustomers]=useState<CRMRecord[]>([]);
  const [products,setProducts]=useState<CRMRecord[]>([]);
  const [customerId,setCustomerId]=useState('');
  const [lines,setLines]=useState<Line[]>([]);
  const [productId,setProductId]=useState('');
  const [quantity,setQuantity]=useState(1);
  const [loading,setLoading]=useState(true);
  const [saving,setSaving]=useState(false);
  const [error,setError]=useState('');
  const [confirmation,setConfirmation]=useState<DraftResponse | null>(null);
  const [drafts,setDrafts]=useState<DraftSummary[]>([]);
  const [revisionDraftId,setRevisionDraftId]=useState<string | null>(null);
  const pendingRequest=useRef<{payload:string;key:string} | null>(null);

  const reload=useCallback(async()=>{
    setError('');setLoading(true);
    try{
      const [c,p,response]=await Promise.all([
        allRecords('customers'),allRecords('products'),authenticatedFetch('/api/quotes/drafts')
      ]);
      const d=await parseResponse<{items:DraftSummary[]}>(response);
      setCustomers(c);setProducts(p);setDrafts(d.items);
    }catch(e){setError(e instanceof Error?e.message:'MySQL data unavailable.');}
    finally{setLoading(false);}
  },[]);
  useEffect(()=>{void reload();},[reload]);

  function addLine(){
    if(!productId || !Number.isSafeInteger(quantity) || quantity<1 || quantity>1000){
      setError('Select a verified product and quantity between 1 and 1000.');return;
    }
    if(lines.some(line=>line.productId===productId)){
      setError('Product already present. Remove or change its quantity.');return;
    }
    if(lines.length>=40){setError('Maximum 40 line items.');return;}
    setLines(old=>[...old,{productId,quantity}]);setProductId('');setQuantity(1);setError('');setConfirmation(null);
  }

  async function save(){
    if(!customerId || !lines.length){setError('Select an existing customer and at least one product.');return;}
    if(!window.confirm('Create an INTERNAL DRAFT only? Nothing will be sent, approved, ordered or reserved.'))return;
    setSaving(true);setError('');setConfirmation(null);
    try{
      const payload=JSON.stringify({customerId,items:lines});
      // Retain key for same payload across uncertain network failures.
      if(!pendingRequest.current || pendingRequest.current.payload!==payload)
        pendingRequest.current={payload,key:crypto.randomUUID()};
      const response=await authenticatedFetch('/api/quotes/drafts',{
        method:'POST',
        headers:{'Content-Type':'application/json','Idempotency-Key':pendingRequest.current.key},
        body:payload
      });
      const result=await parseResponse<DraftResponse>(response);
      pendingRequest.current=null;
      setConfirmation(result);setLines([]);setCustomerId('');
      const updated=await authenticatedFetch('/api/quotes/drafts');
      const listed=await parseResponse<{items:DraftSummary[]}>(updated);
      setDrafts(listed.items);
    }catch(e){
      setError((e instanceof Error?e.message:'Draft save failed')+
        ' Repeating the same form uses its original request key and should not create a duplicate.');
    }finally{setSaving(false);}
  }
  const selectedProduct=(id:string)=>products.find(p=>p.id===id);
  return <section className="space-y-5">
    <div className="rounded-xl border border-cyan-800 bg-slate-900 p-5">
      <h2 className="text-xl font-bold">Live BOM → Internal Quotation Draft</h2>
      <p className="mt-2 text-sm text-slate-400">Select only MySQL-backed CRM customers and catalog products.
        Amounts, price snapshots and estimated GST are calculated by the server at save time.</p>
      <p className="mt-2 text-sm text-amber-300">Draft-only. No real sales quote sent; no invoice, tax approval,
        inventory reservation, Telegram approval or customer notification.</p>
    </div>
    {error && <p role="alert" className="rounded-lg border border-rose-800 bg-rose-950/40 p-3 text-rose-200 text-sm">{error}</p>}
    {confirmation && <div role="status" className="border border-emerald-700 rounded-lg p-4 bg-emerald-950/40">
      <strong>{confirmation.replayed ? 'Previously saved draft found:' : 'Internal draft saved:'} {confirmation.draftNumber}</strong>
      <p>Subtotal ₹{confirmation.subtotal} · Estimated GST ₹{confirmation.taxEstimate} · Estimated total ₹{confirmation.totalEstimate}</p>
      <p className="text-sm">{confirmation.message}</p>
    </div>}
    <div className="rounded-xl border border-slate-700 bg-slate-900 p-5 space-y-4">
      <div className="flex justify-between gap-3">
        <h3 className="font-semibold">Create draft</h3>
        <button onClick={()=>void reload()} disabled={loading || saving} className="text-cyan-300 text-sm disabled:opacity-40">Refresh from MySQL</button>
      </div>
      {loading ? <p role="status" className="text-sm text-slate-400">Loading verified records…</p> : <>
        <label className="block text-sm space-y-1">Customer
          <select value={customerId} onChange={e=>setCustomerId(e.target.value)}
            className="block w-full bg-slate-950 border border-slate-700 p-3 rounded-lg">
            <option value="">Select live customer</option>
            {customers.map(customer=><option key={customer.id} value={customer.id}>{String(customer.name)} · {String(customer.email)}</option>)}
          </select>
        </label>
        <div className="grid grid-cols-1 sm:grid-cols-[1fr_120px_auto] gap-3 items-end">
          <label className="text-sm space-y-1">Catalog product
            <select value={productId} onChange={e=>setProductId(e.target.value)}
              className="block w-full bg-slate-950 border border-slate-700 p-3 rounded-lg">
              <option value="">Select verified SKU</option>
              {products.map(product=><option key={product.id} value={product.id}>{String(product.sku)} · {String(product.brand)} {String(product.model)}</option>)}
            </select>
          </label>
          <label className="text-sm space-y-1">Quantity
            <input value={quantity} type="number" min={1} max={1000} step={1} onChange={e=>setQuantity(Number(e.target.value))}
              className="block w-full bg-slate-950 border border-slate-700 p-3 rounded-lg"/>
          </label>
          <button type="button" onClick={addLine} className="bg-cyan-700 rounded-lg px-4 py-3 text-sm">Add line</button>
        </div>
        {lines.map(line=>{
          const item=selectedProduct(line.productId);
          return <div key={line.productId} className="flex justify-between gap-3 p-3 border border-slate-700 rounded-lg text-sm">
            <span>{String(item?.sku??'Unavailable')} · {String(item?.brand??'')} {String(item?.model??'')} · Qty {line.quantity}</span>
            <button type="button" onClick={()=>setLines(v=>v.filter(i=>i.productId!==line.productId))}
              className="text-rose-300">Remove</button>
          </div>;
        })}
        <p className="text-xs text-slate-400">No browser-calculated figure is authoritative. Server validates availability of master data, catalog selling price and draft totals.</p>
        <button type="button" onClick={()=>void save()} disabled={saving || !customerId || !lines.length}
          className="bg-cyan-600 px-4 py-3 rounded-lg disabled:opacity-40 font-semibold">
          {saving ? 'Saving internal draft…' : 'Save internal draft to MySQL'}
        </button>
      </>}
    </div>
    {revisionDraftId && <><DraftRevisionPanel draftId={revisionDraftId} /><DraftOwnerReviewPanel draftId={revisionDraftId}/><DraftReleaseHoldPanel draftId={revisionDraftId}/></>}
    <div className="rounded-xl border border-slate-700 bg-slate-900 p-5">
      <h3 className="font-semibold mb-3">Saved draft quotations (latest 100)</h3>
      {drafts.length===0 ? <p className="text-slate-400 text-sm">No persisted draft quotations yet.</p> :
        <div className="overflow-x-auto"><table className="w-full text-sm text-left">
          <thead><tr className="border-b border-slate-700 text-slate-400">
            <th className="p-2">Draft ID</th><th className="p-2">Customer</th><th className="p-2">Subtotal</th><th className="p-2">Tax estimate</th><th className="p-2">Total estimate</th>
          </tr></thead>
          <tbody>{drafts.map(d=><tr key={d.id} className="border-b border-slate-800">
            <td className="p-2 font-mono text-xs">
              <button type="button" className="text-cyan-300 hover:underline"
                onClick={()=>setRevisionDraftId(d.id)}>{d.draftNumber} · Revisions</button>
            </td><td className="p-2">{d.customer_name}</td>
            <td className="p-2">₹{d.subtotal}</td><td className="p-2">₹{d.tax_estimate}</td><td className="p-2">₹{d.total_estimate}</td>
          </tr>)}</tbody>
        </table></div>}
    </div>
  </section>;
}
