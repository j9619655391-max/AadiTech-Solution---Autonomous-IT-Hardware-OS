import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';

type Supplier={id:string;code:string;legalName:string;status:string};
type Request={id:string;subtotal:string;status:string;supplierCode:string;siteCode:string;quoteEvidenceRef:string};
type Detail={request:Request;items:{sku:string;name:string;quantity:number;quotedUnitCost:string;lineSubtotal:string}[]};
async function json<T>(response:Response):Promise<T>{
 const body:unknown=await response.json();
 if(!response.ok)throw Error(body&&typeof body==='object'&&'error' in body?String(body.error):'Review service unavailable');
 return body as T;
}
export function ProcurementReviewerPanel(){
 const [suppliers,setSuppliers]=useState<Supplier[]>([]);
 const [requests,setRequests]=useState<Request[]>([]);
 const [selected,setSelected]=useState<Detail|null>(null);
 const [password,setPassword]=useState(''),[verified,setVerified]=useState(false);
 const [evidenceRef,setEvidenceRef]=useState('');
 const [decision,setDecision]=useState<'APPROVED_INTERNAL'|'REJECTED_INTERNAL'>('REJECTED_INTERNAL');
 const [reason,setReason]=useState('');
 const [attest,setAttest]=useState(false);
 const [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 const reload=useCallback(async()=>{
  const [s,r]=await Promise.all([
   json<{items:Supplier[]}>(await authenticatedFetch('/api/procurement/review/suppliers')),
   json<{items:Request[]}>(await authenticatedFetch('/api/procurement/review/requests'))
  ]);
  setSuppliers(s.items);setRequests(r.items);
 },[]);
 useEffect(()=>{void reload().catch(e=>setError(e instanceof Error?e.message:'Procurement review unavailable'));},[reload]);
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{await verifyCurrentPassword(password);setVerified(true);setPassword('');
   setNotice('Password verification active for at most five minutes. Privileged MFA still enforced by server.');}
  catch(e){setVerified(false);setError(e instanceof Error?e.message:'Verification unavailable');}
  finally{setBusy(false);}
 }
 function checkStepUp(){
  if(!verified||!hasRecentVerification())throw Error('Verify current password before reviewing');
 }
 async function attestSupplier(supplier:Supplier){
  setBusy(true);setError('');setNotice('');
  try{
   checkStepUp();
   if(!window.confirm('Record an INTERNAL identity review based on evidence reference only? No external supplier verification occurs.'))return;
   const result=await json<{status:string}>(await sensitiveFetch(
    '/api/procurement/review/suppliers/'+encodeURIComponent(supplier.id)+'/attest',{
     method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({evidenceRef,attestIdentified:true})
    }));
   setNotice(supplier.code+': '+result.status+'. Internal identity evidence recorded only.');
   setEvidenceRef('');await reload();
  }catch(e){setError(e instanceof Error?e.message:'Supplier review failed');}
  finally{setBusy(false);}
 }
 async function open(item:Request){
  setBusy(true);setError('');setNotice('');
  try{
   const detail=await json<Detail>(await authenticatedFetch(
    '/api/procurement/review/requests/'+encodeURIComponent(item.id)));
   setSelected(detail);setReason('');setAttest(false);setDecision('REJECTED_INTERNAL');
  }catch(e){setError(e instanceof Error?e.message:'Cannot inspect request');}
  finally{setBusy(false);}
 }
 async function submit(e:React.FormEvent){
  e.preventDefault();if(!selected)return;
  setBusy(true);setError('');setNotice('');
  try{
   checkStepUp();
   if(!window.confirm('Record independent INTERNAL purchase review? This cannot send a supplier PO or post stock.'))return;
   const value=await json<{decision:string}>(await sensitiveFetch(
    '/api/procurement/review/requests/'+encodeURIComponent(selected.request.id)+'/decide',{
     method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({decision,reason,evidenceAttested:attest})
    }));
   setNotice('Internal decision recorded: '+value.decision+'. No purchase order or stock movement.');
   setSelected(null);await reload();
  }catch(e){setError(e instanceof Error?e.message:'Review failed; refresh before retry');}
  finally{setBusy(false);}
 }
 return <section aria-label="Independent procurement reviewer" className="border border-slate-700 rounded-xl bg-slate-900 p-5 space-y-4">
  <h2 className="font-semibold text-lg">Independent Procurement Review — Internal Only</h2>
  <p className="text-sm text-amber-200">Supplier identity attestation and purchase-review snapshots are internal
   evidence records; not certified supplier onboarding, PO dispatch, goods receipts or available inventory.
   Reviewer must not act for the original requestor.</p>
  {error&&<p role="alert" className="text-rose-200 text-sm border border-rose-700 p-3 rounded">{error}</p>}
  {notice&&<p role="status" className="text-cyan-200 text-sm border border-cyan-700 p-3 rounded">{notice}</p>}
  <button type="button" disabled={busy} onClick={()=>void reload().catch(e=>setError(String(e)))}
   className="text-cyan-300 text-sm">Refresh procurement review queue</button>
  <form onSubmit={verify} className="border border-slate-700 rounded p-3 flex flex-wrap items-end gap-3">
   <label className="text-sm">Current password
    <input type="password" autoComplete="current-password" required value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block mt-1 bg-slate-950 border border-slate-700 p-2 rounded"/></label>
   <button type="submit" disabled={busy} className="bg-cyan-700 px-3 py-2 rounded text-sm disabled:opacity-50">Verify</button>
   <span className="text-xs text-slate-400">{verified&&hasRecentVerification()?'Step-up current':'Step-up required'}</span>
  </form>
  <div className="grid md:grid-cols-2 gap-4">
   <section className="space-y-3 border border-slate-700 p-4 rounded">
    <h3 className="font-semibold text-sm">Unverified supplier identity queue</h3>
    {suppliers.length===0?<p className="text-xs text-slate-400">No pending supplier entries.</p>:
     suppliers.map(s=><div key={s.id} className="border-t border-slate-700 pt-2 text-xs space-y-2">
      <p>{s.code} · {s.legalName}</p>
      <label className="block">Reference from independent supplier identity inspection
       <input value={evidenceRef} maxLength={160} onChange={e=>setEvidenceRef(e.target.value)}
        placeholder="Ticket/reference ID, no secrets"
        className="block bg-slate-950 border border-slate-700 p-2 w-full rounded mt-1"/></label>
      <button type="button" disabled={busy||!verified||evidenceRef.length<8}
       onClick={()=>void attestSupplier(s)}
       className="bg-amber-800 rounded px-3 py-2 disabled:opacity-50">Attest supplier internally</button>
     </div>)}
   </section>
   <section className="space-y-3 border border-slate-700 p-4 rounded">
    <h3 className="font-semibold text-sm">Purchase requisitions</h3>
    {requests.length===0?<p className="text-xs text-slate-400">No internal requisitions to inspect.</p>:
     requests.map(r=><button type="button" key={r.id} onClick={()=>void open(r)}
      className="block text-left border-t border-slate-700 py-2 w-full text-xs hover:text-cyan-300">
      <strong>{r.id.slice(0,12)} · {r.status}</strong>
      <span className="block">{r.supplierCode} · Site {r.siteCode} · Proposed ₹{r.subtotal}</span>
     </button>)}
   </section>
  </div>
  {selected&&<form onSubmit={submit} className="p-4 border border-amber-700 rounded space-y-3">
   <h3 className="font-semibold">Review request {selected.request.id.slice(0,16)}</h3>
   <p className="text-sm">Supplier: {selected.request.supplierCode} · Supplier quote reference: {selected.request.quoteEvidenceRef}
    · Proposed subtotal ₹{selected.request.subtotal} (not a verified invoice amount)</p>
   <table className="text-xs text-left w-full"><thead><tr>
    <th>SKU</th><th>Qty</th><th>Quoted cost</th><th>Line subtotal</th>
   </tr></thead><tbody>{selected.items.map(item=><tr key={item.sku} className="border-t border-slate-700">
    <td className="py-2">{item.sku} · {item.name}</td><td>{item.quantity}</td>
    <td>₹{item.quotedUnitCost}</td><td>₹{item.lineSubtotal}</td>
   </tr>)}</tbody></table>
   {selected.request.status==='PENDING'?<>
    <label className="text-sm block">Internal decision
     <select value={decision} onChange={e=>setDecision(e.target.value as typeof decision)}
      className="block bg-slate-950 border border-slate-700 rounded p-2 mt-1">
      <option value="REJECTED_INTERNAL">Reject internally</option>
      <option value="APPROVED_INTERNAL">Approve internal request ONLY</option>
     </select></label>
    <label className="text-sm block">Reason (10–1000 characters)
     <textarea required minLength={10} maxLength={1000} value={reason} onChange={e=>setReason(e.target.value)}
      className="block bg-slate-950 border border-slate-700 rounded p-2 w-full mt-1" rows={3}/></label>
    <label className="flex gap-2 items-start text-xs text-amber-200">
     <input type="checkbox" checked={attest} onChange={e=>setAttest(e.target.checked)}/>
     I independently inspected supplier quote evidence and request-line details (required to approve).
    </label>
    <button type="submit" disabled={busy||!verified||(decision==='APPROVED_INTERNAL'&&!attest)}
     className="rounded bg-amber-800 px-4 py-2 text-sm disabled:opacity-50">Record internal decision</button>
   </>:<p className="text-amber-200 text-sm">Already decided; immutable review. Cannot approve again.</p>}
  </form>}
  <p className="text-xs text-amber-200">No supplier dispatch, purchase booking, bank transfer,
   receipt, serialized custody or stock reservation is authorized by review actions.</p>
 </section>;
}
