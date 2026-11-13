import React,{useCallback,useEffect,useRef,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
import {crmClient,type CRMRecord} from '../services/crmClient';

type Supplier={id:string;code:string;legalName:string;status:'UNVERIFIED'|'REVIEWED_INTERNAL'};
type Site={id:string;code:string;name:string};
type Purchase={id:string;status:string;subtotal:string;supplierCode:string;siteCode:string;holdId:string|null};
type Line={productId:string;quantity:number;quotedUnitCost:string};
async function json<T>(r:Response):Promise<T>{
 const raw:unknown=await r.json();
 if(!r.ok)throw Error(raw&&typeof raw==='object'&&'error' in raw?String(raw.error):'Procurement API unavailable');
 return raw as T;
}
async function loadProducts():Promise<CRMRecord[]>{
 const first=await crmClient.list('products',1,100);
 if(first.total>2000)throw Error('Product master exceeds safe selector limit; restrict catalog before entry');
 const all=[...first.items];
 for(let page=2;page<=Math.ceil(first.total/100);page++){
  const next=await crmClient.list('products',page,100);
  all.push(...next.items);
 }
 if(all.length!==first.total)throw Error('Catalog changed during load; refresh before selecting SKU');
 return all;
}
export function LiveProcurementWorkspace(){
 const [suppliers,setSuppliers]=useState<Supplier[]>([]);
 const [sites,setSites]=useState<Site[]>([]);
 const [products,setProducts]=useState<CRMRecord[]>([]);
 const [requests,setRequests]=useState<Purchase[]>([]);
 const [busy,setBusy]=useState(false),[loading,setLoading]=useState(true);
 const [error,setError]=useState(''),[notice,setNotice]=useState('');
 const [password,setPassword]=useState(''),[verified,setVerified]=useState(false);
 const [supplierCode,setSupplierCode]=useState(''),[supplierName,setSupplierName]=useState('');
 const [supplierTaxId,setSupplierTaxId]=useState('');
 const [supplierId,setSupplierId]=useState(''),[siteId,setSiteId]=useState('');
 const [quoteEvidenceRef,setQuoteEvidenceRef]=useState('');
 const [productId,setProductId]=useState(''),[quantity,setQuantity]=useState('1');
 const [quotedUnitCost,setQuotedUnitCost]=useState('');
 const [lines,setLines]=useState<Line[]>([]);
 const pending=useRef<{body:string;key:string}|null>(null);
 const reload=useCallback(async()=>{
  setLoading(true);setError('');
  try{
   const [s,i,p,r]=await Promise.all([
    json<{items:Supplier[]}>(await authenticatedFetch('/api/procurement/suppliers')),
    json<{items:Site[]}>(await authenticatedFetch('/api/inventory/sites')),
    loadProducts(),
    json<{items:Purchase[]}>(await authenticatedFetch('/api/procurement/requests'))
   ]);
   setSuppliers(s.items);setSites(i.items);setProducts(p);setRequests(r.items);
  }catch(e){setSuppliers([]);setProducts([]);setRequests([]);setSites([]);
   setError(e instanceof Error?e.message:'Server-backed procurement unavailable');
  }finally{setLoading(false);}
 },[]);
 useEffect(()=>{void reload();},[reload]);
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{await verifyCurrentPassword(password);setVerified(true);setPassword('');
   setNotice('Password verified for at most five minutes; privileged production MFA remains required.');}
  catch(e){setVerified(false);setError(e instanceof Error?e.message:'Password verification failed');}
  finally{setBusy(false);}
 }
 function requireVerified(){
  if(!verified||!hasRecentVerification())throw Error('Recent password verification required');
 }
 async function createSupplier(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{
   requireVerified();
   const result=await json<{id:string}>(await sensitiveFetch('/api/procurement/suppliers',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({code:supplierCode.trim().toUpperCase(),
     legalName:supplierName.trim(),taxId:supplierTaxId.trim().toUpperCase()||null})}));
   setNotice('Supplier saved UNVERIFIED: '+result.id+'. Independent reviewer must attest identity before purchasing.');
   setSupplierCode('');setSupplierName('');setSupplierTaxId('');await reload();
  }catch(e){setError(e instanceof Error?e.message:'Supplier not saved');}
  finally{setBusy(false);}
 }
 function addLine(){
  if(!productId||!/^[1-9][0-9]{0,3}$/.test(quantity)||Number(quantity)>1000||
    !/^(0|[1-9][0-9]{0,12})(\.[0-9]{1,2})?$/.test(quotedUnitCost)||
    Number(quotedUnitCost)<=0){
   setError('Select a product, quantity 1–1000 and positive quoted unit cost (decimal string).');return;
  }
  if(lines.some(x=>x.productId===productId)||lines.length>=25){
   setError('Duplicate product or 25-line limit exceeded');return;
  }
  setLines(old=>[...old,{productId,quantity:Number(quantity),quotedUnitCost}]);
  setProductId('');setQuantity('1');setQuotedUnitCost('');pending.current=null;setError('');
 }
 async function createRequest(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{
   requireVerified();
   if(!lines.length)throw Error('Select and add at least one verified SKU');
   if(!window.confirm('Submit INTERNAL procurement request for independent review only? No supplier PO, receipt, reservation or payment will occur.'))
    return;
   const body=JSON.stringify({supplierId,siteId,quoteEvidenceRef,items:lines});
   if(!pending.current||pending.current.body!==body)
    pending.current={body,key:crypto.randomUUID()};
   const result=await json<{id:string;subtotal:string}>(await sensitiveFetch('/api/procurement/requests',{
    method:'POST',headers:{'Content-Type':'application/json','Idempotency-Key':pending.current.key},
    body
   }));
   pending.current=null;setLines([]);setQuoteEvidenceRef('');
   setNotice('Internal requisition '+result.id+' saved, proposed subtotal ₹'+result.subtotal+
    '. Await independent review. No supplier order was sent.');
   await reload();
  }catch(e){setError((e instanceof Error?e.message:'Requisition failed')+
   '. Same form is retried using original idempotency key.');}
  finally{setBusy(false);}
 }
 async function hold(id:string){
  if(busy||!window.confirm('Prepare a HELD internal PO snapshot? This will NOT send a purchase order to the supplier.'))return;
  setBusy(true);setError('');setNotice('');
  try{
   requireVerified();
   const value=await json<{sha256:string}>(await sensitiveFetch('/api/procurement/requests/'+encodeURIComponent(id)+'/hold',{
    method:'POST',headers:{'Content-Type':'application/json'},body:'{}'
   }));
   setNotice('Internal PO snapshot held (SHA-256 '+value.sha256+'). Dispatch DISABLED; nothing sent or received.');
   await reload();
  }catch(e){setError(e instanceof Error?e.message:'Cannot prepare PO hold');}
  finally{setBusy(false);}
 }
 const choose=(id:string)=>products.find(x=>x.id===id);
 return <section className="border border-slate-700 bg-slate-900 rounded-xl p-5 space-y-5" aria-label="MySQL internal procurement">
  <header>
   <h2 className="text-xl font-semibold">MySQL Procurement — Independent Review / PO HOLD</h2>
   <p className="text-sm text-amber-200 mt-2">Internal supplier registry, requisitions and held PO snapshots only.
    Reviewer attestation is NOT external supplier verification. No supplier messages, goods receipts, available stock,
    reservation, payment or GST-certified invoice can be created by this interface.</p>
  </header>
  {error&&<p role="alert" className="p-3 border border-rose-700 rounded text-sm text-rose-200">{error}</p>}
  {notice&&<p role="status" className="p-3 border border-cyan-700 rounded text-sm text-cyan-200">{notice}</p>}
  <button type="button" disabled={busy||loading} onClick={()=>void reload()} className="text-xs text-cyan-300">Refresh server records</button>
  <form onSubmit={verify} className="flex flex-wrap items-end gap-3 border border-slate-700 p-3 rounded">
   <label className="text-xs">Verify current password
    <input type="password" required autoComplete="current-password" value={password}
     onChange={e=>setPassword(e.target.value)} className="block bg-slate-950 border border-slate-600 rounded p-2 mt-1"/></label>
   <button type="submit" disabled={busy} className="bg-cyan-700 rounded px-3 py-2 text-xs disabled:opacity-50">Verify</button>
   <span className="text-xs text-slate-400">{verified&&hasRecentVerification()?'Recent verification active':'Reverification needed before writes'}</span>
  </form>
  <form onSubmit={createSupplier} className="border border-slate-700 rounded p-4 space-y-3">
   <h3 className="font-medium">Register unverified supplier</h3>
   <div className="grid gap-3 sm:grid-cols-3">
    <label className="text-xs">Supplier code<input required value={supplierCode} maxLength={32}
     onChange={e=>setSupplierCode(e.target.value)} placeholder="VENDOR_01"
     className="block w-full bg-slate-950 border border-slate-700 rounded p-2 mt-1"/></label>
    <label className="text-xs">Legal name<input required value={supplierName} maxLength={200}
     onChange={e=>setSupplierName(e.target.value)} placeholder="From verified document"
     className="block w-full bg-slate-950 border border-slate-700 rounded p-2 mt-1"/></label>
    <label className="text-xs">GSTIN (optional, verify source)<input value={supplierTaxId} maxLength={15}
     onChange={e=>setSupplierTaxId(e.target.value)}
     className="block w-full bg-slate-950 border border-slate-700 rounded p-2 mt-1"/></label>
   </div>
   <button type="submit" disabled={busy||loading||!verified} className="bg-cyan-700 rounded px-3 py-2 text-xs disabled:opacity-50">Save supplier UNVERIFIED</button>
  </form>
  <div className="border border-slate-700 rounded p-3">
   <h3 className="font-medium text-sm">Supplier registry · {suppliers.length}</h3>
   {suppliers.length===0?<p className="text-xs text-slate-400 mt-2">No suppliers created in MySQL.</p>:
    suppliers.map(s=><p key={s.id} className="text-xs border-t border-slate-700 p-2">{s.code} · {s.legalName} · <strong>{s.status}</strong></p>)}
  </div>
  <form onSubmit={createRequest} className="border border-slate-700 rounded p-4 space-y-3">
   <h3 className="font-medium">Create supplier-quoted INTERNAL requisition</h3>
   <div className="grid md:grid-cols-3 gap-3">
    <label className="text-xs">Reviewed supplier
     <select required value={supplierId} onChange={e=>{setSupplierId(e.target.value);pending.current=null;}}
      className="block bg-slate-950 border border-slate-700 rounded p-2 w-full mt-1">
      <option value="">Select reviewed supplier</option>
      {suppliers.filter(x=>x.status==='REVIEWED_INTERNAL').map(x=><option key={x.id} value={x.id}>{x.code} · {x.legalName}</option>)}
     </select></label>
    <label className="text-xs">Registered site
     <select required value={siteId} onChange={e=>{setSiteId(e.target.value);pending.current=null;}}
      className="block bg-slate-950 border border-slate-700 rounded p-2 w-full mt-1">
      <option value="">Select site</option>
      {sites.map(x=><option key={x.id} value={x.id}>{x.code} · {x.name}</option>)}
     </select></label>
    <label className="text-xs">Supplier quote evidence ID
     <input required value={quoteEvidenceRef} maxLength={160}
      onChange={e=>{setQuoteEvidenceRef(e.target.value);pending.current=null;}}
      className="block bg-slate-950 border border-slate-700 rounded p-2 w-full mt-1"/></label>
   </div>
   <div className="grid gap-3 sm:grid-cols-[1fr_110px_150px_auto] items-end">
    <label className="text-xs">Existing MySQL SKU
     <select value={productId} onChange={e=>setProductId(e.target.value)}
      className="block bg-slate-950 border border-slate-700 rounded p-2 w-full mt-1">
      <option value="">Select product</option>
      {products.map(x=><option key={x.id} value={x.id}>{String(x.sku)} · {String(x.model)}</option>)}
     </select></label>
    <label className="text-xs">Qty<input value={quantity} inputMode="numeric" onChange={e=>setQuantity(e.target.value)}
     className="block bg-slate-950 border border-slate-700 rounded p-2 w-full mt-1"/></label>
    <label className="text-xs">Quoted unit cost ₹
     <input value={quotedUnitCost} inputMode="decimal" placeholder="From supplier evidence"
      onChange={e=>setQuotedUnitCost(e.target.value)}
      className="block bg-slate-950 border border-slate-700 rounded p-2 w-full mt-1"/></label>
    <button type="button" onClick={addLine} className="bg-slate-700 rounded px-3 py-2 text-xs">Add line</button>
   </div>
   {lines.map(l=><div key={l.productId} className="flex justify-between gap-2 text-xs border border-slate-700 rounded p-2">
    <span>{String(choose(l.productId)?.sku??'SKU missing')} · {l.quantity} × ₹{l.quotedUnitCost} (unverified supplier quote)</span>
    <button type="button" className="text-rose-300" onClick={()=>{setLines(v=>v.filter(x=>x.productId!==l.productId));pending.current=null;}}>Remove</button></div>)}
   <button disabled={busy||loading||!verified||!supplierId||!siteId||!lines.length} type="submit"
    className="bg-cyan-700 px-4 py-2 rounded text-xs disabled:opacity-50">Save INTERNAL request for independent approval</button>
  </form>
  <div className="border border-slate-700 rounded p-3 space-y-2">
   <h3 className="text-sm font-medium">Internal procurement requests · last {requests.length}</h3>
   {requests.length===0?<p className="text-xs text-slate-400">No requests yet</p>:
    requests.map(r=><div key={r.id} className="border-t border-slate-700 p-2 text-xs flex flex-wrap gap-2 items-center justify-between">
     <span>{r.id.slice(0,12)} · {r.supplierCode} / {r.siteCode} · ₹{r.subtotal} · {r.status}
      {r.holdId?' · PO HOLD CREATED (no dispatch)':''}</span>
     {r.status==='APPROVED_INTERNAL'&&!r.holdId&&
      <button disabled={busy||!verified} type="button" onClick={()=>void hold(r.id)}
       className="px-3 py-2 bg-amber-800 rounded disabled:opacity-50">Create HELD PO snapshot</button>}
    </div>)}
  </div>
  <p className="text-xs text-amber-200">HOLD: Goods receipt, serial/lot custody, physical stock ledger, reservation,
   purchase order transmission, vendor payment and accounting are intentionally disabled pending independent controls.</p>
 </section>;
}
