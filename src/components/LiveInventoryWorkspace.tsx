import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,hasRecentVerification,sensitiveFetch,verifyCurrentPassword} from '../services/authClient';
import {crmClient,type CRMRecord} from '../services/crmClient';

type Site={id:string;code:string;name:string};
type Count={id:string;productId:string;sku:string;brand:string;model:string;
 siteCode:string;quantity:number;evidenceRef:string;recordedAt:string};
async function json<T>(response:Response):Promise<T>{
 const body:unknown=await response.json();
 if(!response.ok){
  const message=body&&typeof body==='object'&&'error' in body&&typeof body.error==='string'
   ?body.error:'Inventory request unavailable';
  throw Error(message);
 }
 return body as T;
}
export function LiveInventoryWorkspace(){
 const [sites,setSites]=useState<Site[]>([]);
 const [counts,setCounts]=useState<Count[]>([]);
 const [products,setProducts]=useState<CRMRecord[]>([]);
 const [page,setPage]=useState(1);
 const [productPage,setProductPage]=useState(1);
 const [productTotal,setProductTotal]=useState(0);
 const [total,setTotal]=useState(0);
 const [error,setError]=useState('');
 const [message,setMessage]=useState('');
 const [loading,setLoading]=useState(true);
 const [busy,setBusy]=useState(false);
 const [password,setPassword]=useState('');
 const [verified,setVerified]=useState(false);
 const [siteCode,setSiteCode]=useState('');
 const [siteName,setSiteName]=useState('');
 const [productId,setProductId]=useState('');
 const [siteId,setSiteId]=useState('');
 const [quantity,setQuantity]=useState('');
 const [evidenceRef,setEvidenceRef]=useState('');
 const [attested,setAttested]=useState(false);
 const load=useCallback(async()=>{
  setLoading(true);setError('');
  try{
   const [siteResult,countResult,productResult]=await Promise.all([
    json<{items:Site[]}>(await authenticatedFetch('/api/inventory/sites')),
    json<{items:Count[];total:number}>(await authenticatedFetch('/api/inventory/opening-counts?page='+page+'&limit=25')),
    crmClient.list('products',productPage,25)
   ]);
   setSites(siteResult.items);
   setCounts(countResult.items);setTotal(countResult.total);
   setProducts(productResult.items);setProductTotal(productResult.total);
  }catch(e){setCounts([]);setProducts([]);setSites([]);
   setError(e instanceof Error?e.message:'Inventory MySQL unavailable');
  }finally{setLoading(false);}
 },[page,productPage]);
 useEffect(()=>{void load();},[load]);
 async function stepUp(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setMessage('');
  try{await verifyCurrentPassword(password);setVerified(true);
   setPassword('');setMessage('Password reverified for up to five minutes. Production also requires MFA.');
  }catch(e){setVerified(false);setError(e instanceof Error?e.message:'Verification unavailable');}
  finally{setBusy(false);}
 }
 function confirmed(){
  if(!verified||!hasRecentVerification())throw Error('Reverify password before writing inventory');
 }
 async function createSite(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setMessage('');
  try{
   confirmed();
   const input={code:siteCode.trim().toUpperCase(),name:siteName.trim()};
   const record=await json<{id:string}>(await sensitiveFetch('/api/inventory/sites',{
    method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(input)}));
   setMessage('Owner-entered site saved: '+record.id+'. No warehouse stock was created.');
   setSiteCode('');setSiteName('');await load();
  }catch(e){setError(e instanceof Error?e.message:'Site creation unavailable');}
  finally{setBusy(false);}
 }
 async function createCount(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setMessage('');
  try{
   confirmed();
   if(!attested)throw Error('Confirm evidence and physical count attestation first');
   if(!/^(0|[1-9][0-9]{0,6})$/.test(quantity)||Number(quantity)>1000000)
    throw Error('Use a whole quantity from 0 to 1000000');
   const requestKey=crypto.randomUUID();
   const record=await json<{id:string}>(await sensitiveFetch('/api/inventory/opening-counts',{
    method:'POST',headers:{'Content-Type':'application/json','Idempotency-Key':requestKey},
    body:JSON.stringify({productId,siteId,quantity:Number(quantity),
     evidenceRef:evidenceRef.trim()})
   }));
   setMessage('Opening count '+record.id+' recorded. This does not certify available-to-sell stock.');
   setQuantity('');setEvidenceRef('');setAttested(false);setPage(1);await load();
  }catch(e){setError(e instanceof Error?e.message:'Opening count unavailable');}
  finally{setBusy(false);}
 }
 return <section className="bg-slate-900 border border-slate-700 rounded-xl p-5 space-y-4" aria-label="MySQL stock opening counts">
  <div><h2 className="text-xl text-white font-semibold">MySQL Inventory · Opening Counts</h2>
   <p className="text-xs text-amber-200 mt-2">AUTHORITATIVE RECORD OF OWNER ATTESTATION ONLY.
    Counts do not prove physical stock, availability, reservation, procurement receipt, payment or dispatch.
    Existing product master comes from the MySQL CRM catalog. No default stock or locations are seeded.</p></div>
  {error&&<p role="alert" className="text-sm text-rose-200">{error}</p>}
  {message&&<p role="status" className="text-sm text-cyan-200">{message}</p>}
  <button type="button" onClick={()=>void load()} disabled={busy||loading} className="rounded border border-cyan-700 text-cyan-300 px-3 py-2 text-xs disabled:opacity-50">Refresh from MySQL</button>
  <form onSubmit={stepUp} className="flex flex-wrap items-end gap-3 border border-slate-700 p-3 rounded-lg">
   <label className="text-xs text-slate-300">Recent password verification
    <input type="password" autoComplete="current-password" value={password} required onChange={e=>setPassword(e.target.value)}
     className="block bg-slate-950 border border-slate-600 rounded p-2 mt-1"/></label>
   <button type="submit" disabled={busy} className="rounded bg-cyan-700 px-3 py-2 text-xs disabled:opacity-50">Verify password</button>
   <span className="text-xs text-amber-200">{verified&&hasRecentVerification()?'Verified temporarily':'Step-up required for new sites and counts'}</span>
  </form>
  <div className="grid gap-4 lg:grid-cols-2">
   <form onSubmit={createSite} className="space-y-2 p-3 rounded-lg border border-slate-700">
    <h3 className="text-sm text-white font-medium">Register verified warehouse/site name</h3>
    <input placeholder="SITE_CODE" aria-label="Site code" value={siteCode} onChange={e=>setSiteCode(e.target.value)}
     maxLength={32} required className="w-full bg-slate-950 border border-slate-600 rounded p-2 text-sm"/>
    <input placeholder="Human-verified site name" aria-label="Site name" value={siteName} onChange={e=>setSiteName(e.target.value)}
     maxLength={120} required className="w-full bg-slate-950 border border-slate-600 rounded p-2 text-sm"/>
    <button type="submit" disabled={busy||!verified} className="rounded bg-cyan-700 px-3 py-2 text-xs disabled:opacity-50">Save site to MySQL</button>
   </form>
   <form onSubmit={createCount} className="space-y-2 p-3 rounded-lg border border-slate-700">
    <h3 className="text-sm text-white font-medium">Record one immutable opening count</h3>
    <select required aria-label="Product" value={productId} onChange={e=>setProductId(e.target.value)}
     className="w-full bg-slate-950 border border-slate-600 rounded p-2 text-sm">
     <option value="">Select verified MySQL catalog product</option>
     {products.map(p=><option key={p.id} value={p.id}>{String(p.sku)} · {String(p.model)}</option>)}
    </select>
    <div className="text-xs text-slate-400 flex gap-2 items-center">
     <button type="button" onClick={()=>{setProductPage(x=>Math.max(1,x-1));setProductId('');}} disabled={productPage===1||loading}>Previous products</button>
     <span>Catalog page {productPage} / {Math.max(1,Math.ceil(productTotal/25))}</span>
     <button type="button" onClick={()=>{setProductPage(x=>x+1);setProductId('');}} disabled={productPage*25>=productTotal||loading}>Next products</button>
    </div>
    <select required aria-label="Warehouse site" value={siteId} onChange={e=>setSiteId(e.target.value)}
     className="w-full bg-slate-950 border border-slate-600 rounded p-2 text-sm">
     <option value="">Select registered site</option>{sites.map(site=><option key={site.id} value={site.id}>{site.code} · {site.name}</option>)}
    </select>
    <input required aria-label="Counted quantity" placeholder="Physically counted quantity (0 allowed)"
     value={quantity} inputMode="numeric" onChange={e=>setQuantity(e.target.value)}
     className="w-full bg-slate-950 border border-slate-600 rounded p-2 text-sm"/>
    <input required aria-label="Evidence ticket" placeholder="Evidence reference (ticket ID, not secrets)"
     value={evidenceRef} maxLength={160} onChange={e=>setEvidenceRef(e.target.value)}
     className="w-full bg-slate-950 border border-slate-600 rounded p-2 text-sm"/>
    <label className="text-xs text-slate-300 flex gap-2 items-start">
     <input type="checkbox" checked={attested} onChange={e=>setAttested(e.target.checked)}/>
     I attest the physical count and independently documented evidence. No later overwrite of this opening count.</label>
    <button type="submit" disabled={busy||!verified||!attested||!sites.length||!products.length}
     className="rounded bg-cyan-700 px-3 py-2 text-xs disabled:opacity-50">Record opening count (no stock movements)</button>
   </form>
  </div>
  <div className="border border-slate-700 rounded-lg overflow-auto">
   <h3 className="p-3 border-b border-slate-700 text-sm text-white">Attested opening counts · {total} records</h3>
   {loading?<p role="status" className="p-3 text-sm">Loading MySQL data…</p>:
    counts.length===0?<p className="p-3 text-sm text-slate-400">No opening counts saved in MySQL.</p>:
    <table className="w-full text-sm text-left"><thead><tr className="text-slate-400">
     <th className="p-2">Product</th><th className="p-2">Site</th><th className="p-2">Opening qty</th>
     <th className="p-2">Evidence</th></tr></thead><tbody>
     {counts.map(c=><tr key={c.id} className="border-t border-slate-700">
      <td className="p-2">{c.sku} · {c.model}</td><td className="p-2">{c.siteCode}</td>
      <td className="p-2">{c.quantity}</td><td className="p-2">{c.evidenceRef}</td>
     </tr>)} </tbody></table>}
  </div>
  <div className="flex gap-3 items-center text-xs text-slate-400">
   <button type="button" disabled={page===1||loading} onClick={()=>setPage(x=>Math.max(1,x-1))}>Previous counts</button>
   <span>Page {page} · {total} records</span>
   <button type="button" disabled={page*25>=total||loading} onClick={()=>setPage(x=>x+1)}>Next counts</button>
  </div>
  <p className="text-xs text-amber-200">Procurement, inbound receipts, reservations, stock issues, adjustments,
   weighted cost/COGS and accounting ledger are NOT YET IMPLEMENTED. This is not an available-to-sell dashboard.</p>
 </section>;
}
