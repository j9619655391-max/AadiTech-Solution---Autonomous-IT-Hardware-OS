import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,hasRecentVerification,sensitiveFetch,verifyCurrentPassword} from '../services/authClient';
type Eligible={preparationId:string;holdId:string;preparationStatus:string;
 supplierCode:string;outboxId:string;claimId:string|null;claimStatus:string|null;
 observationId:string|null;observationStatus:string|null};
type Claim={id:string;preparationId:string;supplierAckRef:string;status:string;documentSha256:string};
type Pack={id:string;claimId:string;observationId:string;status:string;
 heldStatus:string|null;stockPostingState:string|null};
type Readiness={productionGrnReady:boolean;externalPoIssued:boolean;
 supplierAcknowledgmentAuthenticated:boolean;availableToSell:null};
async function parse<T>(r:Response):Promise<T>{
 const value:unknown=await r.json();
 if(!r.ok)throw Error(value&&typeof value==='object'&&'error' in value?String(value.error):'Evidence service unavailable');
 return value as T;
}
export function SupplierEvidenceOwnerPanel(){
 const [eligible,setEligible]=useState<Eligible[]>([]),[claims,setClaims]=useState<Claim[]>([]);
 const [packs,setPacks]=useState<Pack[]>([]),[readiness,setReadiness]=useState<Readiness|null>(null);
 const [preparationId,setPreparationId]=useState(''),[ackRef,setAckRef]=useState('');
 const [evidenceRef,setEvidenceRef]=useState(''),[documentSha256,setDocumentSha256]=useState('');
 const [candidate,setCandidate]=useState(''),[password,setPassword]=useState('');
 const [verified,setVerified]=useState(false),[busy,setBusy]=useState(false);
 const [error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  try{
   const [e,c,p,r]=await Promise.all([
    parse<{items:Eligible[]}>(await authenticatedFetch('/api/evidence-chain/eligible')),
    parse<{items:Claim[]}>(await authenticatedFetch('/api/evidence-chain/claims')),
    parse<{items:Pack[]}>(await authenticatedFetch('/api/evidence-chain/grn-packs')),
    parse<Readiness>(await authenticatedFetch('/api/evidence-chain/readiness'))
   ]);
   setEligible(e.items);setClaims(c.items);setPacks(p.items);setReadiness(r);
  }catch(e){setError(e instanceof Error?e.message:'Could not load evidence');
   setEligible([]);setClaims([]);setPacks([]);setReadiness(null);}
 },[]);
 useEffect(()=>{void refresh();},[refresh]);
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{await verifyCurrentPassword(password);setVerified(true);setPassword('');
   setNotice('Recent password verified; server MFA policy remains required.');}
  catch(e){setVerified(false);setError(e instanceof Error?e.message:'Verification failed');}
  finally{setBusy(false);}
 }
 function checkStepUp(){if(!verified||!hasRecentVerification())throw Error('Verify current password first');}
 async function recordClaim(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{
   checkStepUp();
   if(!window.confirm('Record an UNVERIFIED supplier acknowledgment CLAIM from offline evidence? No supplier authentication, delivery or PO issuance will be established.'))return;
   const data=await parse<{id:string;status:string}>(await sensitiveFetch('/api/evidence-chain/claims',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({preparationId,supplierAckRef:ackRef,evidenceRef,documentSha256})
   }));
   setNotice('Claim '+data.id+' '+data.status+'. This is NOT an authenticated supplier acknowledgment.');
   setPreparationId('');setAckRef('');setEvidenceRef('');setDocumentSha256('');
   await refresh();
  }catch(e){setError(e instanceof Error?e.message:'Claim refused');}
  finally{setBusy(false);}
 }
 async function prepare(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{
   checkStepUp();
   const candidateRow=eligible.find(x=>x.preparationId===candidate);
   if(!candidateRow?.claimId||!candidateRow.observationId)throw Error('Matching claim and quarantine observation required');
   if(!window.confirm('Create internal GRN evidence reconciliation for independent review? This will NOT create a GRN or recognize stock.'))return;
   const result=await parse<{id:string;status:string;quantityTotal:number}>(
    await sensitiveFetch('/api/evidence-chain/grn-packs',{
     method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({claimId:candidateRow.claimId,observationId:candidateRow.observationId})
    }));
   setNotice('Held-only GRN evidence pack '+result.id+' '+result.status+
    '. Observed internal units '+result.quantityTotal+'. No inventory posting.');
   setCandidate('');await refresh();
  }catch(e){setError(e instanceof Error?e.message:'Evidence reconciliation refused');}
  finally{setBusy(false);}
 }
 return <section aria-label="Supplier acknowledgment claims and held GRN evidence" className="bg-slate-900 border border-amber-800 rounded-xl p-5 space-y-4">
  <h2 className="text-xl font-semibold">Phase 1AF · Unverified supplier claim + GRN evidence HOLD</h2>
  <p className="text-xs text-amber-200">All claims are manually entered and unverified. HELD supplier PO was NEVER dispatched.
   An independent review does not establish supplier identity, authentic vendor acknowledgment,
   official GRN or available inventory. No external dispatch, warehouse posting or payment.</p>
  {error&&<p role="alert" className="border border-rose-700 text-rose-200 p-3 rounded text-sm">{error}</p>}
  {notice&&<p role="status" className="border border-cyan-700 text-cyan-200 p-3 rounded text-sm">{notice}</p>}
  <button type="button" disabled={busy} onClick={()=>void refresh()}
   className="text-xs text-cyan-300">Refresh internal evidence</button>
  <form onSubmit={verify} className="border border-slate-700 rounded p-3 flex flex-wrap items-end gap-3">
   <label className="text-xs">Current password
    <input type="password" autoComplete="current-password" required value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block mt-1 rounded bg-slate-950 border border-slate-700 p-2"/></label>
   <button type="submit" disabled={busy} className="bg-amber-800 px-3 py-2 rounded text-xs">Verify</button>
   <span className="text-xs text-slate-400">{verified&&hasRecentVerification()?'Step-up active':'Step-up required'}</span>
  </form>
  <form onSubmit={recordClaim} className="border border-slate-700 rounded p-3 space-y-3">
   <h3 className="text-sm font-semibold">Record manually asserted supplier-acknowledgment claim</h3>
   <label className="block text-xs">Approved INTERNAL supplier PO dispatch HOLD
    <select required value={preparationId} onChange={e=>setPreparationId(e.target.value)}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2">
     <option value="">Choose HELD internal preparation</option>
     {eligible.filter(x=>!x.claimId).map(x=><option value={x.preparationId} key={x.preparationId}>
      {x.supplierCode} · {x.preparationId.slice(0,12)} · dispatch DISABLED</option>)}
    </select></label>
   <div className="grid sm:grid-cols-2 gap-3">
    <label className="text-xs">Supplier-claimed ACK reference (uppercase)
     <input required value={ackRef} onChange={e=>setAckRef(e.target.value)}
      maxLength={80} className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2"/></label>
    <label className="text-xs">Offline evidence ticket (NOT a document upload)
     <input required value={evidenceRef} onChange={e=>setEvidenceRef(e.target.value)}
      maxLength={160} className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2"/></label>
    <label className="text-xs sm:col-span-2">SHA-256 (lowercase, 64 hex) of independently retained offline document
     <input required minLength={64} maxLength={64} value={documentSha256}
      onChange={e=>setDocumentSha256(e.target.value)}
      className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2 font-mono"/>
    </label>
   </div>
   <button disabled={busy||!verified||!preparationId} type="submit"
    className="rounded bg-amber-800 px-3 py-2 text-xs disabled:opacity-50">
    Record UNVERIFIED claim (no supplier contact)</button>
  </form>
  <div className="border border-slate-700 rounded p-3">
   <h3 className="text-sm font-semibold">Owner's supplier claims</h3>
   {claims.length===0?<p className="text-xs text-slate-400">No claims recorded.</p>:
    claims.map(x=><p key={x.id} className="text-xs border-t border-slate-700 py-2">
     {x.id.slice(0,12)} · {x.supplierAckRef} · {x.status} · External verification: NONE</p>)}
  </div>
  <form onSubmit={prepare} className="border border-slate-700 p-3 rounded space-y-3">
   <h3 className="text-sm font-semibold">Reconcile unverified claim against independently quarantined count</h3>
   <label className="block text-xs">Select internally attested claim + quarantine (no actual delivery proof)
    <select required value={candidate} onChange={e=>setCandidate(e.target.value)}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2">
     <option value="">Choose evidence pair</option>
     {eligible.filter(x=>x.claimStatus==='ATTESTED_INTERNAL'&&
      x.observationStatus==='QUARANTINED_INTERNAL'&&
      !packs.some(p=>p.claimId===x.claimId)).map(x=>
      <option key={x.preparationId} value={x.preparationId}>
       {x.supplierCode} · observation {x.observationId?.slice(0,12)} · reviewed internally</option>)}
    </select></label>
   <button disabled={busy||!verified||!candidate} type="submit"
    className="rounded bg-amber-800 px-3 py-2 text-xs disabled:opacity-50">
    Prepare GRN evidence HOLD (no stock)</button>
  </form>
  <div className="border border-amber-700 rounded p-3 space-y-2">
   <h3 className="text-sm font-semibold">GRN reconciliation evidence (not receipts)</h3>
   {packs.length===0?<p className="text-xs text-slate-400">No GRN-reconciliation evidence yet.</p>:
    packs.map(p=><p key={p.id} className="text-xs border-t border-slate-700 py-2">
     {p.id.slice(0,12)} · {p.status} · {p.heldStatus??'Review pending'} ·
     {p.stockPostingState??'NO STOCK POSTING'}</p>)}
   <p className="text-xs text-amber-200">Production GRN ready: {String(readiness?.productionGrnReady??false)}
    · Supplier authenticated: {String(readiness?.supplierAcknowledgmentAuthenticated??false)}
    · Available stock: NOT CALCULATED.</p>
  </div>
 </section>;
}
