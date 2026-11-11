import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,hasRecentVerification,sensitiveFetch,verifyCurrentPassword} from '../services/authClient';
type Claim={id:string;preparationId:string;status:string;supplierAckRef:string;
 evidenceRef:string;documentSha256:string;recordedBy:string;claimSha256:string};
type Pack={id:string;claimId:string;observationId:string;status:string;packSha256:string;preparedBy:string};
type Detail={pack:{id:string;status:string;claimId:string;observationId:string};
 snapshot:{holdId:string;outboxSha256:string;claimSha256:string;observationSha256:string;
 quantityTotal:number;lineCount:number;externalPoIssued:boolean;stockPostingState:string}};
async function parse<T>(r:Response):Promise<T>{
 const v:unknown=await r.json();
 if(!r.ok)throw Error(v&&typeof v==='object'&&'error' in v?String(v.error):'Review API unavailable');
 return v as T;
}
export function SupplierEvidenceReviewerPanel(){
 const [claims,setClaims]=useState<Claim[]>([]),[packs,setPacks]=useState<Pack[]>([]);
 const [selectedClaim,setSelectedClaim]=useState<Claim|null>(null),[selectedPack,setSelectedPack]=useState<Detail|null>(null);
 const [password,setPassword]=useState(''),[verified,setVerified]=useState(false);
 const [decision,setDecision]=useState<'ATTESTED_INTERNAL'|'DISPUTED_INTERNAL'|'HELD_INTERNAL'|'REJECTED_INTERNAL'>('DISPUTED_INTERNAL');
 const [reason,setReason]=useState(''),[evidence,setEvidence]=useState(''),[inspected,setInspected]=useState(false);
 const [error,setError]=useState(''),[notice,setNotice]=useState(''),[busy,setBusy]=useState(false);
 const refresh=useCallback(async()=>{
  const [c,p]=await Promise.all([
   parse<{items:Claim[]}>(await authenticatedFetch('/api/evidence-chain/review/claims')),
   parse<{items:Pack[]}>(await authenticatedFetch('/api/evidence-chain/review/grn-packs'))
  ]);
  setClaims(c.items);setPacks(p.items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(e instanceof Error?e.message:'Evidence review unavailable'));},[refresh]);
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{await verifyCurrentPassword(password);setPassword('');setVerified(true);
   setNotice('Password reverified; server-side MFA policy still applies.');}
  catch(e){setVerified(false);setError(e instanceof Error?e.message:'Password verification failed');}
  finally{setBusy(false);}
 }
 function reset(){setReason('');setEvidence('');setInspected(false);setError('');setNotice('');}
 function selectClaim(c:Claim){
  reset();setSelectedClaim(c);setSelectedPack(null);setDecision('DISPUTED_INTERNAL');
 }
 async function openPack(p:Pack){
  setBusy(true);reset();setSelectedClaim(null);setSelectedPack(null);
  try{
   const result=await parse<Detail>(await authenticatedFetch(
    '/api/evidence-chain/review/grn-packs/'+encodeURIComponent(p.id)));
   setSelectedPack(result);setDecision('REJECTED_INTERNAL');
  }catch(e){setError(e instanceof Error?e.message:'Cannot load immutable GRN pack');}
  finally{setBusy(false);}
 }
 async function decide(e:React.FormEvent){
  e.preventDefault();if(busy)return;
  setBusy(true);setError('');setNotice('');
  try{
   if(!verified||!hasRecentVerification())throw Error('Verify reviewer current password');
   if(!window.confirm('Record internal evidence-review decision ONLY? This cannot verify supplier authenticity, issue GRN, release stock or dispatch goods.'))return;
   const claimMode=!!selectedClaim;
   if(!selectedClaim&&!selectedPack)throw Error('Select evidence to review');
   const url=claimMode?
    '/api/evidence-chain/review/claims/'+encodeURIComponent(selectedClaim!.id)+'/decide':
    '/api/evidence-chain/review/grn-packs/'+encodeURIComponent(selectedPack!.pack.id)+'/decide';
   const body=claimMode?{decision,reason,reviewEvidenceRef:evidence,documentInspected:inspected}:
    {decision,reason,reviewEvidenceRef:evidence,custodyInspected:inspected};
   const result=await parse<{status:string}>(await sensitiveFetch(url,{
    method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)
   }));
   setNotice('Independent internal decision '+result.status+
    '. Supplier authentication/official GRN/stock posting remain disabled.');
   setSelectedClaim(null);setSelectedPack(null);setReason('');setEvidence('');setInspected(false);
   await refresh();
  }catch(e){setError(e instanceof Error?e.message:'Review refused');}
  finally{setBusy(false);}
 }
 const canApprove=decision==='ATTESTED_INTERNAL'||decision==='HELD_INTERNAL';
 return <section aria-label="Independent supplier acknowledgment claims and GRN reconciliation witness"
  className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="text-lg font-semibold">Phase 1AF · Independent supplier-claim / GRN-evidence review</h2>
  <p className="text-xs text-amber-200">These records originate from unverified offline owner claims and internally
   quarantined counts. Approval is NOT vendor-source authentication, legal goods receipt,
   available-to-sell stock, invoice matching or financial valuation. All dispatch/posting disabled.</p>
  {error&&<p role="alert" className="text-rose-200 border border-rose-700 rounded p-3 text-sm">{error}</p>}
  {notice&&<p role="status" className="text-cyan-200 border border-cyan-700 rounded p-3 text-sm">{notice}</p>}
  <button type="button" disabled={busy} className="text-xs text-cyan-300"
   onClick={()=>void refresh().catch(e=>setError(String(e)))}>Refresh independent evidence queues</button>
  <form onSubmit={verify} className="border border-slate-700 rounded p-3 flex flex-wrap gap-3 items-end">
   <label className="text-xs">Reviewer current password
    <input type="password" autoComplete="current-password" required value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block mt-1 rounded bg-slate-950 border border-slate-700 p-2"/></label>
   <button type="submit" disabled={busy} className="bg-amber-800 px-3 py-2 rounded text-xs">Verify</button>
   <span className="text-xs text-slate-400">{verified&&hasRecentVerification()?'Recent step-up valid':'Step-up required'}</span>
  </form>
  <div className="grid md:grid-cols-2 gap-3">
   <div className="rounded border border-slate-700 p-3 space-y-2">
    <h3 className="text-sm font-semibold">Unverified supplier-acknowledgment claims</h3>
    {claims.length===0?<p className="text-xs text-slate-400">No recorded claims.</p>:
     claims.map(c=><div key={c.id} className="border-t border-slate-700 py-2 space-y-1 text-xs">
      <p>{c.supplierAckRef} · {c.status} · {c.id.slice(0,12)}</p>
      {c.status==='AWAITING_INTERNAL_REVIEW'&&<button type="button"
       onClick={()=>selectClaim(c)} className="text-cyan-300">Inspect offline claim</button>}
     </div>)}
   </div>
   <div className="rounded border border-slate-700 p-3 space-y-2">
    <h3 className="text-sm font-semibold">GRN-reconciliation evidence packs (NOT GRNs)</h3>
    {packs.length===0?<p className="text-xs text-slate-400">No internal evidence packs.</p>:
     packs.map(p=><div key={p.id} className="border-t border-slate-700 py-2 text-xs">
      <p>{p.id.slice(0,12)} · {p.status}</p>
      <button type="button" onClick={()=>void openPack(p)} className="text-cyan-300">
       Inspect digest-bound source lines</button>
     </div>)}
   </div>
  </div>
  {selectedClaim&&<div className="border border-amber-700 rounded p-3 space-y-2">
   <h3 className="text-sm font-semibold">Review manually asserted claim {selectedClaim.id.slice(0,12)}</h3>
   <p className="text-xs">Operator: {selectedClaim.recordedBy} · supplier-claimed ref: {selectedClaim.supplierAckRef}
    · Ticket {selectedClaim.evidenceRef}</p>
   <p className="text-xs break-all">Owner-entered document SHA-256: {selectedClaim.documentSha256}
    · Server claim SHA-256: {selectedClaim.claimSha256}</p>
   <p className="text-xs text-amber-200">Review the offline document independently. Hash alone does NOT prove
    ownership, vendor delivery or document authenticity.</p>
  </div>}
  {selectedPack&&<div className="border border-amber-700 rounded p-3 space-y-2">
   <h3 className="text-sm font-semibold">Inspect immutable GRN-readiness pack</h3>
   <p className="text-xs">Pack {selectedPack.pack.id} · {selectedPack.pack.status}
    · Internal observed SKU lines {selectedPack.snapshot.lineCount}
    · Internally quarantined units {selectedPack.snapshot.quantityTotal}</p>
   <p className="text-xs break-all">Held PO {selectedPack.snapshot.holdId}
    · Observed evidence SHA-256 {selectedPack.snapshot.observationSha256}
    · Claimed ACK SHA-256 {selectedPack.snapshot.claimSha256}</p>
   <p className="text-xs text-amber-200">Outbound dispatch state {selectedPack.snapshot.stockPostingState}
    · Supplier PO issued? {String(selectedPack.snapshot.externalPoIssued)}
    · No official receipt or stock posting authority.</p>
  </div>}
  {(selectedClaim||selectedPack)&&
   (selectedClaim?.status==='AWAITING_INTERNAL_REVIEW'||selectedPack?.pack.status==='AWAITING_INTERNAL_REVIEW')&&
   <form onSubmit={decide} className="rounded border border-slate-700 p-3 space-y-3">
    <label className="block text-xs">Independent INTERNAL decision only
     <select value={decision} onChange={e=>setDecision(e.target.value as typeof decision)}
      className="block mt-1 rounded bg-slate-950 border border-slate-700 p-2">
      {selectedClaim?<><option value="DISPUTED_INTERNAL">Dispute supplier claim</option>
       <option value="ATTESTED_INTERNAL">Internally attest inspected claim (NOT verified)</option></>:
       <><option value="REJECTED_INTERNAL">Reject GRN evidence pack</option>
        <option value="HELD_INTERNAL">Approve internal HELD pack (NO posting)</option></>}
     </select></label>
    <label className="block text-xs">Independent evidence ticket
     <input required value={evidence} maxLength={160} onChange={e=>setEvidence(e.target.value)}
      className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2"/></label>
    <label className="block text-xs">Written reason (12–1000 characters)
     <textarea required minLength={12} maxLength={1000} rows={3} value={reason}
      onChange={e=>setReason(e.target.value)}
      className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2"/></label>
    <label className="flex gap-2 text-xs text-amber-200">
     <input type="checkbox" checked={inspected} onChange={e=>setInspected(e.target.checked)}/>
     I independently inspected the cited offline document or internal quarantine evidence.
     Mandatory for internal attestation/HELD approval.</label>
    <button type="submit" disabled={busy||!verified||(canApprove&&!inspected)}
     className="bg-amber-800 rounded px-4 py-2 text-xs disabled:opacity-50">
     Record irreversible internal review</button>
   </form>}
  <p className="text-xs text-amber-200">Supplier acknowledgments are NOT externally authenticated.
   Official GRN, vendor invoice, stock release and negative-stock operations remain unavailable.</p>
 </section>;
}
