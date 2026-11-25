import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Nom={id:string;providerCode:string;legalName:string;openedBy:string;status:string;reviewed:string|null};
type Policy={id:string;policyOid:string;cpsSha256:string;preparedBy:string;status:string;reviewed:string|null};
type Dossier={id:string;registryReference:string;preparedBy:string;masterSha:string;delegationSha:string;status:string;reviewed:string|null};
async function read<T>(r:Response):Promise<T>{
 const v:unknown=await r.json();
 if(!r.ok)throw Error(v&&typeof v==='object'&&'error' in v?String(v.error):'Independent provider review unavailable');
 return v as T;
}
type Kind='nomination'|'policy'|'dossier';
export function ProviderSelectionReviewerPanel(){
 const [nominations,setNominations]=useState<Nom[]>([]),[policies,setPolicies]=useState<Policy[]>([]),
 [dossiers,setDossiers]=useState<Dossier[]>([]);
 const [selected,setSelected]=useState<{id:string;kind:Kind;label:string}|null>(null),
 [password,setPassword]=useState(''),[verified,setVerified]=useState(false),
 [decision,setDecision]=useState('REJECTED_INTERNAL'),[reason,setReason]=useState(''),
 [evidenceRef,setEvidenceRef]=useState(''),[first,setFirst]=useState(false),
 [second,setSecond]=useState(false),[busy,setBusy]=useState(false),
 [error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  const [a,b,c]=await Promise.all([
   read<{items:Nom[]}>(await authenticatedFetch('/api/provider-selection/review/nominations')),
   read<{items:Policy[]}>(await authenticatedFetch('/api/provider-selection/review/policies')),
   read<{items:Dossier[]}>(await authenticatedFetch('/api/provider-selection/review/dossiers'))]);
  setNominations(a.items);setPolicies(b.items);setDossiers(c.items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 function choose(kind:Kind,id:string,label:string){
  setSelected({kind,id,label});setDecision('REJECTED_INTERNAL');setReason('');
  setEvidenceRef('');setFirst(false);setSecond(false);
 }
 const positive=selected?.kind==='nomination'?'REVIEWED_CANDIDATE_HELD':
  selected?.kind==='policy'?'REVIEWED_POLICY_HELD':'REVIEWED_CLAIM_HELD';
 const flags=selected?.kind==='nomination'?
  {officialListingInspected:first,contractMissingAcknowledged:second}:
  selected?.kind==='policy'?
  {policyOidInspected:first,missingCrlOcspAcknowledged:second}:
  {registrySourceInspected:first,delegationSourceInspected:second};
 const labels=selected?.kind==='nomination'?
  ['I inspected the CCA public licensed-CA listing.',
   'I acknowledge no contract, credentials, verified root or application-specific authority.']:
  selected?.kind==='policy'?
  ['I inspected exact sandbox policy OID and public CPS fingerprint.',
   'I acknowledge lack of provider approval, trusted CRL/OCSP and full production PKIX.']:
  ['I inspected offline corporate-registry reference/document SHA.',
   'I inspected offline signatory-delegation SHA; legal signatory remains UNVERIFIED.'];
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setPassword('');setVerified(true);
   setNotice('Reviewer password reverified. CSRF and MFA remain server enforced.');}
  catch(e){setVerified(false);setError(String(e));}finally{setBusy(false);}
 }
 async function decide(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{
   if(!selected||!verified||!hasRecentVerification())
    throw Error('Select item and verify current password');
   if(!window.confirm('Record one-time INTERNAL HELD/rejection only? No provider contract, legal KYC or production trust will be approved.'))return;
   const plural=selected.kind==='policy'?'policies':
    selected.kind==='dossier'?'dossiers':'nominations';
   const result=await read<{status:string}>(await sensitiveFetch(
    '/api/provider-selection/review/'+plural+'/'+encodeURIComponent(selected.id)+'/decide',{
     method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({decision,reason,evidenceRef,...flags})}));
   setNotice(result.status+' recorded; provider, KYC and production trust remain unverified.');
   setSelected(null);await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 return <section aria-label="Phase 1AN independent provider, CP and MCA dossier reviewer"
  className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="text-lg font-semibold">Phase 1AN · Independent named-provider due diligence</h2>
  <p className="text-xs text-amber-200">A licensed CA listing is NOT an approved eMudhra contract
   or sandbox API. Synthetic certificate-policy OID results are not proof of a provider-issued
   certificate. Offline MCA references and signatory hashes are not independent legal KYC.
   All positive decisions are held, never production authorization.</p>
  {error&&<p role="alert" className="rounded border border-rose-700 p-2 text-rose-200 text-xs">{error}</p>}
  {notice&&<p role="status" className="rounded border border-cyan-700 p-2 text-cyan-200 text-xs">{notice}</p>}
  <button type="button" className="text-cyan-300 text-xs" disabled={busy}
   onClick={()=>void refresh().catch(e=>setError(String(e)))}>Refresh independent review queues</button>
  <form onSubmit={verify} className="rounded border border-slate-700 p-3 flex items-end gap-2 flex-wrap">
   <label className="block text-xs">Reviewer current password
    <input required type="password" autoComplete="current-password" value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block mt-1 rounded bg-slate-950 border border-slate-700 p-2"/></label>
   <button disabled={busy} className="rounded bg-amber-800 px-3 py-2 text-xs">Verify</button>
  </form>
  <div className="grid md:grid-cols-3 gap-3 text-xs">
   <div className="border border-slate-700 rounded p-3 space-y-2">
    <h3 className="font-semibold text-sm">Named provider shortlist</h3>
    {nominations.map(n=><div key={n.id} className="border-t border-slate-700 py-1">
     <p>{n.legalName} · {n.reviewed??n.status}</p>
     {!n.reviewed&&n.status==='NOMINATED_HELD'&&
      <button type="button" className="text-cyan-300"
       onClick={()=>choose('nomination',n.id,n.legalName)}>
       Review CCA listing only</button>}
    </div>)}
   </div>
   <div className="border border-slate-700 rounded p-3 space-y-2">
    <h3 className="font-semibold text-sm">Synthetic certificate policy OID</h3>
    {policies.map(p=><div key={p.id} className="border-t border-slate-700 py-1">
     <p>OID {p.policyOid} · {p.reviewed??p.status}</p>
     {!p.reviewed&&<button type="button" className="text-cyan-300"
      onClick={()=>choose('policy',p.id,'Policy OID '+p.policyOid)}>
      Review missing PKIX, CRL and issuance</button>}
    </div>)}
   </div>
   <div className="border border-slate-700 rounded p-3 space-y-2">
    <h3 className="font-semibold text-sm">MCA/signatory internal dossier</h3>
    {dossiers.map(d=><div key={d.id} className="border-t border-slate-700 py-1">
     <p>{d.registryReference} · {d.reviewed??d.status}</p>
     {!d.reviewed&&<button type="button" className="text-cyan-300"
      onClick={()=>choose('dossier',d.id,'Claimed registration '+d.registryReference)}>
      Inspect registry and delegated signatory hashes</button>}
    </div>)}
   </div>
  </div>
  {selected&&<form onSubmit={decide} className="border border-amber-700 rounded p-3 space-y-2">
   <h3 className="font-semibold text-sm">{selected.label}</h3>
   <label className="block text-xs">One-time independent decision
    <select value={decision} onChange={e=>setDecision(e.target.value)}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2">
     <option value="REJECTED_INTERNAL">REJECTED_INTERNAL</option>
     <option value={positive}>{positive} (NOT provider approval)</option>
    </select></label>
   <label className="block text-xs">Detailed rationale
    <textarea required minLength={12} maxLength={1000} value={reason}
     onChange={e=>setReason(e.target.value)} rows={3}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2"/></label>
   <label className="block text-xs">Independent evidence reference
    <input required value={evidenceRef} onChange={e=>setEvidenceRef(e.target.value)}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2"/></label>
   <label className="flex items-start gap-2 text-amber-200 text-xs">
    <input type="checkbox" checked={first} onChange={e=>setFirst(e.target.checked)}/>{labels[0]}</label>
   <label className="flex items-start gap-2 text-amber-200 text-xs">
    <input type="checkbox" checked={second} onChange={e=>setSecond(e.target.checked)}/>{labels[1]}</label>
   <button disabled={busy||!verified||(decision===positive&&(!first||!second))}
    className="rounded bg-amber-800 px-3 py-2 text-xs disabled:opacity-50">
    Record internal-only review</button>
  </form>}
 </section>;
}
