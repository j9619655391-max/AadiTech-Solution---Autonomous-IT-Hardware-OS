import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Nom={id:string;providerCode:string;legalName:string;status:string;reviewDecision:string|null};
type Policy={id:string;nominationId:string;policyOid:string;status:string};
type Dossier={id:string;nominationId:string;registryReference:string;status:string};
async function read<T>(r:Response):Promise<T>{
 const v:unknown=await r.json();
 if(!r.ok)throw Error(v&&typeof v==='object'&&'error' in v?String(v.error):'Named provider selection unavailable');
 return v as T;
}
export function ProviderSelectionOwnerPanel(){
 const [nominations,setNominations]=useState<Nom[]>([]),[policies,setPolicies]=useState<Policy[]>([]),
 [dossiers,setDossiers]=useState<Dossier[]>([]),[password,setPassword]=useState(''),
 [verified,setVerified]=useState(false),[ticket,setTicket]=useState(''),
 [accessTicket,setAccessTicket]=useState(''),[nomId,setNomId]=useState(''),
 [policyJson,setPolicyJson]=useState(JSON.stringify({nominationId:'',certId:'',
  policyOid:'',cpsSha256:'',purpose:'SUPPLIER_ACK'},null,2)),
 [dossierJson,setDossierJson]=useState(JSON.stringify({nominationId:'',sandboxCaseId:'',
  registryReference:'',companyMasterDataSha256:'',signatoryDelegationSha256:'',
  sourceEvidenceRef:''},null,2)),
 [policyId,setPolicyId]=useState(''),[dossierId,setDossierId]=useState(''),
 [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  const [a,b,c]=await Promise.all([
   read<{items:Nom[]}>(await authenticatedFetch('/api/provider-selection/nominations')),
   read<{items:Policy[]}>(await authenticatedFetch('/api/provider-selection/policies')),
   read<{items:Dossier[]}>(await authenticatedFetch('/api/provider-selection/dossiers'))]);
  setNominations(a.items);setPolicies(b.items);setDossiers(c.items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 async function post<T>(path:string,body:object){
  if(!verified||!hasRecentVerification())throw Error('Recent password step-up required');
  return read<T>(await sensitiveFetch('/api/provider-selection/'+path,{
   method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}));
 }
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setPassword('');setVerified(true);
   setNotice('Step-up verified; privileged MFA and CSRF remain required.');}
  catch(e){setVerified(false);setError(String(e));}finally{setBusy(false);}
 }
 async function submit(path:string,body:object,warning:string){
  setBusy(true);setError('');setNotice('');
  try{
   if(!window.confirm(warning))return;
   const response=await post<{id?:string;status:string;nominationId?:string}>(path,body);
   setNotice((response.id??response.nominationId??'Internal ticket')+
    ' · '+response.status+' · external provider approval: NO');
   if(path==='nominations'&&response.id)setNomId(response.id);
   await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function check(){
  setBusy(true);setError('');
  try{
   const query=new URLSearchParams({policyId,dossierId});
   const v=await read<{productionReady:boolean;blockers:string[]}>(
    await authenticatedFetch('/api/provider-selection/readiness?'+query.toString()));
   setNotice('ProductionReady: '+String(v.productionReady)+'. '+v.blockers.join('; '));
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 return <section aria-label="Phase 1AN named external trust provider nomination"
  className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="text-lg font-semibold">Phase 1AN · Named CCA provider evaluation (HOLD)</h2>
  <p className="text-xs text-amber-200">eMudhra Limited is an India CCA-listed candidate,
   NOT a contracted or authorized provider for this supplier/warehouse workflow.
   No approved sandbox credentials, external root trust, genuine company registry verification,
   trusted CRL/OCSP, official GRN or sellable inventory exists. Never enter API secrets here.</p>
  <a className="text-cyan-300 text-xs underline" target="_blank" rel="noopener noreferrer"
   href="https://cca.gov.in/CAServicesPublic.html">Public India CCA licensed-CA reference</a>
  {error&&<p role="alert" className="text-xs text-rose-200 border border-rose-700 rounded p-2">{error}</p>}
  {notice&&<p role="status" className="text-xs text-cyan-200 border border-cyan-700 rounded p-2">{notice}</p>}
  <button type="button" disabled={busy} className="text-xs text-cyan-300"
   onClick={()=>void refresh().catch(e=>setError(String(e)))}>Refresh HELD nomination and dossier queues</button>
  <form onSubmit={verify} className="border border-slate-700 rounded p-3 flex items-end gap-2 flex-wrap">
   <label className="text-xs">Owner current password
    <input type="password" required autoComplete="current-password" value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block mt-1 bg-slate-950 border border-slate-700 rounded p-2"/></label>
   <button disabled={busy} className="bg-amber-800 rounded px-3 py-2 text-xs">Verify</button>
  </form>
  <form className="border border-slate-700 rounded p-3 space-y-2" onSubmit={e=>{
   e.preventDefault();void submit('nominations',{
    providerCode:'EMUDHRA_INDIA_CCA',nominationTicket:ticket},
    'Nominate eMudhra ONLY for evaluation? It will NOT become a verified vendor or CA root.');
  }}>
   <h3 className="font-semibold text-sm">1. Nominate eMudhra (internal shortlist only)</h3>
   <label className="block text-xs">Internal procurement/IT due-diligence ticket
    <input required value={ticket} onChange={e=>setTicket(e.target.value)}
     className="block w-full mt-1 bg-slate-950 border border-slate-700 rounded p-2"/></label>
   <button disabled={busy||!verified} className="bg-amber-800 rounded px-3 py-2 text-xs">
    Record NOMINATED_HELD</button>
  </form>
  <div className="border border-slate-700 rounded p-3 space-y-2 text-xs">
   <h3 className="font-semibold text-sm">2. Independent nomination and access-request status</h3>
   <select value={nomId} onChange={e=>setNomId(e.target.value)}
    className="block w-full mt-1 bg-slate-950 border border-slate-700 rounded p-2">
    <option value="">Choose nominated candidate</option>
    {nominations.map(n=><option key={n.id} value={n.id}>
     {n.id.slice(0,14)} · {n.legalName} · {n.reviewDecision??n.status}</option>)}
   </select>
   <label className="block text-xs">Internal sandbox-access request ticket (never an API key)
    <input value={accessTicket} onChange={e=>setAccessTicket(e.target.value)}
     className="block mt-1 w-full rounded border border-slate-700 bg-slate-950 p-2"/></label>
   <button type="button" disabled={busy||!verified||!nomId||!accessTicket}
    className="text-cyan-300" onClick={()=>void submit('access-requests',
     {nominationId:nomId,requestTicket:accessTicket},
     'Only record a WAITING_EXTERNAL ticket; no actual credential can be stored or used.')}>
    Record sandbox access request (credential status NOT_PROVIDED)</button>
  </div>
  <div className="border border-slate-700 rounded p-3 space-y-2">
   <h3 className="font-semibold text-sm">3. Sandbox certificate policy OID dry-run</h3>
   <p className="text-xs">Requires independently reviewed Phase 1AM certificate case, the exact
    provider-approved policy OID (do not invent real OIDs) and CPS SHA-256. Local OpenSSL
    one-hop policy check is available only in disposable CI/approved TLS staging, no CRL/OCSP trust.</p>
   <textarea aria-label="Policy proposal JSON" value={policyJson}
    onChange={e=>setPolicyJson(e.target.value)} rows={7}
    className="w-full bg-slate-950 border border-slate-700 rounded p-2 font-mono text-xs"/>
   <button type="button" disabled={busy||!verified}
    className="bg-amber-800 rounded px-3 py-2 text-xs" onClick={()=>void (async()=>{
     try{await submit('policies',JSON.parse(policyJson) as object,
      'Run isolated non-authorizing OpenSSL policy match? This is NOT a trusted certification path.');}
     catch(e){setError(String(e));}
    })()}>Record PROFILE_HELD</button>
   {policies.map(p=><p key={p.id} className="text-xs border-t border-slate-700 py-1">
    {p.id.slice(0,14)} · OID {p.policyOid} · {p.status}</p>)}
  </div>
  <div className="border border-slate-700 rounded p-3 space-y-2">
   <h3 className="font-semibold text-sm">4. MCA company/signatory evidence dossier</h3>
   <p className="text-xs">Only SHA-256 evidence references and original Phase 1AM claimed
    registry value. No raw KYC files; independent reviewer still cannot assert legal authority.</p>
   <textarea aria-label="MCA/company dossier JSON" value={dossierJson}
    onChange={e=>setDossierJson(e.target.value)} rows={8}
    className="w-full bg-slate-950 border border-slate-700 rounded p-2 font-mono text-xs"/>
   <button type="button" disabled={busy||!verified}
    className="bg-amber-800 rounded px-3 py-2 text-xs" onClick={()=>void (async()=>{
     try{await submit('dossiers',JSON.parse(dossierJson) as object,
      'Record document hashes as UNVERIFIED internal claims, not verified MCA corporate identity?');}
     catch(e){setError(String(e));}
    })()}>Record EVIDENCE_PENDING_EXTERNAL</button>
   {dossiers.map(d=><p key={d.id} className="text-xs border-t border-slate-700 py-1">
    {d.id.slice(0,14)} · {d.registryReference} · {d.status}</p>)}
  </div>
  <div className="border border-slate-700 rounded p-3 space-y-2 text-xs">
   <h3 className="font-semibold text-sm">5. End-to-end release blockers (always HOLD)</h3>
   <label>Reviewed policy candidate
    <select value={policyId} onChange={e=>setPolicyId(e.target.value)}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2">
     <option value="">Choose</option>
     {policies.map(p=><option key={p.id} value={p.id}>{p.id.slice(0,15)}</option>)}
    </select></label>
   <label>Reviewed company/signatory dossier
    <select value={dossierId} onChange={e=>setDossierId(e.target.value)}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2">
     <option value="">Choose</option>
     {dossiers.map(d=><option key={d.id} value={d.id}>{d.id.slice(0,15)}</option>)}
    </select></label>
   <button type="button" className="text-cyan-300" disabled={busy||!policyId||!dossierId}
    onClick={()=>void check()}>Read independently held prerequisites and production blockers</button>
  </div>
 </section>;
}
