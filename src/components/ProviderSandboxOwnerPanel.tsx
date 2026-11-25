import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Case={id:string;pinId:string;issuerId:string;purpose:string;
 registryReference:string;signatoryReference:string;status:string};
type Cert={id:string;caseId:string;serial:string;status:string;
 leafFingerprint:string;leafKeyFingerprint:string};
async function result<T>(r:Response):Promise<T>{
 const data:unknown=await r.json();
 if(!r.ok)throw Error(data&&typeof data==='object'&&'error' in data?String(data.error):
  'Sandbox evidence request unavailable');
 return data as T;
}
export function ProviderSandboxOwnerPanel(){
 const [cases,setCases]=useState<Case[]>([]),[certs,setCerts]=useState<Cert[]>([]);
 const [password,setPassword]=useState(''),[verified,setVerified]=useState(false);
 const [pinId,setPinId]=useState(''),[issuerId,setIssuerId]=useState(''),
 [purpose,setPurpose]=useState('SUPPLIER_ACK'),[registryReference,setRegistry]=useState(''),
 [identityDoc,setIdentityDoc]=useState(''),[signatory,setSignatory]=useState(''),
 [signatoryDoc,setSignatoryDoc]=useState(''),[ticket,setTicket]=useState(''),
 [caseId,setCaseId]=useState(''),[rootPem,setRootPem]=useState(''),[leafPem,setLeafPem]=useState(''),
 [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  const [a,b]=await Promise.all([
   result<{items:Case[]}>(await authenticatedFetch('/api/provider-sandbox/cases')),
   result<{items:Cert[]}>(await authenticatedFetch('/api/provider-sandbox/certificates'))]);
  setCases(a.items);setCerts(b.items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 async function step(){
  if(!verified||!hasRecentVerification())throw Error('Recent password verification required');
 }
 async function post<T>(path:string,body:object):Promise<T>{
  await step();return result<T>(await sensitiveFetch('/api/provider-sandbox/'+path,{
   method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}));
 }
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setVerified(true);setPassword('');
   setNotice('Password verified. Server MFA and CSRF remain mandatory.');}
  catch(e){setVerified(false);setError(String(e));}finally{setBusy(false);}
 }
 async function createCase(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{
   if(!window.confirm('Create an UNVERIFIED internal corporate/signatory evidence case? This is not real KYC.'))return;
   const v=await post<{id:string;status:string}>('cases',{
    pinId,issuerId,purpose,registryReference,identityDocumentSha256:identityDoc,
    signatoryReference:signatory,signatoryDocumentSha256:signatoryDoc,evidenceRef:ticket});
   setNotice('Internal corporate case '+v.id+' · '+v.status+'. Independent review required.');
   setCaseId(v.id);await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function addCert(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{
   if(!window.confirm('Only public X509 CA and leaf certificate PEM, with NO private keys. One-hop signature evidence remains HELD.'))return;
   const v=await post<{id:string;status:string}>('certificates',{
    caseId,rootCertificatePem:rootPem,leafCertificatePem:leafPem});
   setNotice('Certificate evidence '+v.id+' · '+v.status+
    '. NOT a complete RFC5280 path, provider issuance, legal corporate proof or GRN.');
   setRootPem('');setLeafPem('');await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function ready(id:string,record=false){
  setBusy(true);setError('');
  try{
   if(record){
    const x=await post<{id:string;status:string}>('revocation-checks',{certId:id});
    setNotice('Immutable current-feed evidence '+x.id+' · '+x.status+
     ' (NO authenticated external identity or stock posting).');
   }else{
    const x=await result<{productionReady:boolean;blockers:string[]}>(
     await authenticatedFetch('/api/provider-sandbox/readiness/'+encodeURIComponent(id)));
    setNotice('Production ready: '+String(x.productionReady)+'. '+x.blockers.join('; '));
   }
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 return <section aria-label="Phase 1AM sandbox onboarding and X509 certificate evidence owner"
  className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="text-lg font-semibold">Phase 1AM · External provider sandbox evidence (HELD)</h2>
  <p className="text-xs text-amber-200">No genuine provider, registry/CA authentication or legally authorized
   signatory is connected. Only public certificates and SHA-256 document REFERENCES are stored.
   One-hop X509 signature verification is NOT complete RFC5280 certification-path, CRL/OCSP,
   certificate-policy or corporate KYC validation. Production, GRN and stock posting stay disabled.</p>
  {error&&<p role="alert" className="rounded border border-rose-700 p-2 text-xs text-rose-200">{error}</p>}
  {notice&&<p role="status" className="rounded border border-cyan-700 p-2 text-xs text-cyan-200">{notice}</p>}
  <button type="button" className="text-xs text-cyan-300" disabled={busy}
   onClick={()=>void refresh().catch(e=>setError(String(e)))}>Refresh cases and certificate evidence</button>
  <form onSubmit={verify} className="rounded border border-slate-700 p-3 flex items-end flex-wrap gap-2">
   <label className="block text-xs">Owner current password
    <input type="password" required autoComplete="current-password" value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block mt-1 rounded border border-slate-700 bg-slate-950 p-2"/></label>
   <button disabled={busy} className="rounded bg-amber-800 px-3 py-2 text-xs">Verify</button>
  </form>
  <form onSubmit={createCase} className="rounded border border-slate-700 p-3 space-y-2">
   <h3 className="text-sm font-semibold">1. Claimed organization and signatory (internal evidence only)</h3>
   <p className="text-xs text-slate-400">Use Phase 1AL independently HELD public root candidate UUID
    and Phase 1AK internally reviewed supplier/warehouse issuer UUID. Never paste raw identity documents.</p>
   {([['Pinned provider UUID',pinId,setPinId],['Claimed issuer UUID',issuerId,setIssuerId],
    ['Canonical organization registration',registryReference,setRegistry],
    ['Identity document SHA-256 (lowercase)',identityDoc,setIdentityDoc],
    ['Signatory authority ticket/reference',signatory,setSignatory],
    ['Signatory authority document SHA-256',signatoryDoc,setSignatoryDoc],
    ['Internal evidence reference',ticket,setTicket]] as const).map(([label,v,set])=>
    <label key={label} className="block text-xs">{label}
     <input required value={v} onChange={e=>set(e.target.value)}
      className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2"/></label>)}
   <label className="block text-xs">Claimed credential purpose
    <select value={purpose} onChange={e=>setPurpose(e.target.value)}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2">
     <option value="SUPPLIER_ACK">SUPPLIER_ACK</option>
     <option value="WAREHOUSE_GRN">WAREHOUSE_GRN</option></select></label>
   <button disabled={busy||!verified} className="rounded bg-amber-800 px-3 py-2 text-xs">
    Record unverified corporation/signatory case</button>
  </form>
  <div className="rounded border border-slate-700 p-3 text-xs">
   <h3 className="text-sm font-semibold">Independent review queue and case status</h3>
   {cases.map(c=><p key={c.id} className="border-t border-slate-700 py-2">
    {c.id.slice(0,15)} · {c.purpose} · {c.status} · KYC UNVERIFIED</p>)}
  </div>
  <form onSubmit={addCert} className="rounded border border-slate-700 p-3 space-y-2">
   <h3 className="text-sm font-semibold">2. Import public one-hop X509 CA and issuer leaf certificate</h3>
   <label className="block text-xs">Case UUID (independently REVIEWED_EVIDENCE_HELD)
    <select value={caseId} onChange={e=>setCaseId(e.target.value)}
     className="block mt-1 w-full rounded border border-slate-700 bg-slate-950 p-2">
     <option value="">Choose independently reviewed case</option>
     {cases.filter(c=>c.status==='REVIEWED_EVIDENCE_HELD').map(c=>
      <option key={c.id} value={c.id}>{c.id.slice(0,14)} · {c.purpose}</option>)}
    </select></label>
   <label className="block text-xs">CA PUBLIC certificate PEM (no PRIVATE key)
    <textarea rows={5} required value={rootPem} onChange={e=>setRootPem(e.target.value)}
     className="block mt-1 w-full rounded border border-slate-700 bg-slate-950 p-2 font-mono text-xs"/></label>
   <label className="block text-xs">Leaf PUBLIC certificate PEM (no PRIVATE key)
    <textarea rows={5} required value={leafPem} onChange={e=>setLeafPem(e.target.value)}
     className="block mt-1 w-full rounded border border-slate-700 bg-slate-950 p-2 font-mono text-xs"/></label>
   <button disabled={busy||!verified||!caseId} className="rounded bg-amber-800 px-3 py-2 text-xs">
    Validate pinned one-hop certificate signature and record HELD evidence</button>
  </form>
  <div className="rounded border border-slate-700 p-3 text-xs">
   <h3 className="text-sm font-semibold">3. Current provider-root signed revocation and readiness</h3>
   {certs.map(c=><div key={c.id} className="border-t border-slate-700 py-2">
    <p>{c.id.slice(0,15)} · serial {c.serial} · {c.status}</p>
    <p className="break-all">Leaf SHA-256: {c.leafFingerprint}</p>
    <button type="button" className="text-cyan-300 mr-4"
     onClick={()=>void ready(c.id)}>Recheck latest signed feed and production blockers</button>
    <button type="button" className="text-cyan-300" disabled={busy||!verified}
     onClick={()=>void ready(c.id,true)}>Record immutable internal HELD revocation check</button>
   </div>)}
  </div>
 </section>;
}
