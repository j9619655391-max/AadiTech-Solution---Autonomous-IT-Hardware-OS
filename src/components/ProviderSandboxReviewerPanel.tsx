import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Case={id:string;openedBy:string;purpose:string;registryReference:string;
 identityDocumentSha256:string;signatoryReference:string;signatoryDocumentSha256:string;
 status:string;corporateState:string;signatoryState:string};
type Cert={id:string;caseId:string;importedBy:string;leafFingerprint:string;
 leafKeyFingerprint:string;leafSerial:string;status:string;reviewState:string|null};
type CertDetail={certificateId:string;caseId:string;rootCertificateSha256:string;
 leafCertificateSha256:string;leafSpkiSha256:string;serial:string;
 validFrom:string;validUntil:string;oneHopSignatureMatched:boolean;
 fullRfc5280PathValidated:boolean;legalCorporateIdentityVerified:boolean};
async function decode<T>(r:Response):Promise<T>{
 const v:unknown=await r.json();
 if(!r.ok)throw Error(v&&typeof v==='object'&&'error' in v?String(v.error):'Sandbox review unavailable');
 return v as T;
}
export function ProviderSandboxReviewerPanel(){
 const [cases,setCases]=useState<Case[]>([]),[certs,setCerts]=useState<Cert[]>([]);
 const [currentCase,setCurrentCase]=useState<Case|null>(null),
 [currentCert,setCurrentCert]=useState<CertDetail|null>(null);
 const [password,setPassword]=useState(''),[verified,setVerified]=useState(false),
 [decision,setDecision]=useState('REJECTED_INTERNAL'),[reason,setReason]=useState(''),
 [evidenceRef,setEvidence]=useState(''),[inspection,setInspection]=useState(false),
 [secondInspection,setSecondInspection]=useState(false),
 [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  const [a,b]=await Promise.all([
   decode<{items:Case[]}>(await authenticatedFetch('/api/provider-sandbox/review/cases')),
   decode<{items:Cert[]}>(await authenticatedFetch('/api/provider-sandbox/review/certificates'))]);
  setCases(a.items);setCerts(b.items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 function clear(){setDecision('REJECTED_INTERNAL');setReason('');setEvidence('');
  setInspection(false);setSecondInspection(false);}
 function chooseCase(c:Case){setCurrentCase(c);setCurrentCert(null);clear();}
 async function chooseCert(id:string){
  setBusy(true);setError('');
  try{
   const v=await decode<CertDetail>(await authenticatedFetch(
    '/api/provider-sandbox/review/certificates/'+encodeURIComponent(id)));
   setCurrentCert(v);setCurrentCase(null);clear();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setVerified(true);setPassword('');
   setNotice('Reviewer password verified; privileged MFA remains server-enforced.');}
  catch(e){setVerified(false);setError(String(e));}finally{setBusy(false);}
 }
 async function decide(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{
   if(!verified||!hasRecentVerification())throw Error('Recent password verification required');
   if(!currentCase&&!currentCert)throw Error('Select evidence first');
   if(!window.confirm('Record one-time internal HELD/rejection only? No corporate KYC, approved signatory or official GRN will be certified.'))return;
   const isCase=Boolean(currentCase),key=isCase?currentCase!.id:currentCert!.certificateId;
   const path=(isCase?'cases/':'certificates/')+encodeURIComponent(key)+'/decide';
   const body={decision,reason,evidenceRef,...(isCase?
    {registryInspected:inspection,signatoryInspected:secondInspection}:
    {certificateInspected:inspection,policyGapsAcknowledged:secondInspection})};
   const v=await decode<{status:string}>(await sensitiveFetch(
    '/api/provider-sandbox/review/'+path,{
     method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}));
   setNotice(v.status+' · independent internal evidence only; external identity remains UNVERIFIED.');
   setCurrentCase(null);setCurrentCert(null);await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 const approved=currentCase?'REVIEWED_EVIDENCE_HELD':'REVIEWED_CRYPTO_HELD';
 return <section aria-label="Independent Phase 1AM corporate identity and X509 sandbox reviewer"
  className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="text-lg font-semibold">Phase 1AM · Independent corporate/signatory & X509 evidence review</h2>
  <p className="text-xs text-amber-200">Claims and public X509 certificates are independently INSPECTED,
   but the real business registry, provider-issued identity and legal signatory authority remain
   unverified. Positive decisions are INTERNAL HELD only. One-hop certificate checks are not complete
   PKIX certificate-policy, EKU, CRL/OCSP or production validation.</p>
  {error&&<p role="alert" className="rounded border border-rose-700 p-2 text-xs text-rose-200">{error}</p>}
  {notice&&<p role="status" className="rounded border border-cyan-700 p-2 text-xs text-cyan-200">{notice}</p>}
  <button type="button" disabled={busy} className="text-xs text-cyan-300"
   onClick={()=>void refresh().catch(e=>setError(String(e)))}>Refresh reviewer queues</button>
  <form onSubmit={verify} className="rounded border border-slate-700 p-3 flex gap-2 flex-wrap items-end">
   <label className="block text-xs">Independent reviewer current password
    <input required type="password" autoComplete="current-password" value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block mt-1 rounded bg-slate-950 border border-slate-700 p-2"/></label>
   <button disabled={busy} className="rounded bg-amber-800 px-3 py-2 text-xs">Verify</button>
  </form>
  <div className="grid md:grid-cols-2 gap-3">
   <div className="rounded border border-slate-700 p-3 text-xs">
    <h3 className="text-sm font-semibold">Internal claimed corporate/signatory cases</h3>
    {cases.map(c=><div key={c.id} className="border-t border-slate-700 py-2">
     <p>{c.id.slice(0,14)} · {c.purpose} · {c.status}</p>
     <p>Registry claim: {c.registryReference}</p>
     {c.status==='PENDING_INTERNAL'&&
      <button type="button" className="text-cyan-300" onClick={()=>chooseCase(c)}>
       Inspect independent identity/signatory evidence claims</button>}
    </div>)}
   </div>
   <div className="rounded border border-slate-700 p-3 text-xs">
    <h3 className="text-sm font-semibold">One-hop pinned CA X509 certificate evidence</h3>
    {certs.map(c=><div key={c.id} className="border-t border-slate-700 py-2">
     <p>{c.id.slice(0,14)} · {c.status} · {c.reviewState??'AWAITING REVIEW'}</p>
     <p className="break-all">Leaf cert SHA-256: {c.leafFingerprint}</p>
     {!c.reviewState&&<button type="button" className="text-cyan-300"
      onClick={()=>void chooseCert(c.id)}>Reverify CA, issuer SPKI, date and certificate signature</button>}
    </div>)}
   </div>
  </div>
  {currentCase&&<div className="rounded border border-amber-700 p-3 text-xs space-y-2">
   <h3 className="font-semibold text-sm">Claimed organization and representative</h3>
   <p>Original owner: {currentCase.openedBy}</p>
   <p>Original registration: {currentCase.registryReference}</p>
   <p className="break-all">Identity document SHA-256: {currentCase.identityDocumentSha256}</p>
   <p>Signatory authority claim: {currentCase.signatoryReference}</p>
   <p className="break-all">Signatory document SHA-256: {currentCase.signatoryDocumentSha256}</p>
   <p className="text-amber-200">These hashes and claimed references are not independent KYC.</p>
  </div>}
  {currentCert&&<div className="rounded border border-amber-700 p-3 text-xs space-y-2">
   <h3 className="font-semibold text-sm">Pinned root-to-leaf mathematical evidence</h3>
   <p>Leaf serial: {currentCert.serial}</p>
   <p>Valid: {currentCert.validFrom} to {currentCert.validUntil}</p>
   <p className="break-all">Root certificate SHA-256: {currentCert.rootCertificateSha256}</p>
   <p className="break-all">Leaf certificate SHA-256: {currentCert.leafCertificateSha256}</p>
   <p>One-hop signature valid: {String(currentCert.oneHopSignatureMatched)}</p>
   <p>Full RFC5280 path validated: {String(currentCert.fullRfc5280PathValidated)}</p>
   <p>Corporate registry independently verified: {String(currentCert.legalCorporateIdentityVerified)}</p>
  </div>}
  {(currentCase||currentCert)&&<form onSubmit={decide}
   className="rounded border border-slate-700 p-3 space-y-2">
   <label className="block text-xs">Independent internal decision
    <select value={decision} onChange={e=>setDecision(e.target.value)}
     className="block mt-1 w-full rounded border border-slate-700 bg-slate-950 p-2">
     <option value="REJECTED_INTERNAL">REJECTED_INTERNAL</option>
     <option value={approved}>{approved} (never legal approval)</option>
    </select></label>
   <label className="block text-xs">Written independent reason (12–1000 chars)
    <textarea required minLength={12} maxLength={1000} value={reason}
     onChange={e=>setReason(e.target.value)} rows={3}
     className="block mt-1 w-full rounded border border-slate-700 bg-slate-950 p-2"/></label>
   <label className="block text-xs">Independent internal evidence reference
    <input required value={evidenceRef} onChange={e=>setEvidence(e.target.value)}
     className="block mt-1 w-full rounded border border-slate-700 bg-slate-950 p-2"/></label>
   <label className="flex gap-2 text-xs text-amber-200">
    <input type="checkbox" checked={inspection} onChange={e=>setInspection(e.target.checked)}/>
    {currentCase?'I inspected claimed corporate registration evidence only.':
     'I revalidated public X509 certificates and pinned one-hop Ed25519 signature.'}</label>
   <label className="flex gap-2 text-xs text-amber-200">
    <input type="checkbox" checked={secondInspection}
     onChange={e=>setSecondInspection(e.target.checked)}/>
    {currentCase?'I inspected claimed signatory delegation evidence only.':
     'I acknowledge missing complete RFC5280 policy, CRL/OCSP and real provider authentication.'}</label>
   <button disabled={busy||!verified||(decision===approved&&(!inspection||!secondInspection))}
    className="rounded bg-amber-800 px-3 py-2 text-xs disabled:opacity-50">
    Record internal HELD/rejected review</button>
  </form>}
 </section>;
}
