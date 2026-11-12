import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Packet={id:string;nominationId:string;owner:string;contractDigest:string;onboardingRef:string;status:string;reviewCount:number};
type Artifact={id:string;trialId:string;artifactType:string;sha256:string;owner:string;reviewDecision:string|null};
type Mca={id:string;packetId:string;dossierId:string;owner:string;mcaDigest:string;signerDigest:string;status:string;reviewDecision:string|null};
type Selected={id:string;kind:'packet'|'artifact'|'mca';name:string};
async function parse<T>(r:Response):Promise<T>{
 const x:unknown=await r.json();
 if(!r.ok)throw Error(x&&typeof x==='object'&&'error' in x?String(x.error):'Independent review unavailable');
 return x as T;
}
export function ProviderOnboardingReviewerPanel(){
 const [packets,setPackets]=useState<Packet[]>([]),[artifacts,setArtifacts]=useState<Artifact[]>([]),
 [mca,setMca]=useState<Mca[]>([]),[chosen,setChosen]=useState<Selected|null>(null),
 [password,setPassword]=useState(''),[verified,setVerified]=useState(false),
 [reviewRole,setReviewRole]=useState<'LEGAL'|'SECURITY'>('LEGAL'),
 [decision,setDecision]=useState('REJECTED_INTERNAL'),[reason,setReason]=useState(''),
 [ticket,setTicket]=useState(''),[first,setFirst]=useState(false),[second,setSecond]=useState(false),
 [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  const [a,b,c]=await Promise.all([
   parse<{items:Packet[]}>(await authenticatedFetch('/api/provider-onboarding/review/packets')),
   parse<{items:Artifact[]}>(await authenticatedFetch('/api/provider-onboarding/review/revocations')),
   parse<{items:Mca[]}>(await authenticatedFetch('/api/provider-onboarding/review/mca-evidence'))]);
  setPackets(a.items);setArtifacts(b.items);setMca(c.items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 function pick(kind:Selected['kind'],id:string,name:string){
  setChosen({kind,id,name});setDecision('REJECTED_INTERNAL');
  setReason('');setTicket('');setFirst(false);setSecond(false);
 }
 const positive=chosen?.kind==='artifact'?'CRYPTO_REVIEWED_HELD':'INSPECTED_HELD';
 const labels=chosen?.kind==='packet'?
  ['I inspected only an internal contract claim, NOT provider contract authenticity.',
   'I acknowledge no real eMudhra sandbox credentials or active connection.']:
  chosen?.kind==='artifact'?
  ['I acknowledge issuer/CRL/OCSP publisher identity remains unverified.',
   'This is a signed offline mathematical test, NOT trusted live revocation.']:
  ['I acknowledge official MCA corporate identity is unverified.',
   'I acknowledge authorized legal signatory identity is unverified.'];
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setPassword('');setVerified(true);
   setNotice('Independent reviewer password verified; privileged MFA is still required.');}
  catch(e){setVerified(false);setError(String(e));}finally{setBusy(false);}
 }
 async function decide(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{
   if(!chosen||!verified||!hasRecentVerification())throw Error('Recent reviewer password and evidence selection required');
   if(!window.confirm('Commit one-time INTERNAL HELD/rejection? This CANNOT authenticate provider, MCA, signer or live revocation.'))return;
   const part=chosen.kind==='packet'?'packets':chosen.kind==='artifact'?'revocations':'mca-evidence';
   const body={decision,reason,evidenceRef:ticket,...(chosen.kind==='packet'?
    {reviewRole,noExternalContractAcknowledged:first,noLiveCredentialsAcknowledged:second}:
    chosen.kind==='artifact'?{issuerProvenanceMissingAcknowledged:first}:
    {externalMcaAuthenticationMissingAcknowledged:first,signatoryAuthorityMissingAcknowledged:second})};
   const result=await parse<{status:string}>(await sensitiveFetch(
    '/api/provider-onboarding/review/'+part+'/'+encodeURIComponent(chosen.id)+'/decide',
    {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}));
   setNotice(result.status+' recorded; real eMudhra, legal company and stock remain UNVERIFIED.');
   setChosen(null);await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 return <section aria-label="Phase 1AO legal, security, revocation and MCA reviewer"
  className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="text-lg font-semibold">Phase 1AO · Independent legal/security and offline evidence review</h2>
  <p className="text-xs text-amber-200">Two DIFFERENT REVIEWER identities must inspect provider packet
   as LEGAL and SECURITY. This records missing external credentials, NOT approval. Signed offline
   CRL/OCSP and MCA hash reviews cannot certify a real issuer, legal signatory, official GRN
   or production stock. Rejection and each review role are one-time.</p>
  {error&&<p role="alert" className="text-xs border border-rose-700 text-rose-200 rounded p-2">{error}</p>}
  {notice&&<p role="status" className="text-xs border border-cyan-700 text-cyan-200 rounded p-2">{notice}</p>}
  <button type="button" className="text-xs text-cyan-300" disabled={busy}
   onClick={()=>void refresh().catch(e=>setError(String(e)))}>Refresh independent queues</button>
  <form onSubmit={verify} className="border border-slate-700 rounded p-3 flex items-end gap-2 flex-wrap">
   <label className="block text-xs">Reviewer password
    <input required type="password" value={password} autoComplete="current-password"
     onChange={e=>setPassword(e.target.value)}
     className="block mt-1 rounded bg-slate-950 border border-slate-700 p-2"/></label>
   <button disabled={busy} className="bg-amber-800 rounded px-3 py-2 text-xs">Verify</button>
  </form>
  <div className="grid md:grid-cols-3 gap-3 text-xs">
   <div className="border border-slate-700 rounded p-3">
    <h3 className="text-sm font-semibold">Provider packet dual reviews</h3>
    {packets.map(p=><div key={p.id} className="border-t border-slate-700 py-2">
     <p>{p.id.slice(0,15)} · {p.status} · {p.reviewCount} / 2 reviews</p>
     <p className="break-all">Claim digest: {p.contractDigest}</p>
     {p.status==='PENDING_INTERNAL'&&<button type="button" className="text-cyan-300"
      onClick={()=>pick('packet',p.id,'Provider evidence '+p.id.slice(0,12))}>Legal or security review</button>}
    </div>)}
   </div>
   <div className="border border-slate-700 rounded p-3">
    <h3 className="text-sm font-semibold">Signed offline CRL and OCSP</h3>
    {artifacts.map(a=><div key={a.id} className="border-t border-slate-700 py-2">
     <p>{a.artifactType} · {a.id.slice(0,14)} · {a.reviewDecision??'UNREVIEWED'}</p>
     <p className="break-all">DER SHA-256: {a.sha256}</p>
     {!a.reviewDecision&&<button type="button" className="text-cyan-300"
      onClick={()=>pick('artifact',a.id,'Offline '+a.artifactType)}>Inspect signature provenance gaps</button>}
    </div>)}
   </div>
   <div className="border border-slate-700 rounded p-3">
    <h3 className="text-sm font-semibold">MCA + signatory claim</h3>
    {mca.map(d=><div key={d.id} className="border-t border-slate-700 py-2">
     <p>{d.id.slice(0,14)} · {d.status} · {d.reviewDecision??'UNREVIEWED'}</p>
     <p className="break-all">Company SHA-256: {d.mcaDigest}</p>
     <p className="break-all">Mandate SHA-256: {d.signerDigest}</p>
     {!d.reviewDecision&&<button type="button" className="text-cyan-300"
      onClick={()=>pick('mca',d.id,'MCA/signatory document evidence')}>Review only claimed hashes</button>}
    </div>)}
   </div>
  </div>
  {chosen&&<form onSubmit={decide} className="border border-amber-700 rounded p-3 space-y-2">
   <h3 className="font-semibold text-sm">{chosen.name}</h3>
   {chosen.kind==='packet'&&<label className="block text-xs">Independent role
    <select value={reviewRole} onChange={e=>setReviewRole(e.target.value as 'LEGAL'|'SECURITY')}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2">
     <option value="LEGAL">LEGAL — internal document/contract review</option>
     <option value="SECURITY">SECURITY — keys/credential scope review</option>
    </select></label>}
   <label className="block text-xs">Decision
    <select value={decision} onChange={e=>setDecision(e.target.value)}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2">
     <option value="REJECTED_INTERNAL">REJECTED_INTERNAL</option>
     <option value={positive}>{positive} — no external authentication</option>
    </select></label>
   <label className="block text-xs">Detailed review rationale
    <textarea required minLength={12} maxLength={1000} value={reason} rows={3}
     onChange={e=>setReason(e.target.value)}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2"/></label>
   <label className="block text-xs">Internal evidence ticket
    <input required value={ticket} onChange={e=>setTicket(e.target.value)}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2"/></label>
   <label className="flex gap-2 text-xs text-amber-200">
    <input type="checkbox" checked={first} onChange={e=>setFirst(e.target.checked)}/>{labels[0]}</label>
   {chosen.kind!=='artifact'&&<label className="flex gap-2 text-xs text-amber-200">
    <input type="checkbox" checked={second} onChange={e=>setSecond(e.target.checked)}/>{labels[1]}</label>}
   <button disabled={busy||!verified||(decision===positive&&(!first||(chosen.kind!=='artifact'&&!second)))}
    className="bg-amber-800 rounded px-3 py-2 text-xs disabled:opacity-50">
    Record one-time HELD / rejection</button>
  </form>}
 </section>;
}