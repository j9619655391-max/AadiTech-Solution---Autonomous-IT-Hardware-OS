import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Issuer={id:string;partyKind:string;partyId:string;fingerprint:string;
 organizationRegistration:string;status:string;frozen:string|null};
type Attest={id:string;issuerId:string;keyId:string;purpose:string;status:string};
type Feed={id:string;issuerId:string;sequenceNumber:number;expiresAt:string};
async function json<T>(r:Response):Promise<T>{
 const v:unknown=await r.json();
 if(!r.ok)throw Error(v&&typeof v==='object'&&'error' in v?String(v.error):'External trust service unavailable');
 return v as T;
}
const time=(offset:number)=>new Date(Math.floor((Date.now()+offset)/1000)*1000).toISOString();
export function ExternalTrustOwnerPanel(){
 const [issuers,setIssuers]=useState<Issuer[]>([]),[attest,setAttest]=useState<Attest[]>([]),
 [feeds,setFeeds]=useState<Feed[]>([]),[password,setPassword]=useState(''),
 [verified,setVerified]=useState(false),[busy,setBusy]=useState(false),
 [error,setError]=useState(''),[notice,setNotice]=useState('');
 const [partyKind,setPartyKind]=useState<'SUPPLIER'|'WAREHOUSE'>('SUPPLIER'),
 [partyId,setPartyId]=useState(''),[organizationRegistration,setOrg]=useState(''),
 [issuerSpkiB64,setSpki]=useState(''),[evidenceRef,setEvidence]=useState('');
 const [issuerId,setIssuerId]=useState(''),[keyId,setKeyId]=useState(''),
 [purpose,setPurpose]=useState<'SUPPLIER_ACK'|'WAREHOUSE_GRN'>('SUPPLIER_ACK'),
 [validFrom,setValidFrom]=useState(time(-60_000)),[validUntil,setValidUntil]=useState(time(3_600_000)),
 [authoritySignature,setAuthoritySignature]=useState('');
 const [sequenceNumber,setSequenceNumber]=useState(1),[issuedAt,setIssuedAt]=useState(time(-60_000)),
 [expiresAt,setExpiresAt]=useState(time(3_600_000)),[revoked,setRevoked]=useState(''),
 [feedSignature,setFeedSignature]=useState(''),[canonical,setCanonical]=useState(''),
 [templateType,setTemplateType]=useState<'AUTHORITY'|'REVOCATION'>('AUTHORITY'),
 [freezeReason,setFreezeReason]=useState(''),[freezeTicket,setFreezeTicket]=useState('');
 const refresh=useCallback(async()=>{
  const [a,b,c]=await Promise.all([
   json<{items:Issuer[]}>(await authenticatedFetch('/api/external-trust/issuers')),
   json<{items:Attest[]}>(await authenticatedFetch('/api/external-trust/attestations')),
   json<{items:Feed[]}>(await authenticatedFetch('/api/external-trust/revocations'))]);
  setIssuers(a.items);setAttest(b.items);setFeeds(c.items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 const step=()=>{if(!verified||!hasRecentVerification())throw Error('Recent password step-up required');};
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setPassword('');setVerified(true);
   setNotice('Password reverified. Server MFA and CSRF still required.');}
  catch(e){setVerified(false);setError(String(e));}finally{setBusy(false);}
 }
 async function post<T>(path:string,body:object):Promise<T>{
  step();return json<T>(await sensitiveFetch('/api/external-trust/'+path,
   {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}));
 }
 async function register(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{
   if(!window.confirm('Register an unverified issuer PUBLIC-key candidate only? No legal identity will be certified.'))return;
   const v=await post<{id:string;status:string}>('issuers',
    {partyKind,partyId,organizationRegistration,issuerSpkiB64,evidenceRef});
   setNotice('Issuer candidate '+v.id+' · '+v.status+' · external authentication NO.');
   setSpki('');setEvidence('');await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 const authorityRequest=()=>({issuerId,keyId,purpose,validFrom,validUntil});
 const revocationRequest=()=>({issuerId,sequenceNumber,issuedAt,expiresAt,
  revokedFingerprints:revoked.split(',').map(s=>s.trim()).filter(Boolean).sort()});
 async function prepare(which:'AUTHORITY'|'REVOCATION'){
  setBusy(true);setError('');setCanonical('');
  try{
   const path=which==='AUTHORITY'?'authority-template':'revocation-template';
   const req=which==='AUTHORITY'?authorityRequest():revocationRequest();
   const v=await post<{canonicalUtf8:string}>(path,req);
   setCanonical(v.canonicalUtf8);setTemplateType(which);
   setNotice('Sign these EXACT UTF-8 bytes OFFLINE; never upload private keys. This issuer is UNVERIFIED.');
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function submitAuthority(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{
   if(templateType!=='AUTHORITY'||!canonical)throw Error('Generate signed authority template first');
   if(!window.confirm('Record only an internally HELD organizational assertion, not verified external authority?'))return;
   const v=await post<{id:string;status:string}>('attestations',
    {...authorityRequest(),signatureB64:authoritySignature});
   setNotice('Signed candidate authority '+v.id+' · '+v.status+' · external verification NO.');
   setCanonical('');setAuthoritySignature('');await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function submitFeed(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{
   if(templateType!=='REVOCATION'||!canonical)throw Error('Generate signed revocation template first');
   if(!window.confirm('Import cumulative signed revocations? New/previous blocked fingerprints cannot be un-revoked.'))return;
   const v=await post<{id:string;sequenceNumber:number}>('revocations',
    {...revocationRequest(),signatureB64:feedSignature});
   setNotice('Candidate-signed revocations '+v.id+' · sequence '+v.sequenceNumber+
    '. Publisher identity still UNVERIFIED.');
   setCanonical('');setFeedSignature('');await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function freeze(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{
   step();if(!window.confirm('Permanently FREEZE untrusted issuer '+issuerId+
    '? All related future evidence will be rejected.'))return;
   await post('issuers/'+encodeURIComponent(issuerId)+'/freeze',
    {reason:freezeReason,evidenceRef:freezeTicket});
   setNotice('Issuer permanently frozen. No re-activation endpoint exists.');
   setFreezeReason('');setFreezeTicket('');await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function inspect(id:string){
  setBusy(true);setError('');
  try{
   const v=await json<{cryptographicallyConsistentInternalEvidence:boolean;
    productionReady:boolean;blockers:string[]}>(await authenticatedFetch(
    '/api/external-trust/readiness/'+encodeURIComponent(id)));
   setNotice('Internal cryptography coherent: '+String(v.cryptographicallyConsistentInternalEvidence)+
    '; productionReady: '+String(v.productionReady)+'. '+v.blockers.join('; '));
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 const eligible=issuers.filter(i=>i.status==='REVIEWED_HELD'&&!i.frozen);
 return <section aria-label="Phase 1AK external issuer trust prerequisites owner"
  className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="text-lg font-semibold">Phase 1AK · External organizational trust prerequisites (HELD)</h2>
  <p className="text-xs text-amber-200">These are owner-entered issuer candidates and offline-signed claims,
   NOT legally authenticated external supplier/warehouse authorities. No independent root provider,
   verified organization, issued PO, authenticated GRN or live inventory posting is connected.</p>
  {error&&<p role="alert" className="border border-rose-700 rounded p-2 text-rose-200 text-xs">{error}</p>}
  {notice&&<p role="status" className="border border-cyan-700 rounded p-2 text-cyan-200 text-xs">{notice}</p>}
  <button type="button" disabled={busy} className="text-cyan-300 text-xs"
   onClick={()=>void refresh().catch(e=>setError(String(e)))}>Refresh untrusted issuer state</button>
  <form onSubmit={verify} className="rounded border border-slate-700 p-3 flex gap-2 flex-wrap items-end">
   <label className="block text-xs">Current owner password
    <input required type="password" autoComplete="current-password" value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block bg-slate-950 border border-slate-700 rounded p-2 mt-1"/></label>
   <button disabled={busy} className="rounded bg-amber-800 px-3 py-2 text-xs">Verify</button>
  </form>
  <form onSubmit={register} className="border border-slate-700 rounded p-3 space-y-2">
   <h3 className="font-semibold text-sm">1. Register issuer PUBLIC-key candidate (UNTRUSTED)</h3>
   <select value={partyKind} onChange={e=>setPartyKind(e.target.value as typeof partyKind)}
    className="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs">
    <option value="SUPPLIER">Internal supplier</option><option value="WAREHOUSE">Internal warehouse site</option>
   </select>
   {([['partyId','Internal supplier/site UUID',partyId,setPartyId],
    ['org','Claimed organization registration',organizationRegistration,setOrg],
    ['evidence','Internal source ticket',evidenceRef,setEvidence]] as const)
    .map(([key,label,v,change])=><label key={key} className="block text-xs">
     {label}<input required value={v} onChange={e=>change(e.target.value)}
      className="block mt-1 w-full p-2 rounded bg-slate-950 border border-slate-700"/></label>)}
   <label className="block text-xs">Ed25519 issuer PUBLIC key: 44-byte SPKI DER base64 (never PRIVATE key)
    <textarea required rows={2} value={issuerSpkiB64} onChange={e=>setSpki(e.target.value)}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>
   <button disabled={busy||!verified} className="rounded bg-amber-800 px-3 py-2 text-xs">
    Register issuer CANDIDATE</button>
  </form>
  <div className="border border-slate-700 rounded p-3 text-xs">
   <h3 className="font-semibold text-sm">Issuer candidates (not external trust anchors)</h3>
   {issuers.map(i=><p key={i.id} className="border-t border-slate-700 py-2 break-all">
    {i.id.slice(0,15)} · {i.partyKind} · {i.status} · {i.frozen?'FROZEN':'UNVERIFIED'} · {i.fingerprint}</p>)}
  </div>
  <div className="border border-slate-700 rounded p-3 space-y-2">
   <h3 className="font-semibold text-sm">2. Offline-sign internal organizational authorization claim</h3>
   <label className="block text-xs">Independently internally reviewed issuer
    <select value={issuerId} onChange={e=>{setIssuerId(e.target.value);setCanonical('');}}
     className="block w-full bg-slate-950 border border-slate-700 rounded p-2 mt-1">
     <option value="">Choose issuer</option>{eligible.map(i=><option key={i.id} value={i.id}>
      {i.id.slice(0,15)} · {i.partyKind}</option>)}
    </select></label>
   <label className="block text-xs">Phase 1AI key UUID with Phase 1AJ independently reviewed possession
    <input value={keyId} onChange={e=>{setKeyId(e.target.value);setCanonical('');}}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>
   <select value={purpose} onChange={e=>{setPurpose(e.target.value as typeof purpose);setCanonical('');}}
    className="w-full rounded p-2 bg-slate-950 border border-slate-700 text-xs">
    <option value="SUPPLIER_ACK">SUPPLIER_ACK claim</option><option value="WAREHOUSE_GRN">WAREHOUSE_GRN claim</option></select>
   {([['Valid from (.000Z)',validFrom,setValidFrom],['Valid until (.000Z)',validUntil,setValidUntil]] as const)
    .map(([label,v,change])=><label key={label} className="block text-xs">{label}
     <input required value={v} onChange={e=>{change(e.target.value);setCanonical('');}}
      className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>)}
   <button type="button" onClick={()=>void prepare('AUTHORITY')} disabled={busy||!verified||!issuerId||!keyId}
    className="rounded bg-slate-700 px-3 py-2 text-xs">Generate AUTHORITY canonical UTF-8</button>
   <form onSubmit={submitAuthority} className="space-y-2">
    <label className="block text-xs">Detached issuer Ed25519 signature (64-byte base64)
     <textarea required value={authoritySignature} onChange={e=>setAuthoritySignature(e.target.value)}
      className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2"/></label>
    <button disabled={busy||!verified||templateType!=='AUTHORITY'||!canonical}
     className="rounded bg-amber-800 px-3 py-2 text-xs">Record HELD cryptographic-only authority</button>
   </form>
  </div>
  <form onSubmit={submitFeed} className="border border-slate-700 rounded p-3 space-y-2">
   <h3 className="font-semibold text-sm">3. Signed cumulative revocation distribution (issuer still UNVERIFIED)</h3>
   <label className="block text-xs">Monotonic issuer-local sequence, starting at 1
    <input type="number" min={1} step={1} required value={sequenceNumber}
     onChange={e=>{setSequenceNumber(Number(e.target.value));setCanonical('');}}
     className="block mt-1 bg-slate-950 border border-slate-700 rounded p-2"/></label>
   {([['Issued at (.000Z)',issuedAt,setIssuedAt],['Expires within 24h (.000Z)',expiresAt,setExpiresAt]] as const)
    .map(([label,v,change])=><label key={label} className="block text-xs">{label}
     <input required value={v} onChange={e=>{change(e.target.value);setCanonical('');}}
      className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>)}
   <label className="block text-xs">Cumulative revoked fingerprints, comma-separated; leave blank for none
    <textarea value={revoked} onChange={e=>{setRevoked(e.target.value);setCanonical('');}}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>
   <button type="button" onClick={()=>void prepare('REVOCATION')} disabled={busy||!verified||!issuerId}
    className="rounded bg-slate-700 px-3 py-2 text-xs">Generate REVOCATION canonical UTF-8</button>
   <label className="block text-xs">64-byte Ed25519 issuer signature of exact revocation message
    <textarea required value={feedSignature} onChange={e=>setFeedSignature(e.target.value)}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>
   <button disabled={busy||!verified||templateType!=='REVOCATION'||!canonical}
    className="rounded bg-amber-800 px-3 py-2 text-xs">Import signed UNTRUSTED revocation bundle</button>
  </form>
  {canonical&&<label className="block text-xs">Exact UTF-8 message to sign OFFLINE ({templateType}); never upload private keys
   <textarea readOnly rows={6} value={canonical}
    className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2 font-mono text-xs"/></label>}
  <div className="border border-slate-700 rounded p-3 text-xs">
   <h3 className="font-semibold text-sm">4. Internal authority readiness (always production HOLD)</h3>
   {attest.map(a=><div key={a.id} className="border-t border-slate-700 py-2">
    {a.id.slice(0,15)} · {a.purpose} · {a.status}
    <button type="button" className="block text-cyan-300" onClick={()=>void inspect(a.id)}>
     Recheck issuer signature, current revocation feed and official blockers</button></div>)}
   <p>Signed bundle history: {feeds.map(f=>f.sequenceNumber+' ['+f.issuerId.slice(0,7)+']').join(', ')||'none'}</p>
  </div>
  <form onSubmit={freeze} className="border border-rose-800 rounded p-3 space-y-2">
   <h3 className="font-semibold text-sm text-rose-200">Emergency permanent issuer FREEZE</h3>
   <p className="text-xs text-rose-200">Uses selected issuer above. Immediately blocks every associated authority and revocation check.</p>
   <textarea required minLength={12} maxLength={1000} value={freezeReason}
    onChange={e=>setFreezeReason(e.target.value)} placeholder="Incident / suspected compromise reason"
    className="w-full rounded p-2 bg-slate-950 border border-slate-700 text-xs"/>
   <input required value={freezeTicket} onChange={e=>setFreezeTicket(e.target.value)}
    placeholder="Internal incident ticket" className="w-full rounded p-2 bg-slate-950 border border-slate-700 text-xs"/>
   <button disabled={busy||!verified||!issuerId||!freezeReason||!freezeTicket}
    className="rounded bg-rose-800 px-3 py-2 text-xs">Irreversibly freeze issuer</button>
  </form>
 </section>;
}
