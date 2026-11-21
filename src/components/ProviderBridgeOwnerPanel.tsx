import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Pin={id:string;providerCode:string;providerOrigin:string;rootFingerprint:string;
 tlsFingerprint:string;status:string;frozen:string|null};
type Credential={id:string;pinId:string;issuerId:string;purpose:string;status:string};
type Feed={id:string;pinId:string;sequenceNumber:number};
async function decode<T>(r:Response):Promise<T>{
 const raw:unknown=await r.json();
 if(!r.ok)throw Error(raw&&typeof raw==='object'&&'error' in raw?String(raw.error):'Pinned provider evidence service unavailable');
 return raw as T;
}
function utc(n:number){return new Date(Math.floor((Date.now()+n)/1000)*1000).toISOString();}
export function ProviderBridgeOwnerPanel(){
 const [pins,setPins]=useState<Pin[]>([]),[credentials,setCredentials]=useState<Credential[]>([]),
 [feeds,setFeeds]=useState<Feed[]>([]),[selectedPin,setSelectedPin]=useState(''),
 [password,setPassword]=useState(''),[verified,setVerified]=useState(false),
 [evidence,setEvidence]=useState(''),[freezeReason,setFreezeReason]=useState(''),
 [freezeTicket,setFreezeTicket]=useState(''),
 [credentialJson,setCredentialJson]=useState(JSON.stringify({
  pinId:'',issuerId:'',purpose:'SUPPLIER_ACK',validFrom:utc(-60_000),validUntil:utc(3_600_000)},null,2)),
 [feedJson,setFeedJson]=useState(JSON.stringify({
  pinId:'',sequenceNumber:1,publishedAt:utc(-60_000),
  validUntil:utc(3_600_000),revokedFingerprints:[]},null,2)),
 [signature,setSignature]=useState(''),[canonical,setCanonical]=useState(''),
 [kind,setKind]=useState<'credential'|'feed'>('credential'),
 [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  const [a,b,c]=await Promise.all([
   decode<{items:Pin[]}>(await authenticatedFetch('/api/provider-bridge/pins')),
   decode<{items:Credential[]}>(await authenticatedFetch('/api/provider-bridge/credentials')),
   decode<{items:Feed[]}>(await authenticatedFetch('/api/provider-bridge/feeds'))]);
  setPins(a.items);setCredentials(b.items);setFeeds(c.items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 function step(){
  if(!verified||!hasRecentVerification())throw Error('Reverify current password for privileged operation');
 }
 async function post<T>(path:string,body:object){
  step();
  return decode<T>(await sensitiveFetch('/api/provider-bridge/'+path,{
   method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}));
 }
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setPassword('');setVerified(true);
   setNotice('Recent owner password check passed; server MFA still enforced.');}
  catch(e){setVerified(false);setError(String(e));}finally{setBusy(false);}
 }
 async function createPin(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{
   if(!window.confirm('Enroll a PUBLIC root already configured OUTSIDE the app? This does NOT verify provider ownership.'))return;
   const v=await post<{id:string;status:string}>('pins',{evidenceRef:evidence});
   setNotice('Server-preprovisioned root CANDIDATE '+v.id+' · '+v.status+
    '. Still not externally authenticated.');setEvidence('');await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function prepare(nextKind:'credential'|'feed'){
  setBusy(true);setError('');setCanonical('');setSignature('');
  try{
   const input=JSON.parse(nextKind==='credential'?credentialJson:feedJson) as object;
   const path=nextKind==='credential'?'credential-template':'feed-template';
   const v=await post<{canonicalUtf8:string;messageSha256:string}>(path,input);
   setKind(nextKind);setCanonical(v.canonicalUtf8);
   setNotice('Exact UTF-8 SHA-256: '+v.messageSha256+
    '. Sign only in independently controlled OFFLINE signing environment. Do NOT upload private keys.');
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function submit(){
  setBusy(true);setError('');
  try{
   if(!canonical||!signature)throw Error('Generate a template and provide offline signature first');
   if(!window.confirm('Record root-signed INTERNAL HELD evidence only? External organization verification will remain FALSE.'))return;
   const input=JSON.parse(kind==='credential'?credentialJson:feedJson) as object;
   const path=kind==='credential'?'credentials':'feeds';
   const v=await post<{id:string;status?:string}>(path,{...input,signatureB64:signature});
   setNotice('Recorded HELD candidate '+v.id+' · externally authenticated: NO.');
   setSignature('');setCanonical('');await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function inspect(id:string){
  setBusy(true);setError('');
  try{
   const v=await decode<{productionReady:boolean;cryptographicSourceConsistent:boolean;blockers:string[]}>(
    await authenticatedFetch('/api/provider-bridge/readiness/'+encodeURIComponent(id)));
   setNotice('Cryptographic source consistent: '+String(v.cryptographicSourceConsistent)+
    '; productionReady: '+String(v.productionReady)+'. '+v.blockers.join(' | '));
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function freeze(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{
   if(!window.confirm('Permanently FREEZE root '+selectedPin+'? All related credential evidence will fail closed.'))return;
   await post('pins/'+encodeURIComponent(selectedPin)+'/freeze',
    {reason:freezeReason,evidenceRef:freezeTicket});
   setNotice('Provider root permanently FROZEN; no trust or operational stock enabled.');
   setFreezeReason('');setFreezeTicket('');await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function preview(){
  setBusy(true);setError('');
  try{
   const v=await post<{previewOnly:boolean;productionReady:boolean}>('feeds/pull-pinned-preview',
    {pinId:selectedPin});
   setNotice('Pinned HTTPS preview validated. Imported: NO. Production ready: '+
    String(v.productionReady)+'. Authenticated corporate authority: NO.');
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 return <section aria-label="Phase 1AL provider-root prerequisites owner"
  className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4">
  <h2 className="text-lg font-semibold">Phase 1AL · Server-pinned trust-provider bridge (RELEASE HOLD)</h2>
  <p className="text-xs text-amber-200">Only separately configured PUBLIC root/TLS SPKI pins can be enrolled.
   Root ownership, corporate registration, credential issuance and revocation publisher have NOT been
   independently verified. Transport is read-only and DISABLED unless explicitly authorized for isolated staging.
   Never enter PRIVATE signing keys, API secrets or original confidential documents.</p>
  {error&&<p role="alert" className="border border-rose-700 text-rose-200 rounded p-2 text-xs">{error}</p>}
  {notice&&<p role="status" className="border border-cyan-700 text-cyan-200 rounded p-2 text-xs">{notice}</p>}
  <button type="button" onClick={()=>void refresh().catch(e=>setError(String(e)))}
   className="text-xs text-cyan-300">Refresh pinned provider evidence</button>
  <form onSubmit={verify} className="border border-slate-700 rounded p-3 flex items-end gap-2 flex-wrap">
   <label className="text-xs block">Owner current password
    <input type="password" required autoComplete="current-password" value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block rounded bg-slate-950 border border-slate-700 p-2 mt-1"/></label>
   <button disabled={busy} className="rounded bg-amber-800 px-3 py-2 text-xs">Verify</button>
  </form>
  <form onSubmit={createPin} className="border border-slate-700 rounded p-3 space-y-2">
   <h3 className="text-sm font-semibold">1. Enroll preprovisioned environment PUBLIC root candidate</h3>
   <label className="block text-xs">Independent internal root-approval evidence ticket
    <input required value={evidence} onChange={e=>setEvidence(e.target.value)}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>
   <button disabled={busy||!verified} className="rounded bg-amber-800 px-3 py-2 text-xs">
    Enroll HELD root candidate (from server config only)</button>
  </form>
  <div className="border border-slate-700 rounded p-3 text-xs space-y-2">
   <h3 className="text-sm font-semibold">Root and separate TLS pin inventory</h3>
   {pins.map(p=><p key={p.id} className="border-t border-slate-700 py-2 break-all">
    {p.id.slice(0,14)} · {p.providerCode} · {p.status} · {p.frozen?'FROZEN':'EXTERNALLY UNVERIFIED'}
    · root {p.rootFingerprint} · TLS {p.tlsFingerprint}</p>)}
   <label className="block text-xs">Selected root for read-only preview and emergency freeze
    <select value={selectedPin} onChange={e=>setSelectedPin(e.target.value)}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2">
     <option value="">Choose candidate</option>
     {pins.filter(p=>!p.frozen).map(p=><option key={p.id} value={p.id}>
      {p.id.slice(0,15)} · {p.providerCode}</option>)}
    </select></label>
   <button type="button" disabled={busy||!verified||!selectedPin}
    className="text-xs text-cyan-300" onClick={()=>void preview()}>
    Read-only pinned HTTPS revocation PREVIEW (staging opt-in required)</button>
  </div>
  <div className="border border-slate-700 rounded p-3 space-y-3">
   <h3 className="text-sm font-semibold">2. Root-signed organizational credential candidate</h3>
   <p className="text-xs">Enter HELD provider pin UUID, independently reviewed Phase 1AK issuer UUID,
    purpose and UTC validity. These are unverified external identity CLAIMS.</p>
   <textarea aria-label="Credential request JSON" value={credentialJson} rows={7}
    onChange={e=>{setCredentialJson(e.target.value);setCanonical('');}}
    className="block w-full rounded p-2 bg-slate-950 border border-slate-700 font-mono text-xs"/>
   <button type="button" disabled={busy||!verified} onClick={()=>void prepare('credential')}
    className="rounded bg-slate-700 px-3 py-2 text-xs">Generate CREDENTIAL bytes for offline signing</button>
  </div>
  <div className="border border-slate-700 rounded p-3 space-y-3">
   <h3 className="text-sm font-semibold">3. Root-signed cumulative revocation feed (UNTRUSTED)</h3>
   <p className="text-xs">First sequence 1, then +1, TTL at most 24h, sorted unique SHA-256 fingerprints.
    All prior revocations must remain in every new feed.</p>
   <textarea aria-label="Revocation feed JSON" rows={7} value={feedJson}
    onChange={e=>{setFeedJson(e.target.value);setCanonical('');}}
    className="block w-full rounded p-2 bg-slate-950 border border-slate-700 font-mono text-xs"/>
   <button type="button" disabled={busy||!verified} onClick={()=>void prepare('feed')}
    className="rounded bg-slate-700 px-3 py-2 text-xs">Generate REVOCATION bytes for offline signing</button>
  </div>
  {canonical&&<div className="border border-amber-700 rounded p-3 space-y-3">
   <h3 className="text-sm font-semibold">Sign exact UTF-8 message OFFLINE: {kind}</h3>
   <textarea readOnly rows={7} value={canonical}
    className="block w-full rounded p-2 bg-slate-950 border border-slate-700 font-mono text-xs"/>
   <label className="block text-xs">Detached Ed25519 signature — base64 of 64 bytes, not a private key
    <textarea required value={signature} onChange={e=>setSignature(e.target.value)}
     className="block mt-1 w-full rounded p-2 bg-slate-950 border border-slate-700 font-mono text-xs"/></label>
   <button type="button" disabled={busy||!verified||!signature} onClick={()=>void submit()}
    className="rounded bg-amber-800 px-3 py-2 text-xs">Record {kind} as INTERNAL HELD evidence</button>
  </div>}
  <div className="border border-slate-700 rounded p-3 text-xs space-y-2">
   <h3 className="text-sm font-semibold">Reviewed credential and signed-feed status</h3>
   {credentials.map(c=><p key={c.id} className="border-t border-slate-700 py-2">
    {c.id.slice(0,15)} · {c.purpose} · {c.status}
    <button type="button" className="block text-cyan-300" onClick={()=>void inspect(c.id)}>
     Check cryptographic evidence and production blockers</button></p>)}
   <p>Imported candidate feed sequences: {feeds.map(f=>f.sequenceNumber).join(', ')||'None'}</p>
  </div>
  <form onSubmit={freeze} className="border border-rose-800 rounded p-3 space-y-2">
   <h3 className="text-sm font-semibold text-rose-200">Emergency irreversible root FREEZE</h3>
   <p className="text-xs text-rose-200">Uses selected provider above. Does not revoke certificates in a real
    external provider; it immediately denies all LOCAL future proof acceptance.</p>
   <textarea required minLength={12} maxLength={1000} value={freezeReason}
    onChange={e=>setFreezeReason(e.target.value)} placeholder="Detailed incident reason"
    className="block w-full rounded bg-slate-950 border border-slate-700 p-2 text-xs"/>
   <input required value={freezeTicket} onChange={e=>setFreezeTicket(e.target.value)}
    placeholder="Internal security ticket"
    className="block w-full rounded bg-slate-950 border border-slate-700 p-2 text-xs"/>
   <button disabled={busy||!verified||!selectedPin||!freezeReason||!freezeTicket}
    className="rounded bg-rose-800 px-3 py-2 text-xs">Permanently freeze selected root</button>
  </form>
 </section>;
}
