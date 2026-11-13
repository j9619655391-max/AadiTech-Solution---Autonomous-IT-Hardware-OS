import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Key={id:string;partyKind:string;supplierId:string|null;siteId:string|null;
 fingerprintSha256:string;status:string};
type Source={sourceId:string;partyId:string;partyKind:'SUPPLIER'|'WAREHOUSE';
 sourceSha256:string};
type Claim={id:string;kind:string;status:string;messageSha256:string;signatureMatched:boolean};
type Authority={publicKeysTrusted:boolean;externalPoIssued:boolean;officialGrnAuthenticated:boolean;
 availableToSell:null};
async function decode<T>(r:Response):Promise<T>{
 const v:unknown=await r.json();
 if(!r.ok)throw Error(v&&typeof v==='object'&&'error' in v?String(v.error):'Offline proof service unavailable');
 return v as T;
}
const kindOptions=['PO_ISSUANCE_ASSERTION','SUPPLIER_ACK_ASSERTION','WAREHOUSE_GRN_ASSERTION'] as const;
export function SignedProofOwnerPanel(){
 const [keys,setKeys]=useState<Key[]>([]),[sources,setSources]=useState<Source[]>([]);
 const [claims,setClaims]=useState<Claim[]>([]),[authority,setAuthority]=useState<Authority|null>(null);
 const [partyKind,setPartyKind]=useState<'SUPPLIER'|'WAREHOUSE'>('SUPPLIER');
 const [partyId,setPartyId]=useState(''),[keyB64,setKeyB64]=useState(''),[keyEvidence,setKeyEvidence]=useState('');
 const [keyId,setKeyId]=useState(''),[kind,setKind]=useState<typeof kindOptions[number]>('SUPPLIER_ACK_ASSERTION');
 const [sourceId,setSourceId]=useState(''),[reference,setReference]=useState('');
 const [docSha,setDocSha]=useState(''),[issuedAt,setIssuedAt]=useState('2026-11-12T00:00:00.000Z');
 const [signatureB64,setSignatureB64]=useState(''),[canonical,setCanonical]=useState('');
 const [password,setPassword]=useState(''),[verified,setVerified]=useState(false);
 const [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  const [k,s,c,a]=await Promise.all([
   decode<{items:Key[]}>(await authenticatedFetch('/api/proof-foundation/keys')),
   decode<{items:Source[]}>(await authenticatedFetch('/api/proof-foundation/sources')),
   decode<{items:Claim[]}>(await authenticatedFetch('/api/proof-foundation/claims')),
   decode<Authority>(await authenticatedFetch('/api/proof-foundation/authority'))]);
  setKeys(k.items);setSources(s.items);setClaims(c.items);setAuthority(a);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 const step=()=>{if(!verified||!hasRecentVerification())throw Error('Verify current password first');};
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setVerified(true);setPassword('');
   setNotice('Recent password verification active; server MFA policy still applies.');}
  catch(e){setVerified(false);setError(String(e));}finally{setBusy(false);}
 }
 async function register(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{
   step();
   if(!window.confirm('Register a SELF-REPORTED public key candidate only? Identity will NOT become trusted. Never enter a private key.'))return;
   const v=await decode<{id:string;status:string}>(await sensitiveFetch('/api/proof-foundation/keys',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({partyKind,partyId,publicKeySpkiB64:keyB64,evidenceRef:keyEvidence})}));
   setNotice('Untrusted candidate key '+v.id+' · '+v.status+'. External identity not verified.');
   setPartyId('');setKeyB64('');setKeyEvidence('');await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 const request=()=>({keyId,kind,sourceId,reference,documentSha256:docSha,issuedAt});
 async function template(){
  setBusy(true);setError('');setNotice('');setCanonical('');
  try{
   const params=new URLSearchParams(request());
   const v=await decode<{canonicalUtf8:string;messageSha256:string}>(
    await authenticatedFetch('/api/proof-foundation/message-template?'+params.toString()));
   setCanonical(v.canonicalUtf8);
   setNotice('Canonical UTF-8 message hash '+v.messageSha256+
    '. Sign EXACT bytes using your own OFFLINE Ed25519 key; do not upload private keys.');
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function claim(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');setNotice('');
  try{
   step();
   if(!window.confirm('Submit detached offline signature? Signature match proves only possession of a SELF-REGISTERED key, NOT supplier-issued PO or warehouse GRN.'))return;
   const v=await decode<{id:string;status:string;detachedSignatureMatched:boolean}>(
    await sensitiveFetch('/api/proof-foundation/claims',{
     method:'POST',headers:{'Content-Type':'application/json'},
     body:JSON.stringify({...request(),signatureB64})}));
   setNotice('Cryptographic-only claim '+v.id+' · '+v.status+
    ' · signature match '+String(v.detachedSignatureMatched)+
    '. Vendor identity and official GRN remain UNVERIFIED.');
   setSignatureB64('');setCanonical('');await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 const sourceKind=kind==='WAREHOUSE_GRN_ASSERTION'?'WAREHOUSE':'SUPPLIER';
 const sourcesFiltered=sources.filter(s=>s.partyKind===sourceKind);
 return <section className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4"
  aria-label="Offline cryptographic proof candidate owner">
  <h2 className="text-lg font-semibold">Phase 1AI · Offline signed-evidence prerequisites (UNTRUSTED)</h2>
  <p className="text-xs text-amber-200">An Ed25519 signature matching a key YOU registered does not verify who
   controls that key. There is no supplier authentication, actual PO issuance, official GRN, serial title or
   warehouse stock posting. Never enter private keys or sensitive documents into this application.</p>
  {error&&<p role="alert" className="text-rose-200 border border-rose-700 rounded p-2 text-xs">{error}</p>}
  {notice&&<p role="status" className="text-cyan-200 border border-cyan-700 rounded p-2 text-xs">{notice}</p>}
  <button type="button" disabled={busy} className="text-cyan-300 text-xs"
   onClick={()=>void refresh().catch(e=>setError(String(e)))}>Refresh candidate keys and offline evidence</button>
  <form onSubmit={verify} className="border border-slate-700 p-3 rounded flex gap-2 flex-wrap items-end">
   <label className="text-xs">Owner current password
    <input required type="password" autoComplete="current-password" value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block mt-1 bg-slate-950 border border-slate-700 rounded p-2"/></label>
   <button type="submit" disabled={busy} className="text-xs rounded bg-amber-800 px-3 py-2">Verify</button>
   <span className="text-xs text-slate-400">{verified&&hasRecentVerification()?'Step-up valid':'Step-up required'}</span>
  </form>
  <form onSubmit={register} className="border border-slate-700 p-3 rounded space-y-2">
   <h3 className="text-sm font-semibold">1. Register public-key CANDIDATE (not trusted)</h3>
   <label className="text-xs block">Party scope
    <select value={partyKind} onChange={e=>setPartyKind(e.target.value as typeof partyKind)}
     className="block mt-1 bg-slate-950 border border-slate-700 rounded p-2">
     <option value="SUPPLIER">Internal supplier</option><option value="WAREHOUSE">Internal inventory site</option>
    </select></label>
   <label className="text-xs block">Internally registered supplier/site UUID
    <input required value={partyId} onChange={e=>setPartyId(e.target.value)}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>
   <label className="text-xs block">Base64 Ed25519 PUBLIC key (X.509 SPKI DER, 44 bytes). NO PRIVATE KEYS.
    <textarea required rows={2} value={keyB64} onChange={e=>setKeyB64(e.target.value)}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>
   <label className="text-xs block">Internal evidence ticket
    <input required value={keyEvidence} onChange={e=>setKeyEvidence(e.target.value)}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>
   <button disabled={busy||!verified} className="text-xs bg-amber-800 rounded px-3 py-2">Submit UNTRUSTED key</button>
  </form>
  <div className="border border-slate-700 p-3 rounded">
   <h3 className="text-sm font-semibold">Candidate keys — externally unverified</h3>
   {keys.length===0?<p className="text-xs text-slate-400">No candidates.</p>:
    keys.map(k=><p key={k.id} className="text-xs border-t border-slate-700 py-2 break-all">
     {k.id.slice(0,14)} · {k.partyKind} · {k.status} · {k.fingerprintSha256}</p>)}
  </div>
  <div className="border border-slate-700 p-3 rounded space-y-3">
   <h3 className="text-sm font-semibold">2. Request frozen source message and sign OFFLINE</h3>
   <p className="text-xs text-amber-200">Only use a separately controlled offline signing environment.
    The signed payload explicitly says external identity verification = false.</p>
   <label className="block text-xs">Type of ASSERTION (not proof of issuance or receipt)
    <select value={kind} onChange={e=>{setKind(e.target.value as typeof kind);setSourceId('');setCanonical('');}}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2">
     {kindOptions.map(k=><option key={k} value={k}>{k}</option>)}</select></label>
   <label className="block text-xs">Reviewed-UNTRUSTED key
    <select required value={keyId} onChange={e=>{setKeyId(e.target.value);setCanonical('');}}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2">
     <option value="">Choose registered candidate</option>
     {keys.filter(k=>k.status==='REVIEWED_UNTRUSTED'&&k.partyKind===sourceKind)
      .map(k=><option key={k.id} value={k.id}>{k.id.slice(0,14)} · {k.partyKind}</option>)}
    </select></label>
   <label className="block text-xs">Immutable held evidence source ID
    <select required value={sourceId} onChange={e=>{setSourceId(e.target.value);setCanonical('');}}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2">
     <option value="">Choose internal HELD source</option>
     {sourcesFiltered.map(s=><option key={s.sourceId} value={s.sourceId}>
      {s.sourceId.slice(0,14)} · party {s.partyId.slice(0,8)}</option>)}
    </select></label>
   <label className="block text-xs">Offline assertion reference (uppercase)
    <input required value={reference} onChange={e=>{setReference(e.target.value);setCanonical('');}}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2"/></label>
   <label className="block text-xs">Offline document SHA-256 (lowercase hexadecimal, 64 chars)
    <input required minLength={64} maxLength={64} value={docSha}
     onChange={e=>{setDocSha(e.target.value);setCanonical('');}}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2 font-mono"/></label>
   <label className="block text-xs">Timestamp UTC exactly YYYY-MM-DDTHH:mm:ss.000Z
    <input required value={issuedAt} onChange={e=>{setIssuedAt(e.target.value);setCanonical('');}}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2"/></label>
   <button type="button" disabled={busy||!keyId||!sourceId}
    onClick={()=>void template()} className="bg-slate-700 rounded px-3 py-2 text-xs">
    Generate exact offline message</button>
   {canonical&&<label className="block text-xs">Canonical UTF-8 bytes to sign — NOT authenticated external proof
    <textarea readOnly rows={6} value={canonical}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2 font-mono text-xs"/></label>}
  </div>
  <form onSubmit={claim} className="border border-slate-700 p-3 rounded space-y-2">
   <h3 className="text-sm font-semibold">3. Submit detached signature only (no private key)</h3>
   <label className="text-xs block">Base64 64-byte Ed25519 signature of exact canonical message
    <textarea required rows={2} value={signatureB64} onChange={e=>setSignatureB64(e.target.value)}
     className="block mt-1 w-full bg-slate-950 border border-slate-700 rounded p-2"/></label>
   <button disabled={busy||!verified||!canonical||!signatureB64}
    className="rounded bg-amber-800 px-3 py-2 text-xs disabled:opacity-50">
    Record signature-matched UNTRUSTED claim</button>
  </form>
  <div className="border border-amber-700 p-3 rounded space-y-1">
   <h3 className="text-sm font-semibold">Signed claims (still never authentic source proof)</h3>
   {claims.map(c=><p key={c.id} className="border-t border-slate-700 py-2 text-xs">
    {c.kind} · {c.id.slice(0,12)} · {c.status} · Ed25519 match {String(c.signatureMatched)}</p>)}
   <p className="text-xs text-amber-200">Trusted keys: {String(authority?.publicKeysTrusted??false)}
    · Issued PO: {String(authority?.externalPoIssued??false)}
    · Official GRN: {String(authority?.officialGrnAuthenticated??false)}
    · Available stock: NOT AUTHORIZED.</p>
  </div>
 </section>;
}
