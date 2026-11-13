import React,{useCallback,useEffect,useState} from 'react';
import {authenticatedFetch,sensitiveFetch,verifyCurrentPassword,hasRecentVerification} from '../services/authClient';
type Packet={id:string;nominationId:string;status:string;contractState:string;credentialState:string};
type Trial={id:string;packetId:string;policyId:string;policyOid:string;status:string};
type Artifact={id:string;trialId:string;artifactType:'CRL'|'OCSP';status:string};
type Mca={id:string;packetId:string;dossierId:string;status:string};
async function read<T>(response:Response):Promise<T>{
 const data:unknown=await response.json();
 if(!response.ok)throw Error(data&&typeof data==='object'&&'error' in data?String(data.error):
  'Sandbox onboarding unavailable');return data as T;
}
export function ProviderOnboardingOwnerPanel(){
 const [packets,setPackets]=useState<Packet[]>([]),[trials,setTrials]=useState<Trial[]>([]),
 [artifacts,setArtifacts]=useState<Artifact[]>([]),[mca,setMca]=useState<Mca[]>([]),
 [password,setPassword]=useState(''),[verified,setVerified]=useState(false),
 [nomId,setNomId]=useState(''),[contractSha,setContractSha]=useState(''),
 [onboardingRef,setOnboardingRef]=useState(''),[scopeRef,setScopeRef]=useState(''),
 [packetId,setPacketId]=useState(''),[policyId,setPolicyId]=useState(''),
 [trialId,setTrialId]=useState(''),[artifactType,setArtifactType]=useState<'CRL'|'OCSP'>('CRL'),
 [artifactB64,setArtifactB64]=useState(''),[dossierId,setDossierId]=useState(''),
 [mcaSha,setMcaSha]=useState(''),[mandateSha,setMandateSha]=useState(''),
 [mcaTicket,setMcaTicket]=useState(''),[mcaId,setMcaId]=useState(''),
 [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 const refresh=useCallback(async()=>{
  const [a,b,c,d]=await Promise.all([
   read<{items:Packet[]}>(await authenticatedFetch('/api/provider-onboarding/packets')),
   read<{items:Trial[]}>(await authenticatedFetch('/api/provider-onboarding/trials')),
   read<{items:Artifact[]}>(await authenticatedFetch('/api/provider-onboarding/revocations')),
   read<{items:Mca[]}>(await authenticatedFetch('/api/provider-onboarding/mca-evidence'))]);
  setPackets(a.items);setTrials(b.items);setArtifacts(c.items);setMca(d.items);
 },[]);
 useEffect(()=>{void refresh().catch(e=>setError(String(e)));},[refresh]);
 async function submit(path:string,body:object){
  setBusy(true);setError('');
  try{
   if(!verified||!hasRecentVerification())throw Error('Recent password verification required');
   if(!window.confirm('Store INTERNAL HELD evidence only? No actual provider contract, API credentials, KYC, GRN or stock permission will be established.'))return;
   const v=await read<{id:string;status:string}>(await sensitiveFetch(
    '/api/provider-onboarding/'+path,{method:'POST',
     headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}));
   setNotice(v.status+' · '+v.id+' · external identity and sandbox credentials remain UNVERIFIED');
   if(path==='packets')setPacketId(v.id);
   if(path==='trials')setTrialId(v.id);
   if(path==='mca-evidence')setMcaId(v.id);
   setArtifactB64('');await refresh();
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 async function verify(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError('');
  try{await verifyCurrentPassword(password);setVerified(true);setPassword('');
   setNotice('Password reverified; server-enforced MFA and CSRF remain required.');}
  catch(e){setError(String(e));setVerified(false);}finally{setBusy(false);}
 }
 async function readiness(){
  setBusy(true);setError('');
  try{
   const qs=new URLSearchParams({trialId,mcaId});
   const v=await read<{productionReady:boolean;blockers:string[]}>(
    await authenticatedFetch('/api/provider-onboarding/readiness?'+qs.toString()));
   setNotice('ProductionReady='+String(v.productionReady)+'. '+v.blockers.join(' | '));
  }catch(e){setError(String(e));}finally{setBusy(false);}
 }
 const field=(name:string,value:string,set:(x:string)=>void)=><label className="block text-xs" key={name}>{name}
  <input required value={value} onChange={e=>set(e.target.value)}
   className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2"/></label>;
 return <section className="rounded-xl border border-amber-800 bg-slate-900 p-5 space-y-4"
  aria-label="Phase 1AO approved sandbox prerequisites">
  <h2 className="text-lg font-semibold">Phase 1AO · eMudhra sandbox prerequisite evidence (HOLD)</h2>
  <p className="text-xs text-amber-200">No real eMudhra agreement, approved sandbox credential,
   authenticated RCAI/eMudhra chain, authoritative CRL/OCSP or verified MCA signer available.
   Cryptographic testing uses PUBLIC certificate files in disposable isolated environments.
   Do not enter secrets, private keys or original identity documents.</p>
  {error&&<p role="alert" className="border border-rose-700 text-rose-200 rounded p-2 text-xs">{error}</p>}
  {notice&&<p role="status" className="border border-cyan-700 text-cyan-200 rounded p-2 text-xs">{notice}</p>}
  <button type="button" className="text-cyan-300 text-xs" disabled={busy}
   onClick={()=>void refresh().catch(e=>setError(String(e)))}>Refresh HELD evidence</button>
  <form onSubmit={verify} className="border border-slate-700 rounded p-3 flex items-end gap-3 flex-wrap">
   <label className="block text-xs">Owner current password
    <input type="password" autoComplete="current-password" required value={password}
     onChange={e=>setPassword(e.target.value)}
     className="block mt-1 rounded bg-slate-950 border border-slate-700 p-2"/></label>
   <button disabled={busy} className="bg-amber-800 rounded px-3 py-2 text-xs">Verify</button>
  </form>
  <form onSubmit={e=>{e.preventDefault();void submit('packets',{
   nominationId:nomId,contractDocumentSha256:contractSha,
   providerOnboardingRef:onboardingRef,sandboxScopeRef:scopeRef});}}
   className="border border-slate-700 rounded p-3 space-y-2">
   <h3 className="text-sm font-semibold">1. Provider agreement and sandbox scope — UNVERIFIED</h3>
   {field('Phase 1AN reviewed nomination UUID',nomId,setNomId)}
   {field('Contract claim SHA-256 only (NOT a validated contract)',contractSha,setContractSha)}
   {field('Internal onboarding evidence reference',onboardingRef,setOnboardingRef)}
   {field('Sandbox scope request ticket (NOT an API key)',scopeRef,setScopeRef)}
   <button disabled={busy||!verified} className="bg-amber-800 px-3 py-2 text-xs rounded">
    Record PENDING_INTERNAL packet</button>
   {packets.map(p=><p key={p.id} className="text-xs border-t border-slate-700 pt-2">
    {p.id.slice(0,16)} · {p.status} · {p.contractState} · credentials {p.credentialState}</p>)}
  </form>
  <form onSubmit={e=>{e.preventDefault();void submit('trials',{packetId,policyId});}}
   className="border border-slate-700 rounded p-3 space-y-2">
   <h3 className="text-sm font-semibold">2. Offline certificate policy trial — dual-reviewed packet required</h3>
   {field('Packet UUID (both LEGAL + SECURITY independent HELD)',packetId,setPacketId)}
   {field('Phase 1AN independently reviewed policy UUID',policyId,setPolicyId)}
   <button disabled={busy||!verified} className="bg-amber-800 rounded px-3 py-2 text-xs">
    Record OFFLINE_CRYPTO_HELD trial</button>
   {trials.map(t=><p key={t.id} className="text-xs border-t border-slate-700 pt-2">
    {t.id.slice(0,16)} · {t.policyOid} · {t.status}</p>)}
  </form>
  <form onSubmit={e=>{e.preventDefault();void submit('revocations',
   {trialId,artifactType,artifactDerB64:artifactB64});}}
   className="border border-slate-700 rounded p-3 space-y-2">
   <h3 className="text-sm font-semibold">3. Offline issuer-signed CRL / OCSP evidence</h3>
   {field('Offline trial UUID',trialId,setTrialId)}
   <label className="block text-xs">Artifact type
    <select value={artifactType} onChange={e=>setArtifactType(e.target.value as 'CRL'|'OCSP')}
     className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2">
     <option value="CRL">CRL — CA-signed DER</option>
     <option value="OCSP">OCSP — responder-signed DER</option></select></label>
   <label className="block text-xs">Base64 DER (PUBLIC CRL/OCSP, max 64 KiB; no private data)
    <textarea required value={artifactB64} onChange={e=>setArtifactB64(e.target.value)}
     rows={4} className="block mt-1 w-full rounded bg-slate-950 border border-slate-700 p-2 font-mono text-xs"/></label>
   <button disabled={busy||!verified} className="bg-amber-800 rounded px-3 py-2 text-xs">
    Verify offline cryptographic artifact only</button>
   {artifacts.map(a=><p key={a.id} className="text-xs border-t border-slate-700 pt-2">
    {a.artifactType} · {a.id.slice(0,16)} · {a.status}</p>)}
  </form>
  <form onSubmit={e=>{e.preventDefault();void submit('mca-evidence',{packetId,dossierId,
   mcaMasterDataSha256:mcaSha,signatoryMandateSha256:mandateSha,verificationTicket:mcaTicket});}}
   className="border border-slate-700 rounded p-3 space-y-2">
   <h3 className="text-sm font-semibold">4. MCA and authorized signer — hashes only / NOT authenticated</h3>
   {field('Original Phase 1AN reviewed dossier UUID',dossierId,setDossierId)}
   {field('MCA master-data evidence SHA-256',mcaSha,setMcaSha)}
   {field('Signatory delegation evidence SHA-256',mandateSha,setMandateSha)}
   {field('Independent verification reference (NOT legal approval)',mcaTicket,setMcaTicket)}
   <button disabled={busy||!verified} className="bg-amber-800 rounded px-3 py-2 text-xs">
    Record PENDING_EXTERNAL evidence</button>
   {mca.map(x=><p key={x.id} className="text-xs border-t border-slate-700 pt-2">
    {x.id.slice(0,16)} · {x.status}</p>)}
  </form>
  <div className="border border-slate-700 rounded p-3 text-xs space-y-2">
   <h3 className="text-sm font-semibold">5. End-to-end independent HELD check</h3>
   {field('Internally reviewed MCA record UUID',mcaId,setMcaId)}
   <button type="button" disabled={busy||!trialId||!mcaId}
    className="text-cyan-300" onClick={()=>void readiness()}>
    Recheck signed CRL, OCSP, latest provider candidate revocation and all production blockers</button>
  </div>
 </section>;
}