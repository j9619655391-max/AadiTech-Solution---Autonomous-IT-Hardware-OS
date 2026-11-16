import {createHash,sign} from 'node:crypto';
import {fixture as bbFixture,now} from './phase1bbFixture.mjs';
import {phase1AzAssessReadiness} from '../../scripts/lib/phase1AzExternalReadiness.mjs';
import {ANCHOR_PURPOSE,phase1AyInclusionLeafHash}
 from '../../scripts/lib/phase1AyWitnessArchiveRecovery.mjs';
import {BA_WITNESS_PURPOSE,phase1BaWitnessBytes}
 from '../../scripts/lib/phase1BaAcceptanceEvidence.mjs';

const hash=(...chunks)=>createHash('sha256').update(Buffer.concat(chunks)).digest();
const leaf=x=>hash(Buffer.from([0]),x);
const node=(a,b)=>hash(Buffer.from([1]),a,b);
function pivot(n){let p=1;while(p*2<n)p*=2;return p;}
export function root(items){
 if(items.length===1)return leaf(items[0]);
 const p=pivot(items.length);
 return node(root(items.slice(0,p)),root(items.slice(p)));
}
function inclusion(index,items){
 if(items.length===1)return [];
 const p=pivot(items.length);
 return index<p?[...inclusion(index,items.slice(0,p)),root(items.slice(p))]:
  [...inclusion(index-p,items.slice(p)),root(items.slice(0,p))];
}
function subproof(m,items,b){
 if(m===items.length)return b?[]:[root(items)];
 const p=pivot(items.length);
 return m<=p?[...subproof(m,items.slice(0,p),b),root(items.slice(p))]:
  [...subproof(m-p,items.slice(p),false),root(items.slice(0,p))];
}
const hex=b=>b.toString('hex');
export function bcFixture(logRef='bc-log-checkpoint-001',source=null){
 const f=source??bbFixture(logRef),a=f.azPacket.archive;
 const first={schemaVersion:1,purpose:ANCHOR_PURPOSE,
  logRef:a.logRef,checkpointReceiptSha256:a.checkpointReceiptSha256,
  archiveObjectSha256:a.archiveObjectSha256,treeSize:1,leafIndex:0,
  rootSha256:'a'.repeat(64),issuedAt:'2026-11-16T16:00:00.000Z',
  expiresAt:'2026-11-16T19:00:00.000Z',releaseDecision:'HOLD'};
 const leaves=[phase1AyInclusionLeafHash(first),
  ...Array.from({length:12},(_,i)=>Buffer.from('BC append-only trial leaf '+i))];
 function make(oldSize=2,newSize=3,customLeaves=leaves){
  if(newSize>customLeaves.length||oldSize>newSize||oldSize<1)
   throw Error('1BC test fixture invalid sizes');
  const oldLeaves=customLeaves.slice(0,oldSize),newLeaves=customLeaves.slice(0,newSize);
  const oldRoot=hex(root(oldLeaves)),newRoot=hex(root(newLeaves));
  const path=subproof(oldSize,newLeaves,true).map(hex);
  const observations=f.actors.slice(0,2).map((actor,i)=>{
   const w=f.azPacket.witnesses[i];
   const pin={role:'WITNESS',reviewerRef:actor.pin.sourceRef,
    authorityRef:actor.pin.authorityRef,keyId:actor.pin.keyId,
    publicKeyPem:actor.pin.publicKeyPem,publicKeySha256:actor.pin.publicKeySha256};
   const common={schemaVersion:1,purpose:BA_WITNESS_PURPOSE,
    packetSha256:phase1AzAssessReadiness(f.azPacket,{now}).packetSha256,
    witnessRef:w.witnessRef,organizationRef:w.organizationRef,
    administrativeAuthorityRef:w.administrativeAuthorityRef,
    logRef:a.logRef,checkpointReceiptSha256:a.checkpointReceiptSha256,
    archiveObjectSha256:a.archiveObjectSha256,leafIndex:0,
    expiresAt:'2026-11-16T19:00:00.000Z',releaseDecision:'HOLD'};
   const previous={...common,treeSize:oldSize,rootSha256:oldRoot,
    observedAt:'2026-11-16T16:20:00.000Z'};
   const current={...common,treeSize:newSize,rootSha256:newRoot,
    observedAt:'2026-11-16T17:00:00.000Z'};
   const snap=(body,items)=>({body,signature:{
    reviewerRef:pin.reviewerRef,keyId:pin.keyId,
    signatureBase64:sign(null,phase1BaWitnessBytes(body),actor.privateKey).toString('base64')
   },inclusionProofSha256:inclusion(0,items).map(hex)});
   return {pin,previous:snap(previous,oldLeaves),
    current:snap(current,newLeaves),consistencyProofSha256:path};
  });
  return {azPacket:f.azPacket,observations,now};
 }
 return {azPacket:f.azPacket,actors:f.actors,leaves,make,now};
}
