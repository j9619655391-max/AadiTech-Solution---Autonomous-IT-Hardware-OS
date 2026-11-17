import {createHash,createSign} from 'node:crypto';
import {mkdtempSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {candidateRemotePacketDigest,type CandidateRemoteExpected}
 from '../server/commercialIntegrity/quoteRemoteEvidence';
import {candidateRootCertificateDigest,type CandidateProviderBytePacket,
 type CandidateByteExpected,type CandidateWormBytes,type CandidateDrBytes,
 type CandidateCheckpointBytes}
 from '../server/commercialIntegrity/quoteProviderBytes';
import {bqPacketFixture,bqResignCapture,bqExpectedFixture}
 from './bq-remote-fixtures';

// All certificates/keys are ephemeral, GENERATED on disposable test runner.
// No CA or private key is checked into Git; never implies eMudhra/CCA identity.
const folder=mkdtempSync(join(tmpdir(),'aaditech-br-synthetic-pki-'));
process.on('exit',()=>{try{rmSync(folder,{recursive:true,force:true});}catch{}});
const run=(...args:string[])=>execFileSync('openssl',args,
 {cwd:folder,stdio:['ignore','pipe','pipe']});
run('req','-x509','-newkey','rsa:2048','-sha256','-nodes',
 '-keyout','root.key','-out','root.crt','-days','3650',
 '-subj','/CN=BR Ephemeral Synthetic Root',
 '-addext','basicConstraints=critical,CA:TRUE',
 '-addext','keyUsage=critical,keyCertSign,cRLSign');
run('req','-newkey','rsa:2048','-nodes','-keyout','leaf.key',
 '-out','leaf.csr','-subj','/CN=provider-fixture.invalid');
writeFileSync(join(folder,'leaf.ext'),
 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'+
 'subjectAltName=DNS:provider-fixture.invalid\nextendedKeyUsage=serverAuth\n');
run('x509','-req','-in','leaf.csr','-CA','root.crt','-CAkey','root.key',
 '-CAcreateserial','-out','leaf.crt','-days','365','-sha256',
 '-extfile','leaf.ext');
export const brRootPem=readFileSync(join(folder,'root.crt'),'utf8');
export const brLeafPem=readFileSync(join(folder,'leaf.crt'),'utf8');
const brLeafKey=readFileSync(join(folder,'leaf.key'),'utf8');
export const brRootSha=candidateRootCertificateDigest(brRootPem);
export const brOrigin='https://provider-fixture.invalid/';
export const brNow=new Date(Date.now()+3000);
export const brHex=(char:string)=>char.repeat(64);
export const brClone=<T>(x:T):T=>structuredClone(x);
export const brCrlDer=Buffer.from([0x30,0x06,0x02,0x01,0x01,0x02,0x01,0x02]);
export const brOcspDer=Buffer.from([0x30,0x06,0x02,0x01,0x03,0x02,0x01,0x04]);
const sha=(b:Buffer)=>createHash('sha256').update(b).digest('hex');
export const brCrlSha=sha(brCrlDer),brOcspSha=sha(brOcspDer);
export function brFixture(
 bqExpected:CandidateRemoteExpected=bqExpectedFixture(),
 challengeSha256=brHex('e'),now=brNow){
 const worm:CandidateWormBytes={
  format:'aaditech-quote-worm-candidate-v1',quoteId:bqExpected.quoteId,
  objectId:'br-synthetic-locked-object',
  retentionUntil:'2029-11-17T15:00:00.000Z',
  deniedOverwrite:true,deniedDelete:true,state:'SIMULATED_ONLY'
 };
 const dr:CandidateDrBytes={
  format:'aaditech-quote-dr-candidate-v1',quoteId:bqExpected.quoteId,
  sequence:bqExpected.bmSequence,bmReceiptSha256:bqExpected.bmReceiptSha256,
  sourceSha256:bqExpected.sourceSha256,
  restoredAt:new Date(now.getTime()-60000).toISOString(),
  operatorId:'br-operator-synthetic',witnessId:'br-witness-synthetic',
  rtoSeconds:300,rpoSeconds:200,state:'SIMULATED_ONLY'
 };
 const wormBytes=Buffer.from(JSON.stringify(worm));
 const drBytes=Buffer.from(JSON.stringify(dr));
 let bq=bqPacketFixture(bqExpected,challengeSha256);
 for(const role of ['PRIMARY','SECONDARY'] as const)
  bq=bqResignCapture(bq,role,{
   crlSha256:brCrlSha,ocspSha256:brOcspSha,
   drTranscriptSha256:sha(drBytes),
   wormRetentionUntil:worm.retentionUntil
  });
 const bqSha=candidateRemotePacketDigest(bq);
 const expected:CandidateByteExpected={
  quoteId:bqExpected.quoteId,bqPacketSha256:bqSha,
  bmReceiptSha256:bqExpected.bmReceiptSha256,
  sourceSha256:bqExpected.sourceSha256,sequence:bqExpected.bmSequence,
  revocationEpoch:bqExpected.minRevocationEpoch,
  bqExists:true,bqLocallyConsistent:true,
  bqGovernanceState:'HELD_UNVERIFIED'
 };
 const checkpoint:CandidateCheckpointBytes={
  format:'aaditech-quote-provider-checkpoint-v1',
  quoteId:expected.quoteId,challengeSha256,
  bqPacketSha256:bqSha,bmReceiptSha256:expected.bmReceiptSha256,
  sourceSha256:expected.sourceSha256,sequence:expected.sequence,
  revocationEpoch:expected.revocationEpoch,
  issuedAt:new Date(now.getTime()-60000).toISOString(),
  expiresAt:new Date(now.getTime()+10*60000).toISOString(),
  crlSha256:brCrlSha,ocspSha256:brOcspSha,
  wormReceiptSha256:sha(wormBytes),drTranscriptSha256:sha(drBytes),
  evidenceState:'OFFLINE_CANDIDATE_ONLY'
 };
 const raw=Buffer.from(JSON.stringify(checkpoint));
 const signer=createSign('RSA-SHA256');
 signer.update(Buffer.concat([
  Buffer.from('aaditech/quote/provider-checkpoint-bytes/v1\n'),raw]));
 const signature=signer.sign(brLeafKey);
 const packet:CandidateProviderBytePacket={
  format:'aaditech-quote-provider-byte-evidence-v1',
  quoteId:expected.quoteId,bqPacketSha256:bqSha,challengeSha256,
  checkpointUtf8Base64:raw.toString('base64'),
  checkpointSignatureBase64:signature.toString('base64'),
  leafCertificatePem:brLeafPem,crlDerBase64:brCrlDer.toString('base64'),
  ocspDerBase64:brOcspDer.toString('base64'),
  wormReceiptUtf8Base64:wormBytes.toString('base64'),
  drTranscriptUtf8Base64:drBytes.toString('base64')
 };
 return {packet,bq,expected,checkpoint,worm,dr};
}
