import type {Pool,RowDataPacket} from 'mysql2/promise';
import {assessPhase1BcWitnessCustody} from '../../scripts/lib/phase1BcWitnessCustody.mjs';

// Phase 1BC records only candidate SHA-256 custody metadata in approved
// disposable environments. These tables are neither remote WORM nor
// independently authenticated witness/source-of-truth evidence.
const ID=/^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$/;
const SHA=/^[0-9a-f]{64}$/;
const ACCEPTED=new Set(['GENESIS_UNVERIFIED','EXTENSION_UNVERIFIED']);
export function bcWitnessWriteTarget(env:NodeJS.ProcessEnv):'ci'|'staging'{
 if(env.NODE_ENV==='test'&&env.CRM_TEST_DB==='1'&&
    env.DB_NAME==='aaditech_ci')return 'ci';
 if(env.NODE_ENV!=='production'&&env.DB_SSL==='true'&&
    env.BC_WITNESS_WRITE_APPROVED==='YES'&&
    env.STAGING_DISPOSABLE_CONFIRMED==='YES'&&
    /^aaditech_staging_[a-z0-9_]+$/.test(env.DB_NAME??''))
  return 'staging';
 throw Error('Phase 1BC witness writes allowed only on disposable CI or approved isolated TLS staging');
}
export interface BcWitnessArgs{
 azPacket:any;observations:any[];now?:Date;env?:NodeJS.ProcessEnv;
}
export async function recordPhase1BcWitnessCustody(pool:Pool,{
 azPacket,observations,now=new Date(),env=process.env
}:BcWitnessArgs){
 bcWitnessWriteTarget(env);
 if(Buffer.byteLength(JSON.stringify({azPacket,observations}),'utf8')>45000)
  throw Error('Phase 1BC overlarge candidate evidence packet');
 const report=assessPhase1BcWitnessCustody({azPacket,observations,now});
 const logRef=azPacket?.archive?.logRef;
 if(!report.claimCryptographicallyConsistent||
    typeof logRef!=='string'||!ID.test(logRef)||
    typeof report.packetSha256!=='string'||!SHA.test(report.packetSha256)||
    typeof report.pinSetSha256!=='string'||!SHA.test(report.pinSetSha256)||
    typeof report.evidenceSha256!=='string'||!SHA.test(report.evidenceSha256)||
    typeof report.oldTreeSize!=='number'||
    typeof report.newTreeSize!=='number'||
    typeof report.oldRootSha256!=='string'||!SHA.test(report.oldRootSha256)||
    typeof report.newRootSha256!=='string'||!SHA.test(report.newRootSha256))
  throw Error('Phase 1BC refuses unbound or invalid signed witness custody claims');
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  // Bind these untrusted witness claims to an existing, unquarantined local
  // Phase 1AZ dossier; never accept an arbitrary caller-created packet alone.
  const [azRows]=await conn.execute<RowDataPacket[]>(
   'SELECT last_packet_sha256,governance_state FROM inv_az_readiness_streams WHERE log_ref=? FOR UPDATE',
   [logRef]);
  if(azRows.length!==1||azRows[0].last_packet_sha256!==report.packetSha256||
     azRows[0].governance_state!=='HELD_UNVERIFIED')
   throw Error('Phase 1BC missing or quarantined local AZ predecessor history');
  await conn.execute(
   'INSERT INTO inv_bc_witness_streams (log_ref) VALUES (?) ON DUPLICATE KEY UPDATE log_ref=log_ref',
   [logRef]);
  const [heads]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_bc_witness_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  const head=heads[0];
  if(!head)throw Error('Phase 1BC missing locked witness head');
  const size=Number(head.last_tree_size);
  if(!Number.isSafeInteger(size)||size<0)
   throw Error('Phase 1BC malformed previous witness head');
  const [accepted]=await conn.execute<RowDataPacket[]>(
   "SELECT id FROM inv_bc_witness_observations WHERE log_ref=? AND evidence_sha256=? AND outcome IN ('GENESIS_UNVERIFIED','EXTENSION_UNVERIFIED') LIMIT 1 FOR UPDATE",
   [logRef,report.evidenceSha256]);
  if(size===report.newTreeSize&&head.last_root_sha256===report.newRootSha256&&
     accepted.length===1&&head.governance_state==='HELD_UNVERIFIED'){
   await conn.commit();
   return Object.freeze({phase:'1BC',outcome:'REPLAY',
    governanceState:'HELD_UNVERIFIED',sourceOfTruthAuthenticated:false,
    productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'});
  }
  const [priorIncident]=await conn.execute<RowDataPacket[]>(
   "SELECT id FROM inv_bc_witness_observations WHERE log_ref=? AND evidence_sha256=? AND outcome NOT IN ('GENESIS_UNVERIFIED','EXTENSION_UNVERIFIED') LIMIT 1 FOR UPDATE",
   [logRef,report.evidenceSha256]);
  if(priorIncident.length){
   await conn.commit();
   return Object.freeze({phase:'1BC',outcome:'DUPLICATE_REJECTED',
    governanceState:head.governance_state,sourceOfTruthAuthenticated:false,
    productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'});
  }
  let outcome:string;
  if(head.governance_state==='QUARANTINED')outcome='POST_INCIDENT_QUARANTINED';
  else if(size===0)outcome='GENESIS_UNVERIFIED';
  else if(head.last_witness_pinset_sha256!==report.pinSetSha256)
   outcome='WITNESS_PINSET_CHANGE_QUARANTINED';
  else if(head.last_az_packet_sha256!==report.packetSha256)
   outcome='AZ_PACKET_CHANGE_QUARANTINED';
  else if(report.newTreeSize<size)
   outcome='ROLLBACK_QUARANTINED';
  else if(report.newTreeSize===size)
   outcome='FORK_QUARANTINED';
  else if(report.oldTreeSize!==size||
     report.oldRootSha256!==head.last_root_sha256)
   outcome='HISTORICAL_HEAD_MISMATCH_QUARANTINED';
  else outcome='EXTENSION_UNVERIFIED';
  await conn.execute(
   'INSERT INTO inv_bc_witness_observations (log_ref,old_tree_size,old_root_sha256,new_tree_size,new_root_sha256,az_packet_sha256,witness_pinset_sha256,evidence_sha256,outcome) VALUES (?,?,?,?,?,?,?,?,?)',
   [logRef,report.oldTreeSize,report.oldRootSha256,report.newTreeSize,
    report.newRootSha256,report.packetSha256,report.pinSetSha256,
    report.evidenceSha256,outcome]);
  if(ACCEPTED.has(outcome)){
   await conn.execute(
    'UPDATE inv_bc_witness_streams SET last_tree_size=?,last_root_sha256=?,last_az_packet_sha256=?,last_witness_pinset_sha256=? WHERE log_ref=?',
    [report.newTreeSize,report.newRootSha256,report.packetSha256,report.pinSetSha256,logRef]);
  }else if(outcome!=='POST_INCIDENT_QUARANTINED'){
   await conn.execute(
    "UPDATE inv_bc_witness_streams SET governance_state='QUARANTINED' WHERE log_ref=?",
    [logRef]);
  }
  await conn.commit();
  return Object.freeze({phase:'1BC',outcome,
   governanceState:ACCEPTED.has(outcome)?head.governance_state:'QUARANTINED',
   candidateEvidenceOnly:true,sourceOfTruthAuthenticated:false,
   productionReleaseAuthorized:false,productionReleaseBlocked:true,releaseDecision:'HOLD'});
 }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}
export async function inspectPhase1BcWitnessCustody(pool:Pool,logRef:string,
 env:NodeJS.ProcessEnv=process.env){
 bcWitnessWriteTarget(env);
 if(typeof logRef!=='string'||!ID.test(logRef))throw Error('Phase 1BC invalid log ref');
 const conn=await pool.getConnection();
 try{
  await conn.beginTransaction();
  const [heads]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_bc_witness_streams WHERE log_ref=? FOR UPDATE',[logRef]);
  if(heads.length!==1)throw Error('Phase 1BC missing witness stream');
  const [rows]=await conn.execute<RowDataPacket[]>(
   'SELECT * FROM inv_bc_witness_observations WHERE log_ref=? ORDER BY id FOR UPDATE',
   [logRef]);
  const problems:string[]=[];
  let currentSize=0,currentRoot:null|string=null,packet:null|string=null,
   pinset:null|string=null,incident=false;
  for(const row of rows){
   for(const k of ['old_root_sha256','new_root_sha256','az_packet_sha256',
    'witness_pinset_sha256','evidence_sha256'])
    if(!SHA.test(String(row[k])))problems.push('INVALID_PERSISTED_HASH');
   const oldSize=Number(row.old_tree_size),newSize=Number(row.new_tree_size);
   if(!Number.isSafeInteger(oldSize)||!Number.isSafeInteger(newSize)||
      oldSize<1||newSize<=oldSize)problems.push('INVALID_ACCEPTED_TREE_SIZES');
   if(ACCEPTED.has(row.outcome)){
    if(currentSize===0){
     if(row.outcome!=='GENESIS_UNVERIFIED')
      problems.push('FIRST_WITNESS_HEAD_NOT_GENESIS');
    }else{
     if(row.outcome!=='EXTENSION_UNVERIFIED'||oldSize!==currentSize||
        row.old_root_sha256!==currentRoot)
      problems.push('BROKEN_APPEND_ONLY_CUSTODY_HISTORY');
     if(row.az_packet_sha256!==packet||row.witness_pinset_sha256!==pinset)
      problems.push('CHANGED_ACCEPTED_WITNESS_PINSET');
    }
    currentSize=newSize;currentRoot=row.new_root_sha256;
    packet=row.az_packet_sha256;pinset=row.witness_pinset_sha256;
   }else incident=true;
  }
  const h=heads[0];
  if(Number(h.last_tree_size)!==currentSize||h.last_root_sha256!==currentRoot||
     h.last_az_packet_sha256!==packet||h.last_witness_pinset_sha256!==pinset)
   problems.push('WITNESS_HEAD_HISTORY_DIVERGENCE');
  if((h.governance_state==='QUARANTINED')!==incident)
   problems.push('WITNESS_INCIDENT_QUARANTINE_MISMATCH');
  if(h.external_source_authenticated!=='NO'||
    h.independent_key_custody_verified!=='NO'||
    h.immutable_worm_retention_verified!=='NO'||h.production_release!=='HOLD')
   problems.push('UNAUTHORIZED_SOURCE_TRUST_PROMOTION');
  await conn.commit();
  return Object.freeze({phase:'1BC',logRef,observations:rows.length,
   latestCandidateTreeSize:currentSize,governanceState:h.governance_state,
   localDigestHistoryConsistent:problems.length===0,
   signedEvidenceIndependentlyRevalidated:false,
   independentlyAuthenticatedSource:false,immutableWormVerified:false,
   independentlyWitnessedDR:false,
   productionReleaseAuthorized:false,productionReleaseBlocked:true,
   releaseDecision:'HOLD',anomalyCodes:Object.freeze([...new Set(problems)].sort())});
 }catch(e){await conn.rollback();throw e;}finally{conn.release();}
}
