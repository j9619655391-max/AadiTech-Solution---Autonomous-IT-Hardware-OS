// 1GT: disposable CI authority-only encrypted artifact and isolated schema restore.
// Never run against live data. No permanent artifacts or credentials are retained.
import {createCipheriv,createDecipheriv,randomBytes,createHash} from 'node:crypto';
import {mkdtempSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import type {Pool,PoolConnection,RowDataPacket} from 'mysql2/promise';
import {gfMigrationTarget} from '../migrate-gf-provenance';
import {GR_SPECS,grCaptureAuthorityDigests,grVerifyManifest,type GrManifest} from './grAuthorityRecoveryManifest';
import {gsCaptureSchemaEvidence,gsRecoveryBytes,gsVerifySchemaBinding} from './gsAuthoritySchemaEvidence';
import {gqInspectAuthoritySnapshot} from './gqAuthorityReconciliation';
const magic=Buffer.from('AADITECH-GT-BACKUP-V1\0','utf8'),maxBytes=16*1024*1024;
function fail():never{throw Error('GT_RESTORE_HOLD');}
function aad(manifest:unknown,schema:string){return Buffer.concat([magic,gsRecoveryBytes(manifest,schema)]);}
export function gtSealBackup(plain:Buffer,key:Buffer,manifest:unknown,schema:string){
 if(!Buffer.isBuffer(plain)||!plain.length||plain.length>maxBytes||!Buffer.isBuffer(key)||key.length!==32)fail();
 const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);
 cipher.setAAD(aad(manifest,schema));
 const encrypted=Buffer.concat([cipher.update(plain),cipher.final()]);
 return Buffer.concat([magic,iv,cipher.getAuthTag(),encrypted]);
}
export function gtOpenBackup(blob:Buffer,key:Buffer,manifest:unknown,schema:string){
 const offset=magic.length;
 if(!Buffer.isBuffer(blob)||blob.length<=offset+28||blob.length>offset+28+maxBytes||
 !blob.subarray(0,offset).equals(magic)||!Buffer.isBuffer(key)||key.length!==32)fail();
 try{
  const decipher=createDecipheriv('aes-256-gcm',key,blob.subarray(offset,offset+12));
  decipher.setAAD(aad(manifest,schema));decipher.setAuthTag(blob.subarray(offset+12,offset+28));
  return Buffer.concat([decipher.update(blob.subarray(offset+28)),decipher.final()]);
 }catch{return fail();}
}
type ArchiveRow=(string|null)[];
type ArchiveEntry={table:string;rows:ArchiveRow[]};
function parseArchive(bytes:Buffer):ArchiveEntry[]{
 let value:unknown;
 try{value=JSON.parse(bytes.toString('utf8'));}catch{return fail();}
 if(!Array.isArray(value)||value.length!==GR_SPECS.length)fail();
 const entries=value.map((item,i)=>{
  if(!item||typeof item!=='object'||Object.keys(item).length!==2||item.table!==GR_SPECS[i][0]||
   !Array.isArray(item.rows)||item.rows.length>10000)fail();
  const n=GR_SPECS[i][2].split(',').length;
  for(const row of item.rows)if(!Array.isArray(row)||row.length!==n||row.some((v:unknown)=>v!==null&&typeof v!=='string'))fail();
  return {table:item.table as string,rows:item.rows as ArchiveRow[]};
 });
 // Canonical archive only, reject duplicate JSON keys/invalid UTF8/noncanonical representation.
 if(!Buffer.from(JSON.stringify(entries),'utf8').equals(bytes))fail();
 return entries;
}
type Expected=Parameters<typeof grVerifyManifest>[2];
export async function gtRehearseEncryptedAuthorityRestore(pool:Pick<Pool,'getConnection'>,manifest:GrManifest,signature:string,expected:Expected,schemaDigest:string,schemaSignature:string){
 gfMigrationTarget(process.env);
 const source=await pool.getConnection();
 let dest:PoolConnection|undefined,dir:string|undefined,created=false;
 const schema='aaditech_ci_gt_'+randomBytes(8).toString('hex'),key=randomBytes(32);
 try{
  const [db]=await source.query<RowDataPacket[]>('SELECT DATABASE() AS name');
  if(db[0]?.name!=='aaditech_ci')fail();
  const [defaults]=await source.query<RowDataPacket[]>('SELECT DEFAULT_CHARACTER_SET_NAME AS charset,DEFAULT_COLLATION_NAME AS collation FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=DATABASE()');
  const charset=defaults[0]?.charset,collation=defaults[0]?.collation;
  if(typeof charset!=='string'||typeof collation!=='string'||!/^[a-z0-9_]+$/.test(charset)||!/^[a-z0-9_]+$/.test(collation))fail();
  await source.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
  await source.query('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY');
  if((await gqInspectAuthoritySnapshot(source)).status!=='PASS')fail();
  const original=await grCaptureAuthorityDigests(source);
  grVerifyManifest(manifest,signature,expected,original);
  gsVerifySchemaBinding(manifest,schemaDigest,(await gsCaptureSchemaEvidence(source)).sha256,schemaSignature,expected);
  const archive:ArchiveEntry[]=[],ddl=new Map<string,string>();let total=0;
  for(const [table,pk,columns] of GR_SPECS){
   const [def]=await source.query<RowDataPacket[]>('SHOW CREATE TABLE '+table);
   const sql=def[0]?.['Create Table'];
   // Trusted CI fixture DDL only. No qualified cross-schema references.
   if(typeof sql!=='string'||!sql.startsWith('CREATE TABLE '+String.fromCharCode(96)+table+String.fromCharCode(96)+' (')||sql.includes('aaditech_ci'))fail();
   ddl.set(table,sql);
   const fields=columns.split(',');
   const [rows]=await source.query<RowDataPacket[]>('SELECT '+fields.map(k=>'CAST('+k+' AS CHAR CHARACTER SET utf8mb4) AS '+k).join(',')+' FROM '+table+' ORDER BY BINARY '+pk+' LIMIT 10001');
   if(rows.length>10000)fail();
   const data:ArchiveRow[]=rows.map(row=>fields.map(k=>{
    const v=row[k];if(v!==null&&typeof v!=='string')fail();return v as string|null;
   }));
   total+=Buffer.byteLength(JSON.stringify(data),'utf8');if(total>maxBytes)fail();
   archive.push({table,rows:data});
  }
  const plain=Buffer.from(JSON.stringify(archive),'utf8');
  dir=mkdtempSync(join(tmpdir(),'aaditech-gt-'));
  const file=join(dir,'authority.aead');
  writeFileSync(file,gtSealBackup(plain,key,manifest,schemaDigest),{mode:0o600,flag:'wx'});
  const artifact=readFileSync(file),artifactSha256=createHash('sha256').update(artifact).digest('hex');
  const recovered=parseArchive(gtOpenBackup(artifact,key,manifest,schemaDigest));
  const damaged=Buffer.from(artifact);damaged[damaged.length-1]^=1;
  let rejected=false;try{gtOpenBackup(damaged,key,manifest,schemaDigest);}catch{rejected=true;}if(!rejected)fail();
  dest=await pool.getConnection();
  await dest.query('CREATE DATABASE '+schema+' CHARACTER SET '+charset+' COLLATE '+collation);created=true;
  await dest.query('USE '+schema);
  // Parent registry/key tables precede receipt FK creation and row import.
  for(const [table] of GR_SPECS)await dest.query(ddl.get(table)!);
  for(let i=0;i<GR_SPECS.length;i++){
   const [table,,columns]=GR_SPECS[i],fields=columns.split(',');
   for(const row of recovered[i].rows)await dest.execute('INSERT INTO '+table+'('+columns+') VALUES ('+fields.map(()=>'?').join(',')+')',row);
  }
  // Reinstall candidate triggers from reviewed source, not arbitrary archive SQL.
  const split=(path:string)=>readFileSync(path,'utf8').split(/^-- statement-break$/m);
  for(const sql of split('database/authority/phase1gn_global_intent_nonce_candidate.sql').slice(1))await dest.query(sql);
  for(const sql of split('database/authority/phase1go_consumption_approval_candidate.sql').slice(3))await dest.query(sql);
  for(const sql of split('database/authority/phase1gp_immutable_authority_candidate.sql'))await dest.query(sql);
  await dest.query(readFileSync('database/authority/phase1gi_session_quote_bind_candidate.sql','utf8'));
  for(const path of ['phase1gk_customer_create_intent_candidate','phase1gl_lead_create_intent_candidate','phase1gl_product_create_intent_candidate','phase1gj_quote_intent_candidate'])
   await dest.query(split('database/authority/'+path+'.sql')[1]);
  const restored=await grCaptureAuthorityDigests(dest);
  grVerifyManifest(manifest,signature,expected,restored);
  gsVerifySchemaBinding(manifest,schemaDigest,(await gsCaptureSchemaEvidence(dest)).sha256,schemaSignature,expected);
  // Exercise restored DML and FK guards, without touching the source or business tables.
  const expectError=async(fn:()=>Promise<unknown>,code:string,message?:string)=>{
   try{await fn();}catch(e){const err=e as {code?:string;sqlMessage?:string};if(err.code===code&&(!message||err.sqlMessage===message))return;throw e;}fail();
  };
  await expectError(()=>dest!.query('DELETE FROM auth_go_intent_approvals_candidate LIMIT 1'),'ER_SIGNAL_EXCEPTION','GP_AUTHORITY_IMMUTABLE');
  await expectError(()=>dest!.query('DELETE FROM auth_gn_intent_nonces_candidate LIMIT 1'),'ER_SIGNAL_EXCEPTION','GP_AUTHORITY_IMMUTABLE');
  await expectError(()=>dest!.query('DELETE FROM auth_go_issuer_keys_candidate LIMIT 1'),'ER_SIGNAL_EXCEPTION','GP_AUTHORITY_IMMUTABLE');
  await expectError(()=>dest!.execute('INSERT INTO auth_go_intent_approvals_candidate(intent_hash,key_id,spki_sha256,evidence_sha256,expires_at) VALUES (?,?,?,?,UTC_TIMESTAMP(3))',[randomBytes(32).toString('hex'),'gt-missing-key','a'.repeat(64),'b'.repeat(64)]),'ER_NO_REFERENCED_ROW_2');
  const [existing]=await dest.query<RowDataPacket[]>('SELECT intent_hash,actor_id,session_hash,customer_id FROM auth_gk_customer_intents_candidate LIMIT 1');
  if(existing.length!==1)fail();
  await expectError(()=>dest!.execute('INSERT INTO auth_gj_quote_intents_candidate(intent_hash,actor_id,session_hash,request_key,request_hash,quote_id,expires_at) VALUES (?,?,?,?,?,?,DATE_ADD(UTC_TIMESTAMP(3),INTERVAL 1 MINUTE))',[existing[0].intent_hash,existing[0].actor_id,existing[0].session_hash,'00000000-0000-0000-0000-000000000001','a'.repeat(64),existing[0].customer_id]),'ER_DUP_ENTRY');
  grVerifyManifest(manifest,signature,expected,await grCaptureAuthorityDigests(dest));
  return {status:'MATCH' as const,artifactSha256,artifactBytes:artifact.length,restoredTables:7,restoredTriggers:22,restoredRoutines:5,productionReleaseAuthorized:false as const};
 }finally{
  key.fill(0);
  try{
   if(dest){try{if(created){await dest.query('USE aaditech_ci');await dest.query('DROP DATABASE '+schema);}}finally{dest.destroy();}}
  }finally{
   try{if(dir)rmSync(dir,{recursive:true,force:true});}
   finally{try{await source.rollback();}catch(e){source.destroy();throw e;}finally{source.release();}}
  }
 }
}
