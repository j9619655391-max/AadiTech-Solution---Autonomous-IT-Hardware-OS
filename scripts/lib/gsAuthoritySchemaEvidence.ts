// 1GS CI-only schema evidence, not independent schema attestation or restore.
import {createHash,createPublicKey,verify} from 'node:crypto';
import type {PoolConnection,RowDataPacket} from 'mysql2/promise';
import {gfMigrationTarget} from '../migrate-gf-provenance';
import {GR_TABLES,grManifestBytes} from './grAuthorityRecoveryManifest';
function fail():never{throw Error('GS_SCHEMA_HOLD');}
const routines=['aaditech_gi_bind_quote_candidate','aaditech_gj_bind_intent_candidate','aaditech_gk_create_customer_candidate','aaditech_gl_create_lead_candidate','aaditech_gl_create_product_candidate'];
export async function gsCaptureSchemaEvidence(db:Pick<PoolConnection,'query'>){
 gfMigrationTarget(process.env);
 const marks=GR_TABLES.map(()=>'?').join(',');
 const routineMarks=routines.map(()=>'?').join(',');
 const groups=[
  {kind:'tables',sql:'SELECT TABLE_NAME,ENGINE,TABLE_COLLATION FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('+marks+') ORDER BY BINARY TABLE_NAME',args:[...GR_TABLES]},
  {kind:'columns',sql:'SELECT TABLE_NAME,COLUMN_NAME,ORDINAL_POSITION,COLUMN_TYPE,IS_NULLABLE,COLUMN_DEFAULT,CHARACTER_SET_NAME,COLLATION_NAME,EXTRA,GENERATION_EXPRESSION FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('+marks+') ORDER BY BINARY TABLE_NAME,ORDINAL_POSITION',args:[...GR_TABLES]},
  {kind:'indexes',sql:'SELECT TABLE_NAME,INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME,COLLATION,SUB_PART,INDEX_TYPE,IS_VISIBLE,EXPRESSION FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('+marks+') ORDER BY BINARY TABLE_NAME,BINARY INDEX_NAME,SEQ_IN_INDEX',args:[...GR_TABLES]},
  {kind:'constraints',sql:'SELECT TABLE_NAME,CONSTRAINT_NAME,CONSTRAINT_TYPE,ENFORCED FROM information_schema.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('+marks+') ORDER BY BINARY TABLE_NAME,BINARY CONSTRAINT_NAME',args:[...GR_TABLES]},
  {kind:'constraintColumns',sql:'SELECT TABLE_NAME,CONSTRAINT_NAME,COLUMN_NAME,ORDINAL_POSITION,POSITION_IN_UNIQUE_CONSTRAINT,CASE WHEN REFERENCED_TABLE_SCHEMA=DATABASE() THEN 'LOCAL' ELSE REFERENCED_TABLE_SCHEMA END AS REFERENCED_TABLE_SCHEMA,REFERENCED_TABLE_NAME,REFERENCED_COLUMN_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('+marks+') ORDER BY BINARY TABLE_NAME,BINARY CONSTRAINT_NAME,ORDINAL_POSITION',args:[...GR_TABLES]},
  {kind:'foreignActions',sql:'SELECT TABLE_NAME,CONSTRAINT_NAME,UNIQUE_CONSTRAINT_NAME,MATCH_OPTION,UPDATE_RULE,DELETE_RULE,REFERENCED_TABLE_NAME FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME IN ('+marks+') ORDER BY BINARY TABLE_NAME,BINARY CONSTRAINT_NAME',args:[...GR_TABLES]},
  {kind:'checkBodies',sql:'SELECT t.TABLE_NAME,t.CONSTRAINT_NAME,c.CHECK_CLAUSE FROM information_schema.TABLE_CONSTRAINTS t JOIN information_schema.CHECK_CONSTRAINTS c ON c.CONSTRAINT_SCHEMA=t.CONSTRAINT_SCHEMA AND c.CONSTRAINT_NAME=t.CONSTRAINT_NAME WHERE t.TABLE_SCHEMA=DATABASE() AND t.TABLE_NAME IN ('+marks+') AND t.CONSTRAINT_TYPE=\'CHECK\' ORDER BY BINARY t.TABLE_NAME,BINARY t.CONSTRAINT_NAME',args:[...GR_TABLES]},
  {kind:'triggers',sql:'SELECT TRIGGER_NAME,EVENT_MANIPULATION,EVENT_OBJECT_TABLE,ACTION_ORDER,ACTION_STATEMENT,ACTION_TIMING,SQL_MODE,DEFINER,CHARACTER_SET_CLIENT,COLLATION_CONNECTION,DATABASE_COLLATION FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE IN ('+marks+') ORDER BY BINARY TRIGGER_NAME',args:[...GR_TABLES]},
  {kind:'routines',sql:'SELECT ROUTINE_NAME,ROUTINE_TYPE,ROUTINE_DEFINITION,SQL_DATA_ACCESS,SECURITY_TYPE,SQL_MODE,DEFINER,CHARACTER_SET_CLIENT,COLLATION_CONNECTION,DATABASE_COLLATION FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE() AND ROUTINE_NAME IN ('+routineMarks+') ORDER BY BINARY ROUTINE_NAME',args:[...routines]},
  {kind:'parameters',sql:'SELECT SPECIFIC_NAME,ORDINAL_POSITION,PARAMETER_MODE,PARAMETER_NAME,DTD_IDENTIFIER,CHARACTER_SET_NAME,COLLATION_NAME FROM information_schema.PARAMETERS WHERE SPECIFIC_SCHEMA=DATABASE() AND SPECIFIC_NAME IN ('+routineMarks+') ORDER BY BINARY SPECIFIC_NAME,ORDINAL_POSITION',args:[...routines]}
 ];
 const hash=createHash('sha256').update('AADITECH-GT-SCHEMA-V2\n');
 const counts:Record<string,number>={};
 for(const group of groups){
  const [rows]=await db.query<RowDataPacket[]>(group.sql,group.args);
  if(rows.length===0||rows.length>4096)fail();
  if(group.kind==='routines'&&rows.some(row=>typeof row.ROUTINE_DEFINITION!=='string'||!row.ROUTINE_DEFINITION))fail();
  if(group.kind==='triggers'&&rows.some(row=>typeof row.ACTION_STATEMENT!=='string'||!row.ACTION_STATEMENT))fail();
  counts[group.kind]=rows.length;
  hash.update(JSON.stringify([group.kind,rows.map(row=>Object.keys(row).sort().map(k=>[k,row[k]]))])+'\n');
 }
 // GN four reservation + GO four consumption + GP fourteen DML guards.
 if(counts.tables!==7||counts.triggers!==22||counts.routines!==5||counts.foreignActions!==2||counts.checkBodies!==2)fail();
 return {sha256:hash.digest('hex'),counts};
}
export function gsRecoveryBytes(manifest:unknown,schemaSha256:unknown){
 if(typeof schemaSha256!=='string'||!/^[0-9a-f]{64}$/.test(schemaSha256))fail();
 return Buffer.from('AADITECH-GS-SCHEMA-BINDING-V1\n'+JSON.stringify([createHash('sha256').update(grManifestBytes(manifest)).digest('hex'),schemaSha256]),'utf8');
}
export function gsVerifySchemaBinding(manifest:unknown,expectedSchema:string,actualSchema:string,signature:unknown,pin:{publicKeyPem:string;spkiSha256:string}){
 const bytes=gsRecoveryBytes(manifest,expectedSchema);
 if(actualSchema!==expectedSchema||typeof signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signature)||
 !/^[0-9a-f]{64}$/.test(pin.spkiSha256)||typeof pin.publicKeyPem!=='string'||pin.publicKeyPem.length>4096||!pin.publicKeyPem.startsWith('-----BEGIN PUBLIC KEY-----'))fail();
 try{
  const key=createPublicKey(pin.publicKeyPem),sig=Buffer.from(signature as string,'base64url');
  if(key.asymmetricKeyType!=='ed25519'||createHash('sha256').update(key.export({format:'der',type:'spki'})).digest('hex')!==pin.spkiSha256||
     sig.length!==64||sig.toString('base64url')!==signature||!verify(null,bytes,key,sig))fail();
 }catch{return fail();}
 return {status:'MATCH' as const,productionReleaseAuthorized:false as const};
}
