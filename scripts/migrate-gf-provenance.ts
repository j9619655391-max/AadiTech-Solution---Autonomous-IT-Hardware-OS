import 'dotenv/config';
import mysql from 'mysql2/promise';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {getDatabaseConfig} from '../server/db';
import {MIGRATIONS} from './lib/stagingPreflight';

const id='0051_gf_crm_quote_write_once';
const file='database/migrations/'+id+'.sql';
function statements(){return readFileSync(file,'utf8').split(/^-- statement-break$/m)
 .map(s=>s.replace(/^--.*$/gm,'').trim()).filter(Boolean);}
export function gfMigrationTarget(env:NodeJS.ProcessEnv):'ci'{
 if(env.CRM_TEST_DB==='1'&&env.DB_NAME==='aaditech_ci'&&env.NODE_ENV==='test'&&env.DB_SSL==='false')return 'ci';
 throw Error('1GF migration is CI-only; independent reconciliation and DBA approval required');
}
export async function assertGfHistoricalIntegrity(db:Pick<mysql.Connection,'query'>){
 const [duplicates]=await db.query<mysql.RowDataPacket[]>(`SELECT 1 FROM crm_audit_events
  WHERE operation='CREATE' GROUP BY entity_type,entity_id HAVING COUNT(*)>1 LIMIT 1`);
 const [reused]=await db.query<mysql.RowDataPacket[]>(`SELECT 1 FROM sales_quote_create_requests
  WHERE quote_id IS NOT NULL GROUP BY quote_id HAVING COUNT(*)>1 LIMIT 1`);
 const [foreign]=await db.query<mysql.RowDataPacket[]>(`SELECT 1 FROM sales_quote_create_requests r
  LEFT JOIN sales_quote_drafts q ON q.id=r.quote_id
  WHERE r.quote_id IS NOT NULL AND (q.id IS NULL OR q.created_by<>r.actor_id) LIMIT 1`);
 if(duplicates.length||reused.length||foreign.length)throw Error('1GF historical provenance conflict; manual quarantine required');
}
// Keep quoted SQL literal bytes intact; normalize only nonliteral tokens.
function canonical(s:string){
 return s.split(/('(?:''|[^'])*')/).map((part,i)=>i%2?part:part.replace(/\x60/g,'').replace(/\s+/g,'').toLowerCase()).join('');
}
export async function checkInstalledGfIntegrity(db:Pick<mysql.Pool,'query'>){
 const [indexes]=await db.query<mysql.RowDataPacket[]>(`SELECT TABLE_NAME,INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,COLUMN_NAME
  FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE()
  AND INDEX_NAME IN ('uq_gf_crm_create_origin','uq_gf_quote_binding') ORDER BY INDEX_NAME,SEQ_IN_INDEX`);
 const expected=[
  ['crm_audit_events','uq_gf_crm_create_origin',0,1,'entity_type'],
  ['crm_audit_events','uq_gf_crm_create_origin',0,2,'gf_create_entity_id'],
  ['sales_quote_create_requests','uq_gf_quote_binding',0,1,'quote_id']
 ];
 if(JSON.stringify(indexes.map(x=>[x.TABLE_NAME,x.INDEX_NAME,Number(x.NON_UNIQUE),Number(x.SEQ_IN_INDEX),x.COLUMN_NAME]))!==JSON.stringify(expected))
  throw Error('1GF installed unique index shape unverified');
 const [columns]=await db.query<mysql.RowDataPacket[]>(`SELECT EXTRA,GENERATION_EXPRESSION FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='crm_audit_events' AND COLUMN_NAME='gf_create_entity_id'`);
 // MySQL formats generated expressions with parentheses and charset introducers.
 const expr=canonical(String(columns[0]?.GENERATION_EXPRESSION??'')).replace(/_utf8mb4/g,'').replace(/[()]/g,'');
 if(columns.length!==1||columns[0].EXTRA!=='STORED GENERATED'||expr!=="casewhenoperation='CREATE'thenentity_idelsenullend")
  throw Error('1GF generated origin expression unverified');
 const [triggers]=await db.query<mysql.RowDataPacket[]>(`SELECT TRIGGER_NAME,ACTION_STATEMENT,ACTION_TIMING,EVENT_MANIPULATION
  FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE='sales_quote_create_requests'`);
 const expectedTriggers=new Map(statements().slice(2).map(s=>{
  const m=/^CREATE TRIGGER (\w+) BEFORE (INSERT|UPDATE) ON sales_quote_create_requests\s+FOR EACH ROW\s+([\s\S]+)$/.exec(s);
  if(!m)throw Error('1GF trigger source malformed');
  return [m[1],{event:m[2],body:m[3]}] as const;
 }));
 if(triggers.length!==expectedTriggers.size)throw Error('1GF installed trigger inventory unverified');
 for(const row of triggers){
  const wanted=expectedTriggers.get(row.TRIGGER_NAME);
  if(!wanted||row.ACTION_TIMING!=='BEFORE'||row.EVENT_MANIPULATION!==wanted.event||
    canonical(String(row.ACTION_STATEMENT))!==canonical(wanted.body))
   throw Error('1GF installed trigger body unverified');
  expectedTriggers.delete(row.TRIGGER_NAME);
 }
}
async function main(){
 gfMigrationTarget(process.env);
 if(MIGRATIONS[50]!==id)throw Error('1GF migration registry mismatch');
 const cfg=getDatabaseConfig();if(!cfg.host||!cfg.user||!cfg.password||!cfg.database)throw Error('Complete DB settings required');
 const db=await mysql.createConnection(cfg);let locked=false;
 try{
  const [lk]=await db.query<mysql.RowDataPacket[]>("SELECT GET_LOCK('aaditech-auth-migrations',15) AS acquired");
  if(Number(lk[0]?.acquired)!==1)throw Error('1GF migration mutex unavailable');locked=true;
  const [rows]=await db.query<mysql.RowDataPacket[]>('SELECT id,checksum FROM schema_migrations');
  const applied=new Map(rows.map(x=>[String(x.id),String(x.checksum)]));
  for(const previous of MIGRATIONS.slice(0,50)){
   if(applied.get(previous)!==createHash('sha256').update(readFileSync('database/migrations/'+previous+'.sql')).digest('hex'))
    throw Error('1GF missing or drifted prerequisite '+previous);
  }
  for(const previous of applied.keys())if(!MIGRATIONS.some(x=>x===previous))throw Error('1GF unknown migration');
  const checksum=createHash('sha256').update(readFileSync(file)).digest('hex');
  if(applied.has(id)){
   if(applied.get(id)!==checksum)throw Error('1GF migration checksum drift');
   await checkInstalledGfIntegrity(db);console.log('Already applied:',id);return;
  }
  await assertGfHistoricalIntegrity(db);
  // MySQL DDL is nontransactional across statements. Partial installs are
  // intentionally not repaired or dropped; reset disposable CI after review.
  for(const sql of statements())await db.query(sql);
  await checkInstalledGfIntegrity(db);
  await db.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,checksum]);
  console.log('Applied:',id);
 }finally{try{if(locked)await db.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");}finally{await db.end();}}
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('1GF migration refused:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
