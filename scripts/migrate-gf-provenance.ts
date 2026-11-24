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
// Narrow grammar, not a general SQL-equivalence parser. MySQL may introduce
// a charset on the enum literal or parenthesize the comparison. Preserve
// quoted literal bytes and reject arbitrary SQL, functions and predicates.
export function verifiedGfOriginColumn(rows:readonly unknown[]):boolean{
 if(!Array.isArray(rows)||rows.length!==1||!rows[0]||typeof rows[0]!=='object')return false;
 const row=rows[0] as {EXTRA?:unknown;GENERATION_EXPRESSION?:unknown;DATA_TYPE?:unknown;CHARACTER_MAXIMUM_LENGTH?:unknown;IS_NULLABLE?:unknown;COLLATION_NAME?:unknown};
 if(typeof row.EXTRA!=='string'||row.EXTRA.trim().toUpperCase()!=='STORED GENERATED'||
    row.DATA_TYPE!=='char'||Number(row.CHARACTER_MAXIMUM_LENGTH)!==36||
    row.IS_NULLABLE!=='YES'||row.COLLATION_NAME!=='utf8mb4_unicode_ci'||
    typeof row.GENERATION_EXPRESSION!=='string'||row.GENERATION_EXPRESSION.length>512)return false;
 // MySQL 8.0.46 observed metadata has one outer parenthesis pair
 // and escaped quote delimiters, not an escaped CREATE literal value.
 // Match token boundaries, exact identifiers and paired parentheses.
 const raw=row.GENERATION_EXPRESSION.trim();
 const expression=raw.startsWith('(')&&raw.endsWith(')')?raw.slice(1,-1).trim():raw;
 const match=/^case\s+when\s+(\()?\s*(?:operation|\x60operation\x60)\s*=\s*(?:_utf8mb4|_utf8mb3|_utf8)?\s*('CREATE'|\\'CREATE\\')\s*(\))?\s+then\s+(?:entity_id|\x60entity_id\x60)(?:\s+else\s+null)?\s+end$/i.exec(expression);
 return !!match&&Boolean(match[1])===Boolean(match[3])&&
  (match[2]==="'CREATE'"||match[2]==="\\'CREATE\\'");
}
// Before applying any DDL, refuse existing named artifacts even when the
// migration ledger is absent. Never overwrite a partly installed constraint.
export async function assertGfFreshInstall(db:Pick<mysql.Connection,'query'>){
 const [rows]=await db.query<mysql.RowDataPacket[]>(`SELECT 1 AS present FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='crm_audit_events' AND COLUMN_NAME='gf_create_entity_id'
  UNION ALL SELECT 1 FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE()
   AND INDEX_NAME IN ('uq_gf_crm_create_origin','uq_gf_quote_binding')
  UNION ALL SELECT 1 FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE()
   AND (EVENT_OBJECT_TABLE='sales_quote_create_requests' OR TRIGGER_NAME IN ('trg_gf_quote_unbound_insert','trg_gf_quote_bind_once'))
  LIMIT 1`);
 if(rows.length!==0)throw Error('1GG partial or conflicting provenance installation; independent reconciliation required');
}
export async function checkInstalledGfIntegrity(db:Pick<mysql.Pool,'query'>,options:{disposableCiDiagnostics?:boolean}={}){
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
 const [columns]=await db.query<mysql.RowDataPacket[]>(`SELECT EXTRA,GENERATION_EXPRESSION,DATA_TYPE,CHARACTER_MAXIMUM_LENGTH,IS_NULLABLE,COLLATION_NAME FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='crm_audit_events' AND COLUMN_NAME='gf_create_entity_id'`);
 if(!verifiedGfOriginColumn(columns)){
  // Only the CI migration runner opts in; never log live staging metadata.
  if(options.disposableCiDiagnostics)
   console.error('1GF disposable generated-column metadata:',JSON.stringify(columns.map(row=>({
    extra:row.EXTRA,expression:String(row.GENERATION_EXPRESSION??'').slice(0,512),
    type:row.DATA_TYPE,length:row.CHARACTER_MAXIMUM_LENGTH,nullable:row.IS_NULLABLE,collation:row.COLLATION_NAME
   }))).slice(0,2048));
  throw Error('1GF generated origin expression unverified');
 }
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
    canonical(String(row.ACTION_STATEMENT))!==canonical(wanted.body)){
   if(options.disposableCiDiagnostics)
    console.error('1GF disposable trigger metadata:',JSON.stringify({
     name:row.TRIGGER_NAME,timing:row.ACTION_TIMING,event:row.EVENT_MANIPULATION,
     body:String(row.ACTION_STATEMENT??'').slice(0,4096)
    }).slice(0,8192));
   throw Error('1GF installed trigger body unverified');
  }
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
   await checkInstalledGfIntegrity(db,{disposableCiDiagnostics:true});console.log('Already applied:',id);return;
  }
  await assertGfFreshInstall(db);
  await assertGfHistoricalIntegrity(db);
  // MySQL DDL is nontransactional across statements. Partial installs are
  // intentionally not repaired or dropped; reset disposable CI after review.
  for(const sql of statements())await db.query(sql);
  await checkInstalledGfIntegrity(db,{disposableCiDiagnostics:true});
  await db.execute('INSERT INTO schema_migrations(id,checksum) VALUES (?,?)',[id,checksum]);
  console.log('Applied:',id);
 }finally{try{if(locked)await db.query("SELECT RELEASE_LOCK('aaditech-auth-migrations')");}finally{await db.end();}}
}
if(import.meta.url===new URL('file://'+process.argv[1]).href)
 main().catch(e=>{console.error('1GF migration refused:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
