import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
 validateTicketCreate,validateTicketTransition,ServiceTicketInputError,isInternalTicketStatus,boundedInternalTicketHistory,parseInternalTicketHistoryCursor,verifyInternalTicketAuditWindow,rejectCredentialLikeTicketText,maskCredentialLikeTicketText,INTERNAL_TICKET_MASK
} from '../server/serviceDesk/validation';
import {computeInternalAuditFingerprint,MAX_INTERNAL_AUDIT_FINGERPRINT_EVENTS,InternalAuditFingerprintLimitError} from '../server/serviceDesk/fingerprint';
import {serviceTicketMigrationTarget} from '../scripts/migrate-service-tickets';
import {MIGRATIONS} from '../scripts/lib/stagingPreflight';
const customerId='123e4567-e89b-42d3-a456-426614174000';
const create={
 customerId,guideId:'wifi-no-internet',subject:' Office Wi-Fi fails ',
 description:'Observed connectivity problem only',priority:'NORMAL',
 acknowledgeUnverifiedConsent:true
};
test('1FN internal ticket intake requires existing guide, canonical CRM ID and unverified consent disclaimer',()=>{
 assert.deepEqual(validateTicketCreate(create),{
  customerId,guideId:'wifi-no-internet',subject:'Office Wi-Fi fails',
  description:'Observed connectivity problem only',priority:'NORMAL'
 });
 for(const changed of [
  {...create,acknowledgeUnverifiedConsent:false},
  {...create,acknowledgeUnverifiedConsent:'true'},
  {...create,customerId:'not-a-uuid'},
  {...create,guideId:'arbitrary-code'},
  {...create,priority:'CRITICAL'},
  {...create,subject:' '},{...create,description:'bad\u0000content'},
  {...create,subject:'X'.repeat(181)},
  {...create,description:'X'.repeat(2001)},
  {...create,customerConsentState:'VERIFIED'},
  {...create,externalDispatchState:'ENABLED'},
  {...create,status:'CLOSED'},
  {...create,technicianId:customerId}
 ])assert.throws(()=>validateTicketCreate(changed),ServiceTicketInputError);
 assert.throws(()=>validateTicketCreate([]),ServiceTicketInputError);
});
test('1FN status transitions are held-only, strictly versioned, and do not allow arbitrary repair completion',()=>{
 const allowed=[
  ['OPEN_INTERNAL','TRIAGED_INTERNAL'],
  ['TRIAGED_INTERNAL','WAITING_INTERNAL'],
  ['WAITING_INTERNAL','TRIAGED_INTERNAL'],
  ['TRIAGED_INTERNAL','RESOLVED_HELD']
 ] as const;
 for(const [current,nextStatus] of allowed){
  assert.deepEqual(validateTicketTransition({expectedVersion:1,nextStatus,note:'Internal only'},current),
   {expectedVersion:1,nextStatus,note:'Internal only'});
 }
 for(const [current,nextStatus] of [
  ['OPEN_INTERNAL','RESOLVED_HELD'],['OPEN_INTERNAL','WAITING_INTERNAL'],
  ['RESOLVED_HELD','TRIAGED_INTERNAL'],['TRIAGED_INTERNAL','CLOSED'],
  ['WAITING_INTERNAL','RESOLVED_HELD']
 ] as const) assert.throws(()=>validateTicketTransition({
  expectedVersion:1,nextStatus,note:'Unsupported'},current),ServiceTicketInputError);
 for(const body of [
  {expectedVersion:0,nextStatus:'TRIAGED_INTERNAL',note:'n'},
  {expectedVersion:1.5,nextStatus:'TRIAGED_INTERNAL',note:'n'},
  {expectedVersion:1,nextStatus:'TRIAGED_INTERNAL',note:''},
  {expectedVersion:1,nextStatus:'TRIAGED_INTERNAL',note:'x'.repeat(501)},
  {expectedVersion:1,nextStatus:'TRIAGED_INTERNAL',note:'n',externalDispatchState:'ENABLED'}
 ])assert.throws(()=>validateTicketTransition(body,'OPEN_INTERNAL'),ServiceTicketInputError);
 assert.equal(isInternalTicketStatus('RESOLVED_HELD'),true);
 assert.equal(isInternalTicketStatus('CLOSED'),false);
});
test('1FN schema migration requires disposable CI or specifically approved isolated TLS staging',()=>{
 const ci={NODE_ENV:'test',DB_NAME:'aaditech_ci',DB_SSL:'false',CRM_TEST_DB:'1'};
 assert.equal(serviceTicketMigrationTarget(ci),'ci');
 const staging={NODE_ENV:'staging',DB_NAME:'aaditech_staging_ticket_ci',DB_SSL:'true',
  SERVICE_TICKETS_MIGRATION_APPROVED:'YES',STAGING_DISPOSABLE_CONFIRMED:'YES'};
 assert.equal(serviceTicketMigrationTarget(staging),'staging');
 for(const denied of [
  {...ci,DB_NAME:'aaditech_prod'},{...ci,DB_SSL:'true'},
  {...ci,NODE_ENV:'production'}, {...staging,NODE_ENV:'production'},
  {...staging,SERVICE_TICKETS_MIGRATION_APPROVED:'NO'},
  {...staging,STAGING_DISPOSABLE_CONFIRMED:'NO'},
  {...staging,DB_NAME:'aaditech_production'},
  {...staging,DB_SSL:'false'}
 ])assert.throws(()=>serviceTicketMigrationTarget(denied));
 assert.equal(MIGRATIONS.at(-1),'0049_fn_service_tickets_internal');
 const ddl=readFileSync('database/migrations/0049_fn_service_tickets_internal.sql','utf8');
 assert.match(ddl,/external_dispatch_state ENUM\('DISABLED'\)/);
 assert.match(ddl,/customer_consent_state ENUM\('UNVERIFIED'\)/);
 assert.match(ddl,/UNIQUE KEY uq_service_ticket_audit_version/);
});
test('1FN routes have no external action and lock actor before internal mutations',()=>{
 const api=readFileSync('server/serviceDesk/router.ts','utf8');
 const app=readFileSync('server.ts','utf8');
 assert.match(api,/router\.use\(requireOwner\)/);
 assert.match(api,/await lockActiveCrmOwner\(conn,res\.locals\.auth\.userId\)/);
 assert.match(api,/creator\.actor_user_id/);
 assert.match(api,/t\.owner_user_id=\?/);
 assert.match(api,/version=version\+1/);
 assert.match(api,/externalDispatchEnabled:false/);
 assert.doesNotMatch(api,/router\.delete|child_process|fetch\(|axios|nodemailer|twilio|smtp|sendEmail/);
 assert.match(app,/app\.use\("\/api\/service-desk\/internal-tickets",internalServiceDeskRouter\)/);
});

test('1FP ticket audit detail bounds newest events and retains chronological display order',()=>{
 const newest=Array.from({length:101},(_,index)=>({versionAfter:101-index}));
 const over=boundedInternalTicketHistory(newest);
 assert.equal(over.historyLimit,100);
 assert.equal(over.historyHasMore,true);
 assert.equal(over.nextBeforeVersion,2);
 assert.equal(over.history.length,100);
 assert.deepEqual(over.history.map(x=>x.versionAfter),Array.from({length:100},(_,i)=>i+2));
 const small=boundedInternalTicketHistory(newest.slice(-5));
 assert.equal(small.historyHasMore,false);
 assert.equal(small.nextBeforeVersion,null);
 assert.deepEqual(small.history.map(x=>x.versionAfter),[1,2,3,4,5]);
 assert.deepEqual(boundedInternalTicketHistory([]),{
  history:[],historyLimit:100,historyHasMore:false,nextBeforeVersion:null
 });
 assert.throws(()=>boundedInternalTicketHistory(Array(102).fill({versionAfter:1})),/bound/);
 const route=readFileSync('server/serviceDesk/router.ts','utf8');
 assert.match(route,/ORDER BY a\.version_after DESC LIMIT 101/);
 assert.match(route,/verifyInternalTicketAuditWindow\(newestFirst,/);
 assert.equal((route.match(/db\.getConnection\(\)\.catch\(\(\)=>null\)/g)||[]).length,2);
 assert.match(route,/ticket:maskedTicket\(data\.ticket\),history:maskedAuditHistory\(data\.history\),mode:'INTERNAL_HELD'/);
});

test('1FQ keyset history cursor rejects array, query pollution, zero and noncanonical integer',()=>{
 assert.equal(parseInternalTicketHistoryCursor({beforeVersion:'1'}),1);
 assert.equal(parseInternalTicketHistoryCursor({beforeVersion:'2147483647'}),2147483647);
 for(const query of [null,{},[],{beforeVersion:''},{beforeVersion:0},
  {beforeVersion:'0'},{beforeVersion:'01'},{beforeVersion:'-1'},
  {beforeVersion:'1.0'},{beforeVersion:'1e2'},{beforeVersion:' 1'},
  {beforeVersion:'2147483648'},{beforeVersion:'99999999999'},
  {beforeVersion:['3','4']},{beforeVersion:{gt:3}},
  {beforeVersion:'4',limit:'99999'},{beforeVersion:'4',offset:'200'}
 ])assert.throws(()=>parseInternalTicketHistoryCursor(query),ServiceTicketInputError);
});
test('1FQ bounded history fails closed on inconsistent event version order',()=>{
 const corrupt=[[{versionAfter:2},{versionAfter:2}],
  [{versionAfter:2},{versionAfter:3}],
  [{versionAfter:0}],[{versionAfter:1.1}],[{versionAfter:NaN}]];
 for(const rows of corrupt)assert.throws(()=>boundedInternalTicketHistory(rows),/integrity/);
 const safe=boundedInternalTicketHistory(Array.from({length:101},(_,i)=>({versionAfter:201-i})));
 assert.equal(safe.history.length,100);
 assert.equal(safe.nextBeforeVersion,102);
 assert.equal(safe.historyHasMore,true);
 const route=readFileSync('server/serviceDesk/router.ts','utf8');
 assert.match(route,/router\.get\('\/:id\/history'/);
 assert.match(route,/parseInternalTicketHistoryCursor\(req\.query\)/);
 assert.match(route,/a\.version_after<\?/);
 assert.match(route,/t\.owner_user_id=\?/);
 assert.match(route,/creator\.actor_user_id=t\.owner_user_id/);
 assert.match(route,/ORDER BY a\.version_after DESC LIMIT 101/);
 const ui=readFileSync('src/components/LiveServiceDeskWorkspace.tsx','utf8');
 assert.match(ui,/history\?beforeVersion=/);
 assert.match(ui,/Load older 100 entries/);
 assert.match(ui,/Return to latest/);
});

test('1FR every bounded audit window is a contiguous permitted status chain anchored to ticket version',()=>{
 type Event={versionAfter:number;operation:'CREATE'|'STATUS_CHANGE';
  fromStatus:'OPEN_INTERNAL'|'TRIAGED_INTERNAL'|'WAITING_INTERNAL'|'RESOLVED_HELD'|null;
  toStatus:'OPEN_INTERNAL'|'TRIAGED_INTERNAL'|'WAITING_INTERNAL'|'RESOLVED_HELD'};
 const state=(v:number):Event['toStatus']=>v===1?'OPEN_INTERNAL':
  v%2===0?'TRIAGED_INTERNAL':'WAITING_INTERNAL';
 const newest:Event[]=Array.from({length:101},(_,i)=>{
  const v=101-i;
  return {versionAfter:v,operation:v===1?'CREATE':'STATUS_CHANGE',
   fromStatus:v===1?null:state(v-1),toStatus:state(v)};
 });
 const first=verifyInternalTicketAuditWindow(newest,{currentVersion:101,currentStatus:state(101)});
 assert.equal(first.historyHasMore,true);
 assert.equal(first.nextBeforeVersion,2);
 assert.deepEqual(first.history.map(e=>e.versionAfter),Array.from({length:100},(_,i)=>i+2));
 const older=verifyInternalTicketAuditWindow(newest.slice(-1),{
  currentVersion:101,currentStatus:state(101),beforeVersion:2});
 assert.deepEqual(older.history.map(e=>e.versionAfter),[1]);
 assert.equal(older.historyHasMore,false);
 assert.deepEqual(verifyInternalTicketAuditWindow([],{
  currentVersion:101,currentStatus:state(101),beforeVersion:1}).history,[]);
 for(const scenario of [
  {rows:newest,ctx:{currentVersion:102,currentStatus:state(101)}},
  {rows:newest,ctx:{currentVersion:101,currentStatus:'TRIAGED_INTERNAL' as const}},
  {rows:newest.slice(0,-1),ctx:{currentVersion:101,currentStatus:state(101)}},
  {rows:newest.slice(-1),ctx:{currentVersion:101,currentStatus:state(101)}},
  {rows:[] as Event[],ctx:{currentVersion:101,currentStatus:state(101)}},
  {rows:newest.slice(-1),ctx:{currentVersion:101,currentStatus:state(101),beforeVersion:3}},
  {rows:newest,ctx:{currentVersion:101,currentStatus:state(101),beforeVersion:103}}
 ])assert.throws(()=>verifyInternalTicketAuditWindow(scenario.rows,scenario.ctx),/1FR/);
 const tamper=(index:number,patch:Partial<Event>)=>newest.map((e,i)=>i===index?{...e,...patch}:e);
 for(const rows of [
  tamper(100,{versionAfter:0}),
  tamper(1,{toStatus:'OPEN_INTERNAL'}),
  tamper(0,{operation:'CREATE'}),
  tamper(0,{fromStatus:'OPEN_INTERNAL'}),
  tamper(100,{operation:'STATUS_CHANGE'}),
  tamper(20,{versionAfter:79}),
  tamper(40,{toStatus:'RESOLVED_HELD'}),
  tamper(50,{fromStatus:'RESOLVED_HELD'})
 ])assert.throws(()=>verifyInternalTicketAuditWindow(rows,{
  currentVersion:101,currentStatus:state(101)}),/1FR|integrity/);
});
test('1FR ticket detail and older pages use same read-only consistent snapshot, no cross-pool mixing',()=>{
 const route=readFileSync('server/serviceDesk/router.ts','utf8');
 assert.match(route,/export async function readInternalTicketSnapshot/);
 assert.match(route,/SET TRANSACTION ISOLATION LEVEL REPEATABLE READ/);
 assert.match(route,/START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY/);
 assert.match(route,/await conn\.commit\(\);started=false/);
 assert.match(route,/if\(started\)await conn\.rollback\(\)\.catch\(\(\)=>\{\}\)/);
 assert.match(route,/finally\{conn\.release\(\);\}/);
 assert.equal((route.match(/await readInternalTicketSnapshot\(db,async\(conn\)=>/g)||[]).length,3,
  '1FR detail, older history and 1FS fingerprint each use an authorized read-only DB snapshot');
 assert.equal((route.match(/verifyInternalTicketAuditWindow\(newestFirst,/g)||[]).length,2);
 assert.match(route,/beforeVersion>eligible\[0\]\.version\+1/);
});

test('1FS bounded unsigned audit fingerprint is reproducible, sensitive to edits and never a real signature',async()=>{
 type State='OPEN_INTERNAL'|'TRIAGED_INTERNAL'|'WAITING_INTERNAL'|'RESOLVED_HELD';
 const status=(v:number):State=>v===1?'OPEN_INTERNAL':v%2===0?'TRIAGED_INTERNAL':'WAITING_INTERNAL';
 type Audit={versionAfter:number;operation:'CREATE'|'STATUS_CHANGE';fromStatus:State|null;
  toStatus:State;note:string;createdAtSql:string};
 const records:Audit[]=Array.from({length:103},(_,i)=>{
  const v=i+1;
  return {versionAfter:v,operation:v===1?'CREATE':'STATUS_CHANGE',
   fromStatus:v===1?null:status(v-1),toStatus:status(v),
   note:'Synthetic internal event '+v,createdAtSql:'2026-11-24 00:01:01.000000'};
 });
 const ticket={id:customerId,version:103,status:status(103)};
 let windows=0;
 const scan=async(beforeVersion?:number)=>{
  windows++;
  return [...records].reverse().filter(e=>beforeVersion===undefined||e.versionAfter<beforeVersion).slice(0,101);
 };
 const a=await computeInternalAuditFingerprint(ticket,scan);
 assert.equal(a.eventCount,103);assert.equal(a.latestVersion,103);
 assert.equal(a.mode,'INTERNAL_HELD');assert.equal(a.externalDispatchEnabled,false);
 assert.equal(a.scope,'APPLICATION_UNATTESTED');assert.equal(a.signatureVerified,false);
 assert.equal(a.externalAnchorVerified,false);assert.equal(a.customerConsentVerified,false);
 assert.equal(a.algorithm,'SHA-256');assert.match(a.auditDigestSha256,/^[a-f0-9]{64}$/);
 assert.equal(windows,2);
 const duplicate=await computeInternalAuditFingerprint(ticket,scan);
 assert.equal(a.auditDigestSha256,duplicate.auditDigestSha256);
 records[41].note='Synthetic correction: note content changed';
 const changed=await computeInternalAuditFingerprint(ticket,scan);
 assert.notEqual(a.auditDigestSha256,changed.auditDigestSha256,
  'A local hash can detect edited data only if the previous digest is independently trusted');
 records[41].note='Synthetic internal event 42';
 const record=records.splice(40,1)[0];
 await assert.rejects(computeInternalAuditFingerprint(ticket,scan),/1FR|1FS|integrity/);
 records.splice(40,0,record);
 const original=records[0].createdAtSql;records[0].createdAtSql='24/11/2026';
 await assert.rejects(computeInternalAuditFingerprint(ticket,scan),/1FS/);
 records[0].createdAtSql=original;
 assert.equal((await computeInternalAuditFingerprint(ticket,scan)).eventCount,103);
 let read=false;
 await assert.rejects(computeInternalAuditFingerprint({
  ...ticket,version:MAX_INTERNAL_AUDIT_FINGERPRINT_EVENTS+1},async()=>{
  read=true;return records;
 }),InternalAuditFingerprintLimitError);
 assert.equal(read,false,'oversized audit must reject before issuing unbounded SQL');
});
test('1FS SHA256 audit endpoint source enforces owner, bounded query, unsigned scope and no DML',()=>{
 const router=readFileSync('server/serviceDesk/router.ts','utf8');
 const fingerprint=readFileSync('server/serviceDesk/fingerprint.ts','utf8');
 assert.match(router,/router\.get\('\/:id\/audit-fingerprint'/);
 assert.match(router,/await readInternalTicketSnapshot\(db,async\(conn\)=>/);
 assert.match(router,/computeInternalAuditFingerprint\(/);
 assert.match(router,/DATE_FORMAT\(a\.created_at,/);
 assert.match(router,/a\.version_after DESC LIMIT 101/);
 assert.match(router,/JOIN service_tickets_internal t ON t\.id=a\.ticket_id/);
 assert.match(router,/t\.owner_user_id=\?/);
 assert.match(router,/creator\.actor_user_id=t\.owner_user_id/);
 assert.match(router,/InternalAuditFingerprintLimitError/);
 assert.match(fingerprint,/MAX_INTERNAL_AUDIT_FINGERPRINT_EVENTS=1000/);
 assert.match(fingerprint,/scope:'APPLICATION_UNATTESTED'/);
 assert.match(fingerprint,/signatureVerified:false/);
 assert.match(fingerprint,/externalAnchorVerified:false/);
 assert.match(fingerprint,/customerConsentVerified:false/);
 assert.doesNotMatch(fingerprint,/INSERT INTO|UPDATE service_ticket|DELETE FROM|nodemailer|smtp|sendEmail/);
});

test('1FT ticket admission blocks high-confidence credentials but permits ordinary diagnostic language',()=>{
 const dangerous=[
  '-----BEGIN OPENSSH PRIVATE KEY-----\\nci-only-fake-value',
  'AWS access reference AKIA'+'A'.repeat(16),
  'CI personal access token ghp_'+'Z'.repeat(26),
  'github_pat_'+'B'.repeat(40),
  'authorization: Bearer '+'A'.repeat(32),
  'aaditech_session='+'q'.repeat(32),
  'password=SuperSecret123456789!',
  'api_key=A1b2C3d4E5f6G7h8',
  'client_secret=someVeryLongSecretXYZ123',
  'header eyJabcdefghi.eyJklmnopqr.abcdefghijklmn',
  'Slack xoxb-'+'1'.repeat(26)
 ];
 for(const secret of dangerous){
  assert.throws(()=>rejectCredentialLikeTicketText(secret),ServiceTicketInputError,
   'High-confidence credential pattern unexpectedly admitted');
  for(const input of [
   {...create,subject:secret},
   {...create,description:'Synthetic IT support observation: '+secret}
  ])assert.throws(()=>validateTicketCreate(input),ServiceTicketInputError);
  assert.throws(()=>validateTicketTransition({
   expectedVersion:1,nextStatus:'TRIAGED_INTERNAL',note:secret
  },'OPEN_INTERNAL'),ServiceTicketInputError);
 }
 for(const safe of [
  'User reports password reset loop; do not collect passwords',
  'API key rotation needed: key not shared',
  'Laptop Wi-Fi connection fails after reboot',
  'SSO access token expired and needs official rotation',
  'Customer consent is unverified; no outreach performed',
  'The auth token was revoked; no credentials captured'
 ]){
  assert.doesNotThrow(()=>rejectCredentialLikeTicketText(safe));
  assert.equal(validateTicketCreate({...create,description:safe}).description,safe);
  assert.equal(validateTicketTransition({
   expectedVersion:1,nextStatus:'TRIAGED_INTERNAL',note:safe
  },'OPEN_INTERNAL').note,safe);
 }
 const router=readFileSync('server/serviceDesk/router.ts','utf8');
 const validator=readFileSync('server/serviceDesk/validation.ts','utf8');
 assert.match(validator,/rejectCredentialLikeTicketText\(v\)/);
 assert.match(validator,/Credential-like content is not allowed/);
 assert.match(router,/validateTicketCreate\(req\.body\)/);
 assert.match(router,/validateTicketTransition\(req\.body,old\.status\)/);
 assert.doesNotMatch(router,/sendEmail|customerConsentState:'VERIFIED'/);
});

test('1FU mask risky legacy ticket fields without modifying source records or disclosing substrings',()=>{
 const unsafe=[
  'Internal note password=SuperSecret123456789!',
  'legacy GitHub token ghp_'+'Z'.repeat(30),
  'Bearer legacy authorization: Bearer '+'Q'.repeat(40),
  '-----BEGIN RSA PRIVATE KEY-----'
 ];
 for(const source of unsafe){
  const masked=maskCredentialLikeTicketText(source);
  assert.equal(masked.redacted,true);
  assert.equal(masked.text,INTERNAL_TICKET_MASK);
  assert.ok(!masked.text.includes(source.slice(-12)),'Never keep a potentially sensitive suffix');
 }
 for(const safe of ['Wi-Fi drops under load','No credentials captured','Password reset failed; no password shared']){
  assert.deepEqual(maskCredentialLikeTicketText(safe),{text:safe,redacted:false});
 }
 for(const broken of [null,undefined,44,[],{}]){
  assert.throws(()=>maskCredentialLikeTicketText(broken),/integrity/);
 }
 const route=readFileSync('server/serviceDesk/router.ts','utf8');
 assert.match(route,/function maskedTicket\(row:RowDataPacket\)/);
 assert.match(route,/function maskedAuditHistory/);
 assert.match(route,/rows\.map\(maskedTicket\)/);
 assert.match(route,/ticket:maskedTicket\(data\.ticket\)/);
 assert.equal((route.match(/history:maskedAuditHistory\(data\.history\)/g)||[]).length,2,
  'Both current detail and historic cursor API must mask audit notes');
 assert.match(route,/noteRedacted:note\.redacted/);
 const ui=readFileSync('src/components/LiveServiceDeskWorkspace.tsx','utf8');
 assert.match(ui,/legacy credential risk masked/);
 assert.match(ui,/subjectRedacted/);
});
