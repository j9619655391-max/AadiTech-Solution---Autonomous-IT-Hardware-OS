import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
 validateTicketCreate,validateTicketTransition,ServiceTicketInputError,isInternalTicketStatus,boundedInternalTicketHistory,parseInternalTicketHistoryCursor
} from '../server/serviceDesk/validation';
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
 assert.match(route,/boundedInternalTicketHistory\(newestFirst\)/);
 assert.equal((route.match(/db\.getConnection\(\)\.catch\(\(\)=>null\)/g)||[]).length,2);
 assert.match(route,/historyWindow,mode:'INTERNAL_HELD',externalDispatchEnabled:false/);
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
