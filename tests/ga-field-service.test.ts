import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validateHeldFieldPlan} from '../server/fieldService/validation';
import {fieldServiceMigrationTarget} from '../scripts/migrate-field-service';
import {MIGRATIONS} from '../scripts/lib/stagingPreflight';
const body={ticketId:'123e4567-e89b-42d3-a456-426614174000',expectedTicketVersion:2,kind:'WORK_ORDER',note:'Internal review only',acknowledgeUnverifiedAuthority:true};
test('1GA field plan admission is strict held-only and denies authority smuggling',()=>{
 assert.equal(validateHeldFieldPlan(body).kind,'WORK_ORDER');
 assert.equal(validateHeldFieldPlan({...body,kind:'RMA'}).kind,'RMA');
 for(const bad of [
  {...body,kind:'APPROVED'}, {...body,ticketId:'not-id'}, {...body,expectedTicketVersion:1},
  {...body,expectedTicketVersion:1000},{...body,expectedTicketVersion:'2'},
  {...body,acknowledgeUnverifiedAuthority:false},{...body,technicianId:body.ticketId},
  {...body,status:'COMPLETED'},{...body,serialNumber:'example'},{...body,externalDispatchEnabled:true},
  {...body,note:'password=ExampleSecret0123456'},{...body,note:' '},{...body,note:'a'.repeat(501)}
 ])assert.throws(()=>validateHeldFieldPlan(bad));
});
test('1GA source lock, entire M16 history and unique held create audit precede commit',()=>{
 const s=readFileSync('server/fieldService/router.ts','utf8');
 const post=s.slice(s.indexOf("router.post("));
 const order=['await lockActiveCrmOwner(','FOR UPDATE','FOR SHARE','verifyInternalTicketAuditForAppend(audit','INSERT INTO field_service_plans_internal','INSERT INTO field_service_plan_audit_internal','await conn.commit()'].map(x=>post.indexOf(x));
 assert.ok(order.every((x,i)=>x>=0&&(i===0||x>order[i-1])));
 assert.match(s,/router\.use\(requireOwner\)/);
 assert.match(s,/creator\.actor_user_id=t\.owner_user_id/);
 assert.doesNotMatch(s,/router\.patch|router\.delete|UPDATE field_service|child_process|nodemailer/);
 assert.match(s,/externalDispatchEnabled:false,technicianAssignmentEnabled:false,replacementApprovalEnabled:false/);
 const ddl=readFileSync('database/migrations/0050_ga_field_service_plans_internal.sql','utf8');
 assert.match(ddl,/UNIQUE KEY uq_ga_ticket_kind \(ticket_id,kind\)/);
 assert.match(ddl,/ENUM\('PLANNING_HELD'\)/);
 assert.match(ddl,/plan_id CHAR\(36\) NOT NULL PRIMARY KEY/);
 assert.equal(MIGRATIONS[49],'0050_ga_field_service_plans_internal');
 assert.equal(fieldServiceMigrationTarget({CRM_TEST_DB:'1',NODE_ENV:'test',DB_NAME:'aaditech_ci',DB_SSL:'false'}),'ci');
 assert.throws(()=>fieldServiceMigrationTarget({NODE_ENV:'production',DB_NAME:'aaditech_ci'}));
});
