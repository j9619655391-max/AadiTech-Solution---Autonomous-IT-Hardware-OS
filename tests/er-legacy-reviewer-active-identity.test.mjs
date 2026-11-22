import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

// Phase 1ER is an app-local authorization contract, not independent certification.
// Every legacy reviewer queue/detail/decision must require ACTIVE *identities*
// as well as the workflow-specific ACTIVE owner->reviewer grant.
const reviewerSources=Object.freeze({
  quotes:4, procurement:5, intake:3, dispatch:5,
  evidenceChain:5, stockFoundation:3, journalFoundation:3
});
test('Phase 1ER legacy reviewer scope checks require active OWNER and REVIEWER identities',()=>{
  for(const [family,count] of Object.entries(reviewerSources)){
    const source=readFileSync('server/'+family+'/reviewRouter.ts','utf8');
    const queries=[...source.matchAll(/FROM app_reviewer_scope_grants(?:[ \\t]+(?:g|scope_grant))?([\\s\\S]*?)\\bWHERE\\b/g)];
    assert.equal(queries.length,count,family+': all grant checks must be inspected');
    for(const [index,match] of queries.entries()){
      const sql=match[1];
      for(const clause of [
        'JOIN auth_users scope_owner ON scope_owner.id=',
        "scope_owner.role='OWNER'",
        "scope_owner.status='ACTIVE'",
        'JOIN auth_users scope_reviewer ON scope_reviewer.id=',
        "scope_reviewer.role='REVIEWER'",
        "scope_reviewer.status='ACTIVE'"
      ])assert.ok(sql.includes(clause),family+' grant '+(index+1)+' missing '+clause);
    }
    assert.equal(source.split('FROM app_reviewer_scope_grants').length-1,count);
  }
});
