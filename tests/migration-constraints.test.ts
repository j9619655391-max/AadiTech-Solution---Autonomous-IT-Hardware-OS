import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {MIGRATIONS} from '../scripts/lib/stagingPreflight';
test('all registered MySQL foreign-key constraint names must be schema-wide unique',()=>{
 const used=new Map<string,string>();
 for(const migration of MIGRATIONS){
  const sql=readFileSync('database/migrations/'+migration+'.sql','utf8');
  const constraints=[...sql.matchAll(/\\bCONSTRAINT\\s+([A-Za-z0-9_]+)\\s+FOREIGN\\s+KEY/gi)]
   .map(m=>m[1].toLowerCase());
  for(const name of constraints){
   assert.equal(used.has(name),false,
    name+' must be unique: '+used.get(name)+' / '+migration);
   used.set(name,migration);
  }
 }
 assert.ok(used.has('fk_release_actor'));
 assert.ok(used.has('fk_stock_intent_preparer'));
 assert.ok(used.size>50);
});
