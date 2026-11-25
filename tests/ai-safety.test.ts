import test from 'node:test';
import assert from 'node:assert/strict';
import {normalizeBomDraft,normalizeCampaignDraft,parseListenPort,requiredAiText}
 from '../server/ai/safety';

test('AI BOM can never report verified compatibility, pricing or GST codes',()=>{
 const r=normalizeBomDraft({title:'Office',items:[{category:'IT',name:'Laptop',qty:3,
  unitCost:500,unitSell:900,hsn:'8471'}]});
 assert.equal(r.compatibilityStatus,'FLAGGED');
 assert.equal(r.pricingVerified,false);
 assert.equal(r.compatibilityVerified,false);
 assert.equal(r.items[0].unitCost,0);
 assert.equal(r.items[0].unitSell,0);
 assert.equal(r.items[0].hsn,'');
});
test('drafts reject invalid data rather than returning fake results',()=>{
 for(const items of [[],[{category:'IT',name:'Laptop',qty:0}],
  [{category:'IT',name:'Laptop',qty:'3'}],[{category:'IT',name:'',qty:3}]]){
  assert.throws(()=>normalizeBomDraft({title:'Draft',items}));
 }
 assert.throws(()=>requiredAiText({requirement:' '.repeat(10)},'requirement'));
 assert.throws(()=>requiredAiText({requirement:'a'.repeat(2001)},'requirement'));
 assert.throws(()=>requiredAiText(null,'requirement'));
});
test('campaign outputs are never dispatchable or credited with invented revenue',()=>{
 const r=normalizeCampaignDraft({headline:'Review',whatsappMessage:'Hello',
  emailSubject:'Hello',emailBody:'Please verify',
  projectedConversion:'90%',estimatedPipelineValue:'₹10L'});
 assert.equal(r.projectedConversion,'NOT_MEASURED');
 assert.equal(r.estimatedPipelineValue,'NOT_MEASURED');
 assert.equal(r.dispatchEnabled,false);
 assert.equal(r.requiresHumanReview,true);
 assert.throws(()=>normalizeCampaignDraft({headline:'x'}));
});
test('runtime port is validated and has safe default',()=>{
 assert.equal(parseListenPort(undefined),3000);
 assert.equal(parseListenPort('3000'),3000);
 assert.equal(parseListenPort('65535'),65535);
 for(const value of ['0','65536','abc','3000px','-1',' 3000','3000 ','123456'])
  assert.throws(()=>parseListenPort(value));
});
