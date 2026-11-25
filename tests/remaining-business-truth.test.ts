import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const source=(file:string)=>readFileSync(file,'utf8');
const absent=(s:string,claims:string[],file:string)=>{
 for(const c of claims)assert.ok(!s.includes(c),file+' must not assert '+c);
};
test('legacy parent can no longer issue commercial quotation, RFQ broadcast, paid PO or unverified stock KYC',()=>{
 const file='src/App.tsx',s=source(file);
 absent(s,[
  "status: 'ISSUED'","'PENDING_APPROVAL' : 'APPROVED'",
  'NEW APPROVAL GATE DISPATCHED','RFQ_BROADCASTED','SERIAL_INWARDED',
  'PO_GENERATED','CUSTOMER_ONBOARDED','Math.random()',
  "storageService.savePurchaseOrders(updated)",
  "storageService.saveQuotations(updated)"
 ],file);
 for(const action of [
  'Customer KYC/onboarding','Verified SKU/vendor pricing registration',
  'Serial stock title and inward goods receipt','Supplier RFQ broadcast',
  'Verified CRM lead onboarding',
  'Commercial quotation pricing, GST and owner approval',
  'Issuance of supplier purchase order'
 ])assert.ok(s.includes("denyUnverifiedOperation('"+action+"')"),action);
});
test('RAG cannot output invented OEM compliance, SLA, or guaranteed source citations',()=>{
 const file='src/components/WorkflowsAndRAGView.tsx',s=source(file);
 absent(s,[
  '100% Fact Checked','MIL-STD-810G & 461E',
  'MTBF of 450,000 operational hours','4-hour on-site engineer response',
  'Live Event Ingestion','onExecuteWorkflowRule(rule.id)',
  'onToggleWorkflowRule(rule.id)','onCreateWorkflowRule(rule)'
 ],file);
 assert.match(s,/RAG Unavailable \/ No Verified Sources/);
 assert.match(s,/No authenticated source \/ no citation/);
 assert.match(s,/NOT VERIFIED — No Durable Event Broker/);
 assert.match(s,/Workflow Creation HOLD/);
 assert.match(s,/Execution HOLD/);
});
test('predictive analytics never fake-liquidate stock or report notifications dispatched',()=>{
 const file='src/components/PredictiveAnalyticsView.tsx',s=source(file);
 absent(s,[
  "status: 'LIQUIDATED' as const",
  "onUpdateDeadStock(updated)",
  "onTriggerAction(id)",
  'Liquidation order initiated for item',
  'Autonomous action executed:',
  'onClick={() => handleLiquidate',
  'onClick={() => handleActionClick',
  'Offer Executed','Dispatch Liquidation Offer'
 ],file);
 assert.match(s,/Liquidation HOLD/);
 assert.match(s,/Action HOLD/);
 assert.match(s,/No liquidation, price discount, inventory mutation or customer dispatch occurred/);
 assert.match(s,/No agent action executed or notification sent/);
 assert.match(s,/Browser-local model previews only/);
});
test('system hub cannot forge sandbox HTTP 200, tenant authorization or durable job retry',()=>{
 const file='src/components/SystemHubView.tsx',s=source(file);
 absent(s,[
  "setApiExecutionStatus('SUCCESS')",
  'Simulated 200 OK returned',
  'Dispatched retry payload for job',
  'onSwitchTenant(tenant.id)',
  'onToggleIntegration(connector.id)',
  'onRetryDeadLetterJob(jobId)',
  'Execute Sandbox Call','Re-Dispatch Webhook Payload',
  'Toggled connector state'
 ],file);
 assert.match(s,/EXAMPLE RESPONSE ONLY • NO REQUEST SENT/);
 assert.match(s,/API Execution HOLD/);
 assert.match(s,/DLQ Retry HOLD/);
 assert.match(s,/Switch HOLD/);
 assert.match(s,/Browser Tenant Preview \(Unverified\)/);
});
test('BOM server proof needed before validating compatibility and issuing a commercial quote',()=>{
 const file='src/components/SalesAndBOMBuilder.tsx',s=source(file);
 absent(s,[
  "setCompatibilityStatus('PASSED')",
  'Compatibility Matrix Cleared:',
  '<span>Create Browser-Only Quote Preview</span>',
  'fully verified Bill of Materials'
 ],file);
 assert.match(s,/NOT VERIFIED: Keyword screening is not a vendor hardware validation/);
 assert.match(s,/Commercial Quote Issuance HOLD/);
});

test('legacy procurement screen cannot turn local SKU/serial/RFQ into saleable stock or an issued PO',()=>{
 const file='src/components/ProcurementAndInventory.tsx',s=source(file);
 absent(s,[
  'state: \'AVAILABLE\',','onRaisePO(rfq.id, quote.supplierId)',
  'onClick={() => setShowAddSerialModal(true)}',
  'onClick={() => setShowAddProductModal(true)}',
  'onClick={() => setShowCreateRFQModal(true)}',
  'Issue Purchase Order (PO)',
  'Compare authorized national distributors',
 ],file);
 assert.match(s,/PO Issuance HOLD/);
 assert.match(s,/Supplier RFQ HOLD/);
 assert.match(s,/Serial Posting HOLD/);
 assert.match(s,/SKU Registration HOLD/);
 assert.match(s,/Real stock ownership and availability NOT VERIFIED/);
});
