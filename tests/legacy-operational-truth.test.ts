import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const source=(p:string)=>readFileSync(p,'utf8');
function refusesClaims(file:string,disallowed:string[]){
 const s=source(file);
 for(const claim of disallowed)
  assert.equal(s.includes(claim),false,file+' must not contain unverified claim '+claim);
}
test('executive briefing never invents revenue, profit, taxes, stock or sends faux AI fallback',()=>{
 const file='src/components/ExecutiveDashboard.tsx',s=source(file);
 refusesClaims(file,['842500','145600','17.28','14200000','₹8.42L Cleared',
  'GST Invoicing: 100%','14 quotations generated autonomously',
  '3 orders dispatched','All business operations running inside autonomous',
  '17.2% Avg Margin','Saved ₹34,200',
  'revenueToday:',"data.text || 'Query answered successfully.'"]);
 assert.match(s,/Invoiced Revenue \(Server Ledger\)/);
 assert.match(s,/Financial posting, inventory availability and external dispatch NOT VERIFIED/);
 assert.match(s,/if \(!res\.ok\) throw/);
 assert.match(s,/The server has not supplied an authoritative answer/);
 assert.match(s,/body: JSON\.stringify\(\{ query \}\)/);
});
test('finance view cannot auto-approve credit or issue invented tax/banking data',()=>{
 const file='src/components/FinanceAndServiceView.tsx',s=source(file);
 refusesClaims(file,["let creditDecision = 'APPROVE'","AUTO-RELEASE",
  'Sales order released autonomously','HDFC0000128','50200088921102',
  '27AADCS8129F1Z3','₹28,40,000','₹6,85,200','+₹14.20 Lakh',
  'GSTR-2B Verified vs Redington/Ingram']);
 assert.match(s,/HELD — INDEPENDENT SERVER REVIEW REQUIRED/);
 assert.match(s,/Current Outstanding \(browser entered\)/);
 assert.match(s,/This browser-local scenario is never a lender/);
});
test('unverified customer portal cannot impersonate sample tenants or accept/e-sign legal deals',()=>{
 const file='src/components/PortalsAndResellersView.tsx',s=source(file);
 refusesClaims(file,['FinStack Technologies','Apex Health Logistics',
  'Navi Mumbai Cold Storage Pvt Ltd','LOCKED_APPROVED',
  'onAcceptQuotation(', 'onRegisterDeal(newDeal)','onApproveCommission(comm.id)',
  'Math.random','1-Click Accept & E-Sign','Approve & Disburse']);
 assert.match(s,/Customer Portal — NOT AVAILABLE \/ RELEASE HOLD/);
 assert.match(s,/Commission Preview — No Automatic Payout/);
 assert.match(s,/Deal Registration HOLD/);
});
test('legacy logistics has no outbound dispatch/order mutation or generated carrier and tax document IDs',()=>{
 const file='src/components/OrdersAndLogisticsView.tsx',s=source(file);
 refusesClaims(file,['Math.random','onDispatchOrder(',
  'onUpdateOrderStatus(', 'onCreateWorkOrder(', 'onAddRMA(',
  'onUpdateWorkOrderStatus(', 'onToggleWorkOrderChecklist(',
  'Generate Dispatch & Transmit AWB','Confirm Dispatch & Transmit',
  'Generate Work Order','Initiate RMA & Pickup','Live AWB Sync']);
 assert.match(s,/This legacy view has no server-authorized outbound logistics/);
 assert.match(s,/Dispatch HARD HOLD/);
 assert.match(s,/Delivery confirmation requires carrier-signed proof/);
 assert.match(s,/Browser-only Order Preview Total/);
});

test('central App callback layer denies legacy business side effects even if child UI invokes handlers',()=>{
 const file='src/App.tsx',s=source(file);
 refusesClaims(file,[
  'irn_1794875710749_nic_einvoice_verified',
  "payoutStatus: 'PAID' as const",
  "fulfillmentStatus: 'DISPATCHED' as const",
  "status: 'WON' as const",
  'customerGst: \'27AABCF1290K1ZP\'',
  'storageService.saveSalesOrders(updated)',
  'storageService.saveCommissions(updated)',
  "action: 'ORDER_DISPATCHED'",
  "action: 'ORDER_CONVERTED_FROM_QUOTE'",
  "action: 'DEAL_REGISTERED'"
 ]);
 for(const action of [
  'AMC renewal quote dispatch','Customer quotation e-sign and sales order conversion',
  'Carrier dispatch and GST e-Way bill','Partner commission settlement',
  'Workflow execution and outbound dispatch','External integration connect/disconnect',
  'Failed job retry','Tenant context switch',
  'Work order/customer acceptance','RMA/replacement initiation'
 ])assert.ok(s.includes("denyUnverifiedOperation('"+action+"')"),
  'missing central denial for '+action);
 assert.match(s,/No transaction, message, payment, stock movement or legal document was created/);
});
