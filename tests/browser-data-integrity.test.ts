import test from 'node:test';
import assert from 'node:assert/strict';

test('fresh browser begins empty and cannot claim release authority',async()=>{
 const data=new Map<string,string>();
 const local={
  getItem:(key:string)=>data.get(key)??null,
  setItem:(key:string,value:string)=>{data.set(key,value);},
  removeItem:(key:string)=>{data.delete(key);},
  clear:()=>{data.clear();}
 };
 (globalThis as any).localStorage=local;
 const {storageService,DEFAULT_COMPANY_PROFILE}=await import('../src/services/storageService');
 const loaders=['loadLeads','loadCustomers','loadProducts','loadQuotations',
  'loadPurchaseOrders','loadInventory','loadSuppliers','loadRfqs','loadWarranties',
  'loadAMCs','loadTickets','loadTelegramMessages','loadCampaigns','loadGeMTenders',
  'loadOutboundTargets','loadHardwareRefreshAssets','loadAuditLogs',
  'loadSalesOrders','loadWorkOrders','loadRMAs','loadPartners',
  'loadDealRegistrations','loadCommissions','loadWorkflowRules',
  'loadEventBusMessages','loadKnowledgeDocs','loadDeadStock','loadDemandForecasts',
  'loadNextBestActions','loadTenants','loadDeadLetterJobs','loadIntegrations'];
 for(const method of loaders)assert.deepEqual((storageService as any)[method](),[],
  method+' must not auto-seed business data');
 for(const k of ['gstin','pan','accountNumber','ifscCode','upiId'])
  assert.equal((DEFAULT_COMPANY_PROFILE as any)[k],'');
 assert.equal(storageService.getEnvironmentMode(),'TESTING');
 assert.throws(()=>storageService.setEnvironmentMode('PRODUCTION'),/requires independently/);
 assert.throws(()=>storageService.wipeToCleanProductionState(),/disabled/);
 assert.throws(()=>storageService.resetAllData(),/Explicit confirmation/);
 assert.throws(()=>storageService.loadTestingDemoState(),/Explicit confirmation/);
 local.setItem('aaditech_leads',JSON.stringify([{id:'keep-me'}]));
 assert.equal(storageService.loadLeads()[0].id,'keep-me');
 assert.throws(()=>storageService.wipeToCleanProductionState(),/disabled/);
 assert.equal(storageService.loadLeads()[0].id,'keep-me');
});
