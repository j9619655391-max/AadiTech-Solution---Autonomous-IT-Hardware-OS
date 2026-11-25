import { authenticatedFetch } from './services/authClient';
import React, { useState } from 'react';
import { Header } from './components/Header';
import {InternalPlanningWorkspace} from './components/InternalPlanningWorkspace';
import {planningTabs} from './services/internalPlanningCatalog';
import { TelegramCommandHub } from './components/TelegramCommandHub';
import { ExecutiveDashboard } from './components/ExecutiveDashboard';
import { CRMAndLeadsView } from './components/CRMAndLeadsView';
import { LiveCRMWorkspace } from './components/LiveCRMWorkspace';
import { LiveInventoryWorkspace } from './components/LiveInventoryWorkspace';
import { LiveProcurementWorkspace } from './components/LiveProcurementWorkspace';
import { InboundObservationWorkspace } from './components/InboundObservationWorkspace';
import { SupplierDispatchOwnerPanel } from './components/SupplierDispatchOwnerPanel';
import { SupplierEvidenceOwnerPanel } from './components/SupplierEvidenceOwnerPanel';
import { StockFoundationOwnerPanel } from './components/StockFoundationOwnerPanel';
import { JournalFoundationOwnerPanel } from './components/JournalFoundationOwnerPanel';
import { SignedProofOwnerPanel } from './components/SignedProofOwnerPanel';
import { KeyLifecycleOwnerPanel } from './components/KeyLifecycleOwnerPanel';
import { ExternalTrustOwnerPanel } from './components/ExternalTrustOwnerPanel';
import { ProviderBridgeOwnerPanel } from './components/ProviderBridgeOwnerPanel';
import { ProviderSandboxOwnerPanel } from './components/ProviderSandboxOwnerPanel';
import { ProviderSelectionOwnerPanel } from './components/ProviderSelectionOwnerPanel';
import { ProviderOnboardingOwnerPanel } from './components/ProviderOnboardingOwnerPanel';
import { SalesAndBOMBuilder } from './components/SalesAndBOMBuilder';
import { LiveBOMWorkspace } from './components/LiveBOMWorkspace';
import { QuotationAndNegotiation } from './components/QuotationAndNegotiation';
import { ApprovalEngineView } from './components/ApprovalEngineView';
import { ProcurementAndInventory } from './components/ProcurementAndInventory';
import { OrdersAndLogisticsView } from './components/OrdersAndLogisticsView';
import { PortalsAndResellersView } from './components/PortalsAndResellersView';
import { WorkflowsAndRAGView } from './components/WorkflowsAndRAGView';
import { FinanceAndServiceView } from './components/FinanceAndServiceView';
import { WindowsTroubleshootingWorkspace } from './components/WindowsTroubleshootingWorkspace';
import { LiveServiceDeskWorkspace } from './components/LiveServiceDeskWorkspace';
import { MarketingAndAgentView } from './components/MarketingAndAgentView';
import { PredictiveAnalyticsView } from './components/PredictiveAnalyticsView';
import { SystemHubView } from './components/SystemHubView';
import { CompanySettingsModal } from './components/CompanySettingsModal';
import { ResetAndEnvironmentModal } from './components/ResetAndEnvironmentModal';
import { storageService } from './services/storageService';

import {
  INITIAL_AI_AGENTS,
  INITIAL_SALES_FORECAST,
  INITIAL_CASH_FLOW_FORECAST,
  INITIAL_LOST_DEALS,
  INITIAL_CUSTOMER_LTVS,
  INITIAL_USER_ROLES,
  INITIAL_SYSTEM_HEALTH,
  INITIAL_API_ENDPOINTS
} from './data/mockData';

import {
  Lead,
  Customer360,
  Product,
  Quotation,
  TelegramMessage,
  TelegramApprovalCard,
  BOMItem,
  Supplier,
  RFQ,
  SerialInventory,
  WarrantyAsset,
  AMCContract,
  ServiceTicket,
  MarketingCampaign,
  AIAgent,
  AuditEvent,
  PurchaseOrder,
  CompanyProfile,
  SalesOrder,
  InstallationWorkOrder,
  RMARequest,
  PartnerAccount,
  DealRegistration,
  CommissionRecord,
  WorkflowRule,
  EventBusMessage,
  KnowledgeDocument,
  DeadStockItem,
  DemandForecast,
  NextBestAction,
  TenantAccount,
  DeadLetterJob,
  IntegrationConnector,
  GeMTenderBid,
  OutboundProspectAccount,
  HardwareRefreshAsset
} from './types';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [crmViewMode, setCrmViewMode] = useState<'live' | 'legacy'>('live');
  const [bomViewMode, setBomViewMode] = useState<'live' | 'legacy'>('live');
  const [isTelegramDrawerOpen, setIsTelegramDrawerOpen] = useState<boolean>(false);
  const [isSettingsModalOpen, setIsSettingsModalOpen] = useState<boolean>(false);
  const [isResetModalOpen, setIsResetModalOpen] = useState<boolean>(false);
  const [environmentMode, setEnvironmentMode] = useState<'TESTING' | 'PRODUCTION'>(() => storageService.getEnvironmentMode());

  // Core Data State backed by storageService (AadiTech Solution Real Business Data)
  const [companyProfile, setCompanyProfile] = useState<CompanyProfile>(() => storageService.loadCompanyProfile());
  const [leads, setLeads] = useState<Lead[]>(() => storageService.loadLeads());
  const [customers, setCustomers] = useState<Customer360[]>(() => storageService.loadCustomers());
  const [products, setProducts] = useState<Product[]>(() => storageService.loadProducts());
  const [quotations, setQuotations] = useState<Quotation[]>(() => storageService.loadQuotations());
  const [purchaseOrders, setPurchaseOrders] = useState<PurchaseOrder[]>(() => storageService.loadPurchaseOrders());
  const [telegramMessages, setTelegramMessages] = useState<TelegramMessage[]>(() => storageService.loadTelegramMessages());
  const [suppliers, setSuppliers] = useState<Supplier[]>(() => storageService.loadSuppliers());
  const [rfqs, setRfqs] = useState<RFQ[]>(() => storageService.loadRfqs());
  const [inventory, setInventory] = useState<SerialInventory[]>(() => storageService.loadInventory());
  const [warranties, setWarranties] = useState<WarrantyAsset[]>(() => storageService.loadWarranties());
  const [amcs, setAmcs] = useState<AMCContract[]>(() => storageService.loadAMCs());
  const [tickets, setTickets] = useState<ServiceTicket[]>(() => storageService.loadTickets());
  const [campaigns, setCampaigns] = useState<MarketingCampaign[]>(() => storageService.loadCampaigns());
  const [agents, setAgents] = useState<AIAgent[]>([]); // No live agent health is verified
  const [auditLogs, setAuditLogs] = useState<AuditEvent[]>(() => storageService.loadAuditLogs());
  const [salesOrders, setSalesOrders] = useState<SalesOrder[]>(() => storageService.loadSalesOrders());
  const [workOrders, setWorkOrders] = useState<InstallationWorkOrder[]>(() => storageService.loadWorkOrders());
  const [rmas, setRmas] = useState<RMARequest[]>(() => storageService.loadRMAs());
  const [partners, setPartners] = useState<PartnerAccount[]>(() => storageService.loadPartners());
  const [dealRegistrations, setDealRegistrations] = useState<DealRegistration[]>(() => storageService.loadDealRegistrations());
  const [commissions, setCommissions] = useState<CommissionRecord[]>(() => storageService.loadCommissions());
  const [workflowRules, setWorkflowRules] = useState<WorkflowRule[]>(() => storageService.loadWorkflowRules());
  const [eventBusMessages, setEventBusMessages] = useState<EventBusMessage[]>(() => storageService.loadEventBusMessages());
  const [knowledgeDocs, setKnowledgeDocs] = useState<KnowledgeDocument[]>(() => storageService.loadKnowledgeDocs());
  const [deadStock, setDeadStock] = useState<DeadStockItem[]>(() => storageService.loadDeadStock());
  const [demandForecasts, setDemandForecasts] = useState<DemandForecast[]>(() => storageService.loadDemandForecasts());
  const [nextBestActions, setNextBestActions] = useState<NextBestAction[]>(() => storageService.loadNextBestActions());
  const [tenants, setTenants] = useState<TenantAccount[]>(() => storageService.loadTenants());
  const [deadLetterJobs, setDeadLetterJobs] = useState<DeadLetterJob[]>(() => storageService.loadDeadLetterJobs());
  const [integrations, setIntegrations] = useState<IntegrationConnector[]>(() => storageService.loadIntegrations());
  const [gemTenders, setGemTenders] = useState<GeMTenderBid[]>(() => storageService.loadGeMTenders());
  const [outboundTargets, setOutboundTargets] = useState<OutboundProspectAccount[]>(() => storageService.loadOutboundTargets());
  const [hardwareRefreshAssets, setHardwareRefreshAssets] = useState<HardwareRefreshAsset[]>(() => storageService.loadHardwareRefreshAssets());

  // Active BOM Builder state
  const [currentBOM, setCurrentBOM] = useState<BOMItem[]>([
    {
      id: 'b1',
      category: 'Laptops',
      name: 'Lenovo ThinkPad T14 Gen 4 (i5/16GB/512GB/Win 11 Pro)',
      sku: 'LEN-TP-T14-G4',
      qty: 15,
      unitCost: 59500,
      unitSell: 68500,
      hsn: '8471',
      gstRate: 18
    },
    {
      id: 'b2',
      category: 'Networking',
      name: 'Cisco Catalyst 1200 24-Port Gigabit PoE+',
      sku: 'CISCO-CAT-1200-24P',
      qty: 2,
      unitCost: 23800,
      unitSell: 27500,
      hsn: '8517',
      gstRate: 18
    },
    {
      id: 'b3',
      category: 'Power & Protection',
      name: 'APC Smart-UPS 3000VA LCD RM 2U',
      sku: 'APC-SMT-3000RM2U',
      qty: 1,
      unitCost: 98000,
      unitSell: 112500,
      hsn: '8504',
      gstRate: 18
    }
  ]);

  // Active Quote in viewer
  const [activeQuoteId, setActiveQuoteId] = useState<string>('QT-2026-089');

  // Derive pending approval cards across all telegram messages
  const pendingApprovals: TelegramApprovalCard[] = telegramMessages
    .filter(m => m.approvalCard && m.approvalCard.status === 'PENDING')
    .map(m => m.approvalCard!);

  // Telegram Send Handler
  const handleSendTelegramMessage = async (text: string) => {
    const userMsg: TelegramMessage = {
      id: `msg-${Date.now()}`,
      sender: 'user',
      text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setTelegramMessages(prev => [...prev, userMsg]);

    try {
      const res = await authenticatedFetch('/api/ai/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: text })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(typeof data.error === 'string' ? data.error : 'Business command unavailable');

      const botMsg: TelegramMessage = {
        id: `bot-${Date.now()}`,
        sender: 'bot',
        text: data.text || 'Command processed.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };

      setTelegramMessages(prev => [...prev, botMsg]);
    } catch (err) {
      console.error(err);
      const fallbackMsg: TelegramMessage = {
        id: `bot-${Date.now()}`,
        sender: 'bot',
        text: err instanceof Error ? err.message : 'Business command unavailable. No action executed.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      setTelegramMessages(prev => [...prev, fallbackMsg]);
    }
  };

  // This browser-local preview has NO authority to approve quotes, dispatch
  // orders, emit immutable audit, notify Telegram, or reserve warehouse stock.
  // Use server-backed review endpoints and MFA/step-up workflow instead.
  const noticeApprovalUnavailable=(action:'approve'|'reject')=>{
    setTelegramMessages(prev=>[...prev,{
      id:`bot-approval-blocked-${Date.now()}`,
      sender:'bot',
      text:`\u26a0\ufe0f ${action==='approve'?'Approval':'Rejection'} NOT recorded. This is an unverified browser-local preview. Use the server-backed quotation review workspace. No message, order or stock movement occurred.`,
      timestamp:new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})
    }]);
  };
  const handleApproveCard=(_cardId:string)=>noticeApprovalUnavailable('approve');
  const handleRejectCard=(_cardId:string)=>noticeApprovalUnavailable('reject');

  // CRM to BOM transition
  const handleSelectLeadForBOM = (lead: Lead) => {
    setActiveTab('bom');
  };

  // Data Reload Handler for Backup / Restore
  const handleReloadAllData = () => {
    setCompanyProfile(storageService.loadCompanyProfile());
    setLeads(storageService.loadLeads());
    setCustomers(storageService.loadCustomers());
    setProducts(storageService.loadProducts());
    setQuotations(storageService.loadQuotations());
    setPurchaseOrders(storageService.loadPurchaseOrders());
    setInventory(storageService.loadInventory());
    setSuppliers(storageService.loadSuppliers());
    setRfqs(storageService.loadRfqs());
    setWarranties(storageService.loadWarranties());
    setAmcs(storageService.loadAMCs());
    setTickets(storageService.loadTickets());
    setTelegramMessages(storageService.loadTelegramMessages());
    setAuditLogs(storageService.loadAuditLogs());
    setSalesOrders(storageService.loadSalesOrders());
    setWorkOrders(storageService.loadWorkOrders());
    setRmas(storageService.loadRMAs());
    setPartners(storageService.loadPartners());
    setDealRegistrations(storageService.loadDealRegistrations());
    setCommissions(storageService.loadCommissions());
    setWorkflowRules(storageService.loadWorkflowRules());
    setEventBusMessages(storageService.loadEventBusMessages());
    setKnowledgeDocs(storageService.loadKnowledgeDocs());
    setDeadStock(storageService.loadDeadStock());
    setDemandForecasts(storageService.loadDemandForecasts());
    setNextBestActions(storageService.loadNextBestActions());
    setTenants(storageService.loadTenants());
    setDeadLetterJobs(storageService.loadDeadLetterJobs());
    setIntegrations(storageService.loadIntegrations());
    setCampaigns(storageService.loadCampaigns());
    setGemTenders(storageService.loadGeMTenders());
    setOutboundTargets(storageService.loadOutboundTargets());
    setHardwareRefreshAssets(storageService.loadHardwareRefreshAssets());
    setEnvironmentMode(storageService.getEnvironmentMode());
  };

  // Legacy demo callbacks are not server-authoritative. Preserve all existing
  // browser-local records for explicit owner migration review; never silently
  // turn browser entries into KYC-approved customers, stock title, supplier
  // RFQ broadcasts, official quotations, accepted prices or issued POs.
  const handleAddCustomer = (_customer: Customer360) =>
    denyUnverifiedOperation('Customer KYC/onboarding');
  const handleAddProduct = (_product: Product) =>
    denyUnverifiedOperation('Verified SKU/vendor pricing registration');
  const handleAddInventoryItem = (_serial: SerialInventory) =>
    denyUnverifiedOperation('Serial stock title and inward goods receipt');
  const handleAddRFQ = (_rfq: RFQ) =>
    denyUnverifiedOperation('Supplier RFQ broadcast');
  const handleAddLead = (_lead: Lead) =>
    denyUnverifiedOperation('Verified CRM lead onboarding');
  const handleGenerateQuote = (_items: BOMItem[], _margin: number) =>
    denyUnverifiedOperation('Commercial quotation pricing, GST and owner approval');
  const handleRaisePO = (_rfqId: string, _supplierId: string) =>
    denyUnverifiedOperation('Issuance of supplier purchase order');

  // AMC Renewal
  // Central deny-only boundary for legacy browser-local operations.
  // Child UI disables these buttons, but a future component may invoke the
  // callback directly: therefore no localStorage mutation or fake audit event
  // may be produced by any of these parent handlers.
  const denyUnverifiedOperation = (action: string): void => {
    window.alert('RELEASE HOLD: ' + action + ' requires an authenticated, server-authoritative workflow, independent review and explicit release. No transaction, message, payment, stock movement or legal document was created.');
  };

  const handleTriggerRenewal = (_contractId: string) =>
    denyUnverifiedOperation('AMC renewal quote dispatch');
  const handleAssignTechnician = (_ticketId: string, _techName: string) =>
    denyUnverifiedOperation('Technician assignment');
  const handleUpdateOrderStatus = (_orderId: string, _status: SalesOrder['fulfillmentStatus']) =>
    denyUnverifiedOperation('Order fulfillment status change');
  const handleDispatchOrder = (_orderId: string, _courier: SalesOrder['courierName'],
    _awb: string, _eWayBill: string) =>
    denyUnverifiedOperation('Carrier dispatch and GST e-Way bill');
  const handleToggleWorkOrderChecklist = (_woId: string, _index: number) =>
    denyUnverifiedOperation('Field-service evidence checklist');
  const handleUpdateWorkOrderStatus = (_woId: string, _status: InstallationWorkOrder['status']) =>
    denyUnverifiedOperation('Work order/customer acceptance');
  const handleCreateWorkOrder = (_wo: InstallationWorkOrder) =>
    denyUnverifiedOperation('Work order issuance');
  const handleAddRMA = (_rma: RMARequest) =>
    denyUnverifiedOperation('RMA/replacement initiation');
  const handleAcceptQuotation = (_quoteId: string) =>
    denyUnverifiedOperation('Customer quotation e-sign and sales order conversion');
  const handleRegisterDeal = (_deal: DealRegistration) =>
    denyUnverifiedOperation('Partner price-protection registration');
  const handleApproveCommission = (_commId: string) =>
    denyUnverifiedOperation('Partner commission settlement');

  // Browser-local rules cannot be mistaken for an actual event bus,
  // independent delivery receipt, active integration or executed workflow.
  const handleToggleWorkflowRule = (_ruleId: string) =>
    denyUnverifiedOperation('Workflow activation');
  const handleExecuteWorkflowRule = (_ruleId: string) =>
    denyUnverifiedOperation('Workflow execution and outbound dispatch');
  const handleCreateWorkflowRule = (_rule: WorkflowRule) =>
    denyUnverifiedOperation('Operational workflow publication');

  // Predictive Analytics Handlers
  const handleUpdateDeadStock = (items: DeadStockItem[]) => {
    setDeadStock(items);
    storageService.saveDeadStock(items);
  };

  const handleUpdateDemandForecasts = (forecasts: DemandForecast[]) => {
    setDemandForecasts(forecasts);
    storageService.saveDemandForecasts(forecasts);
  };

  const handleTriggerNextBestAction = (_actionId: string) =>
    denyUnverifiedOperation('Predictive next-best-action execution');

  // The system hub is not a tenant switch, connected-provider console or
  // durable job worker. Do not forge successful retries or connector states.
  const handleSwitchTenant = (_tenantId: string) =>
    denyUnverifiedOperation('Tenant context switch');
  const handleRetryDeadLetterJob = (_jobId: string) =>
    denyUnverifiedOperation('Failed job retry');
  const handleToggleIntegration = (_id: string) =>
    denyUnverifiedOperation('External integration connect/disconnect');

  const formatINR = (val: number) => {
    return '₹' + Number(val || 0).toLocaleString('en-IN');
  };

  const activeQuote = quotations.find(q => q.id === activeQuoteId) || quotations[0];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-blue-600 selection:text-white">
      {/* Universal Top Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        pendingApprovalsCount={pendingApprovals.length}
        openTelegramDrawer={() => setIsTelegramDrawerOpen(true)}
        isTelegramDrawerOpen={isTelegramDrawerOpen}
        companyProfile={companyProfile}
        onOpenSettings={() => setIsSettingsModalOpen(true)}
        onOpenReset={() => setIsResetModalOpen(true)}
        environmentMode={environmentMode}
      />

      <div role="alert" className="mx-auto max-w-screen-2xl px-4 py-3 text-sm rounded-lg border border-amber-700/60 bg-amber-950/40 text-amber-100">
        RELEASE HOLD — MIXED MODE: only explicitly server-backed CRM and quotation review endpoints can persist approved changes.
        Other legacy dashboards, catalogs, workflows and previews are browser-local or simulated; figures and actions are NOT verified business records.
        No customer messaging, purchasing, inventory movement or production release is authorized by this UI.
      </div>

      {/* AadiTech Solution Master Settings & Real Data Backup/Import Modal */}
      <CompanySettingsModal
        isOpen={isSettingsModalOpen}
        onClose={() => setIsSettingsModalOpen(false)}
        companyProfile={companyProfile}
        onSaveProfile={(prof) => {
          setCompanyProfile(prof);
          storageService.saveCompanyProfile(prof);
        }}
        onDataReload={handleReloadAllData}
      />

      {/* Complete Reset to Fresh Production Slate & Testing Dataset Controller */}
      <ResetAndEnvironmentModal
        isOpen={isResetModalOpen}
        onClose={() => setIsResetModalOpen(false)}
        onDataReload={handleReloadAllData}
      />

      {/* Main Workspace Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">
        {activeTab !== 'crm' && <div role="note" className="mb-5 rounded-lg border border-amber-700/70 bg-amber-950/40 p-3 text-sm text-amber-200">
          Preview modules: many business reports, orders and inventory still use browser or demo data. The troubleshooting tab uses authenticated read-only guidance, not device inspection or real ticket records. Do not treat preview figures as verified operational data.
          Do not treat other dashboard figures or claimed automation as verified live business operations.
        </div>}
        {planningTabs[activeTab] && <div key={activeTab}><InternalPlanningWorkspace modules={planningTabs[activeTab]} /></div>}
        {activeTab === 'dashboard' && (
          <ExecutiveDashboard
            leads={leads}
            products={products}
            quotations={quotations}
            pendingApprovals={pendingApprovals}
            onOpenTelegram={() => setActiveTab('telegram')}
            onNavigateToTab={(tab) => setActiveTab(tab)}
          />
        )}

        {activeTab === 'telegram' && (
          <div className="max-w-4xl mx-auto h-[80vh]">
            <TelegramCommandHub
              messages={telegramMessages}
              onSendMessage={handleSendTelegramMessage}
              onApproveCard={handleApproveCard}
              onRejectCard={handleRejectCard}
              onNavigateToQuote={(refId) => {
                const target = quotations.find(q => q.quoteNumber === refId || q.id === refId);
                if (target) {
                  setActiveQuoteId(target.id);
                  setActiveTab('quotes');
                }
              }}
            />
          </div>
        )}

        {activeTab === 'crm' && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <button type="button" onClick={() => setCrmViewMode('live')}
                aria-pressed={crmViewMode === 'live'}
                className={'rounded-lg px-4 py-2 text-sm border ' + (crmViewMode === 'live' ? 'bg-cyan-700 border-cyan-500 text-white' : 'border-slate-700 text-slate-300')}>
                Live MySQL CRM
              </button>
              <button type="button" onClick={() => setCrmViewMode('legacy')}
                aria-pressed={crmViewMode === 'legacy'}
                className={'rounded-lg px-4 py-2 text-sm border ' + (crmViewMode === 'legacy' ? 'bg-amber-900 border-amber-600 text-amber-100' : 'border-slate-700 text-slate-300')}>
                Legacy Demo Workspace
              </button>
            </div>
            {crmViewMode === 'live' ? <LiveCRMWorkspace /> : (
              <div className="space-y-3">
                <div role="alert" className="rounded-lg border border-amber-700/70 bg-amber-950/40 p-3 text-sm text-amber-200">
                  DEMO / BROWSER-ONLY: All records and actions below use localStorage or simulated workflows.
                  They do not create MySQL customers or verified external leads.
                </div>
              <CRMAndLeadsView
                leads={leads}
                customers={customers}
                gemTenders={gemTenders}
                outboundTargets={outboundTargets}
                hardwareRefreshAssets={hardwareRefreshAssets}
                dealRegistrations={dealRegistrations}
                onSelectLeadForBOM={handleSelectLeadForBOM}
                onAddLead={handleAddLead}
                onAddCustomer={handleAddCustomer}
                onConvertTenderToLead={(tender) => {
                  setGemTenders(storageService.loadGeMTenders());
                }}
                onLaunchOutboundSequence={(target) => {
                  setOutboundTargets(storageService.loadOutboundTargets());
                }}
                onTriggerRefreshProposal={(asset) => {
                  setHardwareRefreshAssets(storageService.loadHardwareRefreshAssets());
                }}
              />
              </div>
            )}
          </div>
        )}

        {activeTab === 'bom' && (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-2">
              <button type="button" aria-pressed={bomViewMode === 'live'} onClick={() => setBomViewMode('live')}
                className={bomViewMode === 'live' ? 'bg-cyan-700 p-2 rounded-lg' : 'border border-slate-700 p-2 rounded-lg'}>Live MySQL BOM</button>
              <button type="button" aria-pressed={bomViewMode === 'legacy'} onClick={() => setBomViewMode('legacy')}
                className={bomViewMode === 'legacy' ? 'bg-amber-900 p-2 rounded-lg' : 'border border-slate-700 p-2 rounded-lg'}>Legacy AI Demo BOM</button>
            </div>
            {bomViewMode === 'live' ? <LiveBOMWorkspace /> :
              <div className="space-y-3">
                <div role="alert" className="rounded-lg border border-amber-700 bg-amber-950/40 p-3 text-amber-200 text-sm">
                  DEMO ONLY: AI generated BOM costs, compatibility claims and quotation transitions are not verified commercial commitments.
                </div>
                <SalesAndBOMBuilder products={products} currentBOM={currentBOM} setCurrentBOM={setCurrentBOM} onGenerateQuote={handleGenerateQuote} />
              </div>}
          </div>
        )}

        {activeTab === 'quotes' && (
          <QuotationAndNegotiation
            quotations={quotations}
            activeQuote={activeQuote}
            onSendToTelegram={(card) => {
              const tgMsg: TelegramMessage = {
                id: `tg-neg-${Date.now()}`,
                sender: 'bot',
                text: `🔔 **TELEGRAM APPROVAL REQUIRED: NEGOTIATION EXCEPTION**\nCustomer counter-offer requires Owner override.`,
                timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                approvalCard: card
              };
              setTelegramMessages(prev => [...prev, tgMsg]);
            }}
            onUpdateQuoteStatus={(quoteId, status) => {
              setQuotations(prev => prev.map(q => q.id === quoteId ? { ...q, status } : q));
            }}
          />
        )}

        {activeTab === 'orders' && (
          <OrdersAndLogisticsView
            salesOrders={salesOrders}
            workOrders={workOrders}
            rmas={rmas}
            companyProfile={companyProfile}
            onUpdateOrderStatus={handleUpdateOrderStatus}
            onDispatchOrder={handleDispatchOrder}
            onToggleWorkOrderChecklist={handleToggleWorkOrderChecklist}
            onUpdateWorkOrderStatus={handleUpdateWorkOrderStatus}
            onCreateWorkOrder={handleCreateWorkOrder}
            onAddRMA={handleAddRMA}
          />
        )}

        {activeTab === 'approvals' && (
          <ApprovalEngineView
            pendingApprovals={pendingApprovals}
            auditLogs={auditLogs}
            onApproveCard={handleApproveCard}
            onRejectCard={handleRejectCard}
            onOpenTelegram={() => setActiveTab('telegram')}
          />
        )}

        {activeTab === 'procurement' && (
          <div className="space-y-5">
            <LiveInventoryWorkspace />
            <LiveProcurementWorkspace />
            <InboundObservationWorkspace />
            <SupplierDispatchOwnerPanel />
            <SupplierEvidenceOwnerPanel />
            <StockFoundationOwnerPanel />
            <JournalFoundationOwnerPanel />
            <SignedProofOwnerPanel />
            <KeyLifecycleOwnerPanel />
            <ExternalTrustOwnerPanel />
            <ProviderBridgeOwnerPanel />
            <ProviderSandboxOwnerPanel />
            <ProviderSelectionOwnerPanel />
            <ProviderOnboardingOwnerPanel />
            <details className="rounded-xl border border-amber-800 bg-amber-950/20 p-4">
              <summary className="cursor-pointer text-amber-200 text-sm font-semibold">
                Legacy procurement / stock UI — DEMO ONLY (browser-local, no MySQL movements)
              </summary>
              <p className="text-amber-200 text-xs my-3">
                Do not use this simulator to receive goods, reserve inventory, authorize supplier POs
                or report audited balances. No real procurement or stock movements occur here.
              </p>
          <ProcurementAndInventory
            products={products}
            suppliers={suppliers}
            rfqs={rfqs}
            inventory={inventory}
            purchaseOrders={purchaseOrders}
            onRaisePO={handleRaisePO}
            onAddProduct={handleAddProduct}
            onAddInventoryItem={handleAddInventoryItem}
            onAddRFQ={handleAddRFQ}
          />
            </details>
          </div>
        )}

        {activeTab === 'analytics' && (
          <PredictiveAnalyticsView
            deadStock={deadStock}
            onUpdateDeadStock={handleUpdateDeadStock}
            demandForecasts={demandForecasts}
            onUpdateDemandForecasts={handleUpdateDemandForecasts}
            salesForecast={INITIAL_SALES_FORECAST}
            cashFlowForecast={INITIAL_CASH_FLOW_FORECAST}
            nextBestActions={nextBestActions}
            onTriggerAction={handleTriggerNextBestAction}
            lostDeals={INITIAL_LOST_DEALS}
            customerLTVs={INITIAL_CUSTOMER_LTVS}
            formatINR={formatINR}
          />
        )}

        {activeTab === 'portals' && (
          <PortalsAndResellersView
            quotations={quotations}
            salesOrders={salesOrders}
            warranties={warranties}
            amcs={amcs}
            partners={partners}
            dealRegistrations={dealRegistrations}
            commissions={commissions}
            companyProfile={companyProfile}
            onAcceptQuotation={handleAcceptQuotation}
            onRegisterDeal={handleRegisterDeal}
            onApproveCommission={handleApproveCommission}
          />
        )}

        {activeTab === 'workflows' && (
          <WorkflowsAndRAGView
            workflowRules={workflowRules}
            eventBusMessages={eventBusMessages}
            knowledgeDocs={knowledgeDocs}
            companyProfile={companyProfile}
            onToggleWorkflowRule={handleToggleWorkflowRule}
            onExecuteWorkflowRule={handleExecuteWorkflowRule}
            onCreateWorkflowRule={handleCreateWorkflowRule}
          />
        )}

        {activeTab === 'system' && (
          <SystemHubView
            tenants={tenants}
            onSwitchTenant={handleSwitchTenant}
            userRoles={INITIAL_USER_ROLES}
            systemHealth={INITIAL_SYSTEM_HEALTH}
            deadLetterJobs={deadLetterJobs}
            onRetryDeadLetterJob={handleRetryDeadLetterJob}
            integrations={integrations}
            onToggleIntegration={handleToggleIntegration}
            apiEndpoints={INITIAL_API_ENDPOINTS}
          />
        )}

        {activeTab === 'troubleshooting' && <WindowsTroubleshootingWorkspace />}
        {activeTab === 'service-desk' && <LiveServiceDeskWorkspace />}

        {activeTab === 'finance' && (
          <FinanceAndServiceView
            warranties={warranties}
            amcs={amcs}
            tickets={tickets}
            customers={customers}
            companyProfile={companyProfile}
            onTriggerRenewal={handleTriggerRenewal}
            onAssignTechnician={handleAssignTechnician}
          />
        )}

        {activeTab === 'marketing' && (
          <MarketingAndAgentView
            campaigns={campaigns}
            agents={agents}
            onTriggerCampaign={(camp) => {
              alert(`Campaign "${camp.name}" is a browser-only preview. No messages were sent and no AI agent was started. Use an authorized connector with verified consent for real campaigns.`);
            }}
          />
        )}
      </main>

      {/* Telegram Slide-over Quick Drawer (accessible anytime from any tab) */}
      {isTelegramDrawerOpen && (
        <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-xs flex justify-end">
          <div className="w-full max-w-md h-full bg-slate-950 p-2 sm:p-4 shadow-2xl flex flex-col">
            <TelegramCommandHub
              messages={telegramMessages}
              onSendMessage={handleSendTelegramMessage}
              onApproveCard={handleApproveCard}
              onRejectCard={handleRejectCard}
              isDrawer={true}
              onCloseDrawer={() => setIsTelegramDrawerOpen(false)}
              onNavigateToQuote={(refId) => {
                const target = quotations.find(q => q.quoteNumber === refId || q.id === refId);
                if (target) {
                  setActiveQuoteId(target.id);
                  setActiveTab('quotes');
                  setIsTelegramDrawerOpen(false);
                }
              }}
            />
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950/80 py-4 px-6 text-center text-xs text-slate-400">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-2 max-w-7xl mx-auto">
          <span>
            Autonomous IT Hardware Sales & Marketing Platform &bull; Production Master Blueprint
          </span>
          <span className="text-slate-400">
            90% Autonomous Execution &bull; 10% Telegram Owner Exception Gate &bull; Section 51 Guardrails
          </span>
        </div>
      </footer>
    </div>
  );
}
