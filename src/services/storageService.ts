import {
  Lead,
  Customer360,
  Product,
  Quotation,
  TelegramMessage,
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
} from '../types';

import {
  INITIAL_LEADS,
  INITIAL_CUSTOMERS,
  INITIAL_PRODUCTS,
  INITIAL_QUOTATIONS,
  INITIAL_TELEGRAM_MESSAGES,
  INITIAL_SUPPLIERS,
  INITIAL_RFQS,
  INITIAL_INVENTORY,
  INITIAL_WARRANTIES,
  INITIAL_AMCS,
  INITIAL_TICKETS,
  INITIAL_CAMPAIGNS,
  INITIAL_AI_AGENTS,
  INITIAL_AUDIT_LOGS,
  INITIAL_SALES_ORDERS,
  INITIAL_WORK_ORDERS,
  INITIAL_RMAS,
  INITIAL_PARTNERS,
  INITIAL_DEAL_REGISTRATIONS,
  INITIAL_COMMISSIONS,
  INITIAL_WORKFLOW_RULES,
  INITIAL_EVENT_BUS_MESSAGES,
  INITIAL_KNOWLEDGE_DOCS,
  INITIAL_DEAD_STOCK,
  INITIAL_DEMAND_FORECASTS,
  INITIAL_NEXT_BEST_ACTIONS,
  INITIAL_TENANTS,
  INITIAL_DEAD_LETTER_JOBS,
  INITIAL_INTEGRATIONS,
  INITIAL_GEM_TENDERS,
  INITIAL_OUTBOUND_TARGETS,
  INITIAL_HARDWARE_REFRESH_ASSETS
} from '../data/mockData';

export const DEFAULT_COMPANY_PROFILE: CompanyProfile = {
  name: 'AadiTech Solution',
  tagline: 'Enterprise IT Infrastructure, Turnkey Power Systems & High-Reliability Hardware Solutions',
  website: 'https://aaditechs.in',
  phone: '+91 9250960063',
  email: 'info@aaditechs.in',
  gstin: '27AABCA9988K1Z5',
  pan: 'AABCA9988K',
  address: 'Unit 204, Tech Park, Andheri-Kurla Road, Mumbai, Maharashtra - 400072',
  bankName: 'ICICI Bank Ltd',
  accountName: 'AadiTech Solution',
  accountNumber: '001105018920',
  ifscCode: 'ICIC0000011',
  branch: 'Andheri East Corporate Branch, Mumbai',
  upiId: 'aaditech@icici',
  defaultMarginThreshold: 15.0
};

// Specialized AadiTech Solution Products (including Power Systems & Hi-REL equipment)
export const AADITECH_SPECIALIZED_PRODUCTS: Product[] = [
  ...INITIAL_PRODUCTS,
  {
    id: 'PROD-ATS-001',
    sku: 'ATS-MIL-PS500',
    brand: 'AadiTech Solutions',
    model: 'Hi-REL 500W Rugged DC-DC Power Supply',
    category: 'POWER_STORAGE',
    specs: 'Wide input 18-36V DC, 28V/18A output, MIL-STD-810G & 461E compliant, conduction cooled, reverse polarity protection',
    unitCost: 48000,
    freightCost: 800,
    riskBuffer: 1200,
    landedCost: 50000,
    sellingPrice: 62500,
    minPrice: 58000,
    targetMarginPct: 20.0,
    gstRate: 18,
    hsn: '8504',
    warrantyMonths: 36,
    stockBhiwandi: 8,
    stockDelhi: 4,
    stockBangalore: 2,
    reservedStock: 1,
    leadTimeDays: 7
  },
  {
    id: 'PROD-ATS-002',
    sku: 'ATS-ACDC-2000',
    brand: 'AadiTech Solutions',
    model: 'Turnkey Enterprise AC-DC Modular Power System',
    category: 'POWER_STORAGE',
    specs: '2000W 48V DC rectifier shelf, N+1 redundant hot-swap modules, SNMP v3 monitoring, telecom/railways grade',
    unitCost: 85000,
    freightCost: 1500,
    riskBuffer: 2500,
    landedCost: 89000,
    sellingPrice: 112000,
    minPrice: 104000,
    targetMarginPct: 20.5,
    gstRate: 18,
    hsn: '8504',
    warrantyMonths: 36,
    stockBhiwandi: 5,
    stockDelhi: 2,
    stockBangalore: 1,
    reservedStock: 0,
    leadTimeDays: 5
  },
  {
    id: 'PROD-ATS-003',
    sku: 'ATS-BAT-CHG48',
    brand: 'AadiTech Solutions',
    model: 'Intelligent Industrial Battery Charger & SMPS Rack Unit',
    category: 'POWER_STORAGE',
    specs: '48V 50A Microprocessor-controlled automatic battery charger with float/boost charging and battery health telemetry',
    unitCost: 62000,
    freightCost: 1200,
    riskBuffer: 1800,
    landedCost: 65000,
    sellingPrice: 81000,
    minPrice: 75000,
    targetMarginPct: 19.75,
    gstRate: 18,
    hsn: '8504',
    warrantyMonths: 24,
    stockBhiwandi: 6,
    stockDelhi: 3,
    stockBangalore: 2,
    reservedStock: 1,
    leadTimeDays: 4
  }
];

export const INITIAL_PURCHASE_ORDERS: PurchaseOrder[] = [
  {
    id: 'PO-2026-101',
    poNumber: 'PO-2026-101',
    rfqId: 'RFQ-2026-44',
    supplierId: 'SUP-02',
    supplierName: 'Ingram Micro India Pvt Ltd',
    productName: 'Fortinet FortiGate 60F UTM Firewall Bundle',
    qty: 5,
    unitPrice: 56200,
    totalAmount: 331580,
    gstAmount: 50580,
    deliveryWarehouse: 'Bhiwandi Central Hub (MH)',
    status: 'DISPATCHED',
    expectedDelivery: '2026-09-06',
    createdDate: '2026-09-04'
  },
  {
    id: 'PO-2026-100',
    poNumber: 'PO-2026-100',
    supplierId: 'SUP-01',
    supplierName: 'Redington India Ltd',
    productName: 'Dell PowerEdge R760 2U Rack Server',
    qty: 2,
    unitPrice: 385000,
    totalAmount: 908600,
    gstAmount: 138600,
    deliveryWarehouse: 'Bhiwandi Central Hub (MH)',
    status: 'QC_INSPECTION',
    expectedDelivery: '2026-09-05',
    createdDate: '2026-09-02'
  }
];

const STORAGE_KEYS = {
  COMPANY_PROFILE: 'aaditech_company_profile',
  LEADS: 'aaditech_leads',
  CUSTOMERS: 'aaditech_customers',
  PRODUCTS: 'aaditech_products',
  QUOTATIONS: 'aaditech_quotations',
  INVENTORY: 'aaditech_inventory',
  SUPPLIERS: 'aaditech_suppliers',
  RFQS: 'aaditech_rfqs',
  POS: 'aaditech_purchase_orders',
  WARRANTIES: 'aaditech_warranties',
  AMCS: 'aaditech_amcs',
  TICKETS: 'aaditech_tickets',
  CAMPAIGNS: 'aaditech_campaigns',
  TELEGRAM_MESSAGES: 'aaditech_telegram_messages',
  AUDIT_LOGS: 'aaditech_audit_logs',
  SALES_ORDERS: 'aaditech_sales_orders',
  WORK_ORDERS: 'aaditech_work_orders',
  RMAS: 'aaditech_rmas',
  PARTNERS: 'aaditech_partners',
  DEAL_REGISTRATIONS: 'aaditech_deal_registrations',
  COMMISSIONS: 'aaditech_commissions',
  WORKFLOW_RULES: 'aaditech_workflow_rules',
  EVENT_BUS_MESSAGES: 'aaditech_event_bus_messages',
  KNOWLEDGE_DOCS: 'aaditech_knowledge_docs',
  DEAD_STOCK: 'aaditech_dead_stock',
  DEMAND_FORECASTS: 'aaditech_demand_forecasts',
  NEXT_BEST_ACTIONS: 'aaditech_next_best_actions',
  TENANTS: 'aaditech_tenants',
  DEAD_LETTER_JOBS: 'aaditech_dead_letter_jobs',
  INTEGRATIONS: 'aaditech_integrations',
  GEM_TENDERS: 'aaditech_gem_tenders',
  OUTBOUND_TARGETS: 'aaditech_outbound_targets',
  HARDWARE_REFRESH: 'aaditech_hardware_refresh',
  ENVIRONMENT_MODE: 'aaditech_env_mode'
};

export const storageService = {
  getEnvironmentMode(): 'TESTING' | 'PRODUCTION' {
    try {
      const mode = localStorage.getItem(STORAGE_KEYS.ENVIRONMENT_MODE);
      return mode === 'PRODUCTION' ? 'PRODUCTION' : 'TESTING';
    } catch {
      return 'TESTING';
    }
  },
  setEnvironmentMode(mode: 'TESTING' | 'PRODUCTION') {
    try {
      localStorage.setItem(STORAGE_KEYS.ENVIRONMENT_MODE, mode);
    } catch (e) {
      console.error(e);
    }
  },

  loadCompanyProfile(): CompanyProfile {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.COMPANY_PROFILE);
      return data ? JSON.parse(data) : DEFAULT_COMPANY_PROFILE;
    } catch {
      return DEFAULT_COMPANY_PROFILE;
    }
  },
  saveCompanyProfile(profile: CompanyProfile) {
    try {
      localStorage.setItem(STORAGE_KEYS.COMPANY_PROFILE, JSON.stringify(profile));
    } catch (e) {
      console.error(e);
    }
  },

  loadLeads(): Lead[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.LEADS);
      return data ? JSON.parse(data) : INITIAL_LEADS;
    } catch {
      return INITIAL_LEADS;
    }
  },
  saveLeads(leads: Lead[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.LEADS, JSON.stringify(leads));
    } catch (e) {
      console.error(e);
    }
  },

  loadCustomers(): Customer360[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.CUSTOMERS);
      return data ? JSON.parse(data) : INITIAL_CUSTOMERS;
    } catch {
      return INITIAL_CUSTOMERS;
    }
  },
  saveCustomers(customers: Customer360[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.CUSTOMERS, JSON.stringify(customers));
    } catch (e) {
      console.error(e);
    }
  },

  loadProducts(): Product[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.PRODUCTS);
      return data ? JSON.parse(data) : AADITECH_SPECIALIZED_PRODUCTS;
    } catch {
      return AADITECH_SPECIALIZED_PRODUCTS;
    }
  },
  saveProducts(products: Product[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.PRODUCTS, JSON.stringify(products));
    } catch (e) {
      console.error(e);
    }
  },

  loadQuotations(): Quotation[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.QUOTATIONS);
      return data ? JSON.parse(data) : INITIAL_QUOTATIONS;
    } catch {
      return INITIAL_QUOTATIONS;
    }
  },
  saveQuotations(quotations: Quotation[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.QUOTATIONS, JSON.stringify(quotations));
    } catch (e) {
      console.error(e);
    }
  },

  loadPurchaseOrders(): PurchaseOrder[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.POS);
      return data ? JSON.parse(data) : INITIAL_PURCHASE_ORDERS;
    } catch {
      return INITIAL_PURCHASE_ORDERS;
    }
  },
  savePurchaseOrders(pos: PurchaseOrder[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.POS, JSON.stringify(pos));
    } catch (e) {
      console.error(e);
    }
  },

  loadInventory(): SerialInventory[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.INVENTORY);
      return data ? JSON.parse(data) : INITIAL_INVENTORY;
    } catch {
      return INITIAL_INVENTORY;
    }
  },
  saveInventory(inv: SerialInventory[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.INVENTORY, JSON.stringify(inv));
    } catch (e) {
      console.error(e);
    }
  },

  loadSuppliers(): Supplier[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.SUPPLIERS);
      return data ? JSON.parse(data) : INITIAL_SUPPLIERS;
    } catch {
      return INITIAL_SUPPLIERS;
    }
  },
  saveSuppliers(suppliers: Supplier[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.SUPPLIERS, JSON.stringify(suppliers));
    } catch (e) {
      console.error(e);
    }
  },

  loadRfqs(): RFQ[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.RFQS);
      return data ? JSON.parse(data) : INITIAL_RFQS;
    } catch {
      return INITIAL_RFQS;
    }
  },
  saveRfqs(rfqs: RFQ[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.RFQS, JSON.stringify(rfqs));
    } catch (e) {
      console.error(e);
    }
  },

  loadWarranties(): WarrantyAsset[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.WARRANTIES);
      return data ? JSON.parse(data) : INITIAL_WARRANTIES;
    } catch {
      return INITIAL_WARRANTIES;
    }
  },
  saveWarranties(warranties: WarrantyAsset[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.WARRANTIES, JSON.stringify(warranties));
    } catch (e) {
      console.error(e);
    }
  },

  loadAMCs(): AMCContract[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.AMCS);
      return data ? JSON.parse(data) : INITIAL_AMCS;
    } catch {
      return INITIAL_AMCS;
    }
  },
  saveAMCs(amcs: AMCContract[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.AMCS, JSON.stringify(amcs));
    } catch (e) {
      console.error(e);
    }
  },

  loadTickets(): ServiceTicket[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.TICKETS);
      return data ? JSON.parse(data) : INITIAL_TICKETS;
    } catch {
      return INITIAL_TICKETS;
    }
  },
  saveTickets(tickets: ServiceTicket[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.TICKETS, JSON.stringify(tickets));
    } catch (e) {
      console.error(e);
    }
  },

  loadTelegramMessages(): TelegramMessage[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.TELEGRAM_MESSAGES);
      return data ? JSON.parse(data) : INITIAL_TELEGRAM_MESSAGES;
    } catch {
      return INITIAL_TELEGRAM_MESSAGES;
    }
  },
  saveTelegramMessages(messages: TelegramMessage[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.TELEGRAM_MESSAGES, JSON.stringify(messages));
    } catch (e) {
      console.error(e);
    }
  },

  loadCampaigns(): MarketingCampaign[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.CAMPAIGNS);
      return data ? JSON.parse(data) : INITIAL_CAMPAIGNS;
    } catch {
      return INITIAL_CAMPAIGNS;
    }
  },
  saveCampaigns(campaigns: MarketingCampaign[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.CAMPAIGNS, JSON.stringify(campaigns));
    } catch (e) {
      console.error(e);
    }
  },

  loadGeMTenders(): GeMTenderBid[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.GEM_TENDERS);
      return data ? JSON.parse(data) : INITIAL_GEM_TENDERS;
    } catch {
      return INITIAL_GEM_TENDERS;
    }
  },
  saveGeMTenders(tenders: GeMTenderBid[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.GEM_TENDERS, JSON.stringify(tenders));
    } catch (e) {
      console.error(e);
    }
  },

  loadOutboundTargets(): OutboundProspectAccount[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.OUTBOUND_TARGETS);
      return data ? JSON.parse(data) : INITIAL_OUTBOUND_TARGETS;
    } catch {
      return INITIAL_OUTBOUND_TARGETS;
    }
  },
  saveOutboundTargets(targets: OutboundProspectAccount[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.OUTBOUND_TARGETS, JSON.stringify(targets));
    } catch (e) {
      console.error(e);
    }
  },

  loadHardwareRefreshAssets(): HardwareRefreshAsset[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.HARDWARE_REFRESH);
      return data ? JSON.parse(data) : INITIAL_HARDWARE_REFRESH_ASSETS;
    } catch {
      return INITIAL_HARDWARE_REFRESH_ASSETS;
    }
  },
  saveHardwareRefreshAssets(assets: HardwareRefreshAsset[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.HARDWARE_REFRESH, JSON.stringify(assets));
    } catch (e) {
      console.error(e);
    }
  },

  loadAuditLogs(): AuditEvent[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.AUDIT_LOGS);
      return data ? JSON.parse(data) : INITIAL_AUDIT_LOGS;
    } catch {
      return INITIAL_AUDIT_LOGS;
    }
  },
  saveAuditLogs(logs: AuditEvent[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.AUDIT_LOGS, JSON.stringify(logs));
    } catch (e) {
      console.error(e);
    }
  },

  loadSalesOrders(): SalesOrder[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.SALES_ORDERS);
      return data ? JSON.parse(data) : INITIAL_SALES_ORDERS;
    } catch {
      return INITIAL_SALES_ORDERS;
    }
  },
  saveSalesOrders(orders: SalesOrder[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.SALES_ORDERS, JSON.stringify(orders));
    } catch (e) {
      console.error(e);
    }
  },

  loadWorkOrders(): InstallationWorkOrder[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.WORK_ORDERS);
      return data ? JSON.parse(data) : INITIAL_WORK_ORDERS;
    } catch {
      return INITIAL_WORK_ORDERS;
    }
  },
  saveWorkOrders(orders: InstallationWorkOrder[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.WORK_ORDERS, JSON.stringify(orders));
    } catch (e) {
      console.error(e);
    }
  },

  loadRMAs(): RMARequest[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.RMAS);
      return data ? JSON.parse(data) : INITIAL_RMAS;
    } catch {
      return INITIAL_RMAS;
    }
  },
  saveRMAs(rmas: RMARequest[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.RMAS, JSON.stringify(rmas));
    } catch (e) {
      console.error(e);
    }
  },

  loadPartners(): PartnerAccount[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.PARTNERS);
      return data ? JSON.parse(data) : INITIAL_PARTNERS;
    } catch {
      return INITIAL_PARTNERS;
    }
  },
  savePartners(partners: PartnerAccount[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.PARTNERS, JSON.stringify(partners));
    } catch (e) {
      console.error(e);
    }
  },

  loadDealRegistrations(): DealRegistration[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.DEAL_REGISTRATIONS);
      return data ? JSON.parse(data) : INITIAL_DEAL_REGISTRATIONS;
    } catch {
      return INITIAL_DEAL_REGISTRATIONS;
    }
  },
  saveDealRegistrations(deals: DealRegistration[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.DEAL_REGISTRATIONS, JSON.stringify(deals));
    } catch (e) {
      console.error(e);
    }
  },

  loadCommissions(): CommissionRecord[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.COMMISSIONS);
      return data ? JSON.parse(data) : INITIAL_COMMISSIONS;
    } catch {
      return INITIAL_COMMISSIONS;
    }
  },
  saveCommissions(commissions: CommissionRecord[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.COMMISSIONS, JSON.stringify(commissions));
    } catch (e) {
      console.error(e);
    }
  },

  loadWorkflowRules(): WorkflowRule[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.WORKFLOW_RULES);
      return data ? JSON.parse(data) : INITIAL_WORKFLOW_RULES;
    } catch {
      return INITIAL_WORKFLOW_RULES;
    }
  },
  saveWorkflowRules(rules: WorkflowRule[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.WORKFLOW_RULES, JSON.stringify(rules));
    } catch (e) {
      console.error(e);
    }
  },

  loadEventBusMessages(): EventBusMessage[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.EVENT_BUS_MESSAGES);
      return data ? JSON.parse(data) : INITIAL_EVENT_BUS_MESSAGES;
    } catch {
      return INITIAL_EVENT_BUS_MESSAGES;
    }
  },
  saveEventBusMessages(events: EventBusMessage[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.EVENT_BUS_MESSAGES, JSON.stringify(events));
    } catch (e) {
      console.error(e);
    }
  },

  loadKnowledgeDocs(): KnowledgeDocument[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.KNOWLEDGE_DOCS);
      return data ? JSON.parse(data) : INITIAL_KNOWLEDGE_DOCS;
    } catch {
      return INITIAL_KNOWLEDGE_DOCS;
    }
  },
  saveKnowledgeDocs(docs: KnowledgeDocument[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.KNOWLEDGE_DOCS, JSON.stringify(docs));
    } catch (e) {
      console.error(e);
    }
  },

  loadDeadStock(): DeadStockItem[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.DEAD_STOCK);
      return data ? JSON.parse(data) : INITIAL_DEAD_STOCK;
    } catch {
      return INITIAL_DEAD_STOCK;
    }
  },
  saveDeadStock(items: DeadStockItem[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.DEAD_STOCK, JSON.stringify(items));
    } catch (e) {
      console.error(e);
    }
  },

  loadDemandForecasts(): DemandForecast[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.DEMAND_FORECASTS);
      return data ? JSON.parse(data) : INITIAL_DEMAND_FORECASTS;
    } catch {
      return INITIAL_DEMAND_FORECASTS;
    }
  },
  saveDemandForecasts(forecasts: DemandForecast[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.DEMAND_FORECASTS, JSON.stringify(forecasts));
    } catch (e) {
      console.error(e);
    }
  },

  loadNextBestActions(): NextBestAction[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.NEXT_BEST_ACTIONS);
      return data ? JSON.parse(data) : INITIAL_NEXT_BEST_ACTIONS;
    } catch {
      return INITIAL_NEXT_BEST_ACTIONS;
    }
  },
  saveNextBestActions(actions: NextBestAction[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.NEXT_BEST_ACTIONS, JSON.stringify(actions));
    } catch (e) {
      console.error(e);
    }
  },

  loadTenants(): TenantAccount[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.TENANTS);
      return data ? JSON.parse(data) : INITIAL_TENANTS;
    } catch {
      return INITIAL_TENANTS;
    }
  },
  saveTenants(tenants: TenantAccount[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.TENANTS, JSON.stringify(tenants));
    } catch (e) {
      console.error(e);
    }
  },

  loadDeadLetterJobs(): DeadLetterJob[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.DEAD_LETTER_JOBS);
      return data ? JSON.parse(data) : INITIAL_DEAD_LETTER_JOBS;
    } catch {
      return INITIAL_DEAD_LETTER_JOBS;
    }
  },
  saveDeadLetterJobs(jobs: DeadLetterJob[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.DEAD_LETTER_JOBS, JSON.stringify(jobs));
    } catch (e) {
      console.error(e);
    }
  },

  loadIntegrations(): IntegrationConnector[] {
    try {
      const data = localStorage.getItem(STORAGE_KEYS.INTEGRATIONS);
      return data ? JSON.parse(data) : INITIAL_INTEGRATIONS;
    } catch {
      return INITIAL_INTEGRATIONS;
    }
  },
  saveIntegrations(integrations: IntegrationConnector[]) {
    try {
      localStorage.setItem(STORAGE_KEYS.INTEGRATIONS, JSON.stringify(integrations));
    } catch (e) {
      console.error(e);
    }
  },

  // Export full real data as JSON snapshot
  exportFullBackup(): string {
    const backup = {
      version: '4.2',
      company: this.loadCompanyProfile(),
      leads: this.loadLeads(),
      customers: this.loadCustomers(),
      products: this.loadProducts(),
      quotations: this.loadQuotations(),
      inventory: this.loadInventory(),
      purchaseOrders: this.loadPurchaseOrders(),
      salesOrders: this.loadSalesOrders(),
      workOrders: this.loadWorkOrders(),
      rmas: this.loadRMAs(),
      partners: this.loadPartners(),
      dealRegistrations: this.loadDealRegistrations(),
      commissions: this.loadCommissions(),
      workflowRules: this.loadWorkflowRules(),
      deadStock: this.loadDeadStock(),
      demandForecasts: this.loadDemandForecasts(),
      nextBestActions: this.loadNextBestActions(),
      tenants: this.loadTenants(),
      deadLetterJobs: this.loadDeadLetterJobs(),
      integrations: this.loadIntegrations(),
      suppliers: this.loadSuppliers(),
      rfqs: this.loadRfqs(),
      warranties: this.loadWarranties(),
      amcs: this.loadAMCs(),
      tickets: this.loadTickets(),
      exportedAt: new Date().toISOString()
    };
    return JSON.stringify(backup, null, 2);
  },

  // Import JSON backup
  importFullBackup(jsonString: string): boolean {
    try {
      const parsed = JSON.parse(jsonString);
      if (parsed.company) this.saveCompanyProfile(parsed.company);
      if (parsed.leads) this.saveLeads(parsed.leads);
      if (parsed.customers) this.saveCustomers(parsed.customers);
      if (parsed.products) this.saveProducts(parsed.products);
      if (parsed.quotations) this.saveQuotations(parsed.quotations);
      if (parsed.inventory) this.saveInventory(parsed.inventory);
      if (parsed.purchaseOrders) this.savePurchaseOrders(parsed.purchaseOrders);
      if (parsed.salesOrders) this.saveSalesOrders(parsed.salesOrders);
      if (parsed.workOrders) this.saveWorkOrders(parsed.workOrders);
      if (parsed.rmas) this.saveRMAs(parsed.rmas);
      if (parsed.partners) this.savePartners(parsed.partners);
      if (parsed.dealRegistrations) this.saveDealRegistrations(parsed.dealRegistrations);
      if (parsed.commissions) this.saveCommissions(parsed.commissions);
      if (parsed.workflowRules) this.saveWorkflowRules(parsed.workflowRules);
      if (parsed.deadStock) this.saveDeadStock(parsed.deadStock);
      if (parsed.demandForecasts) this.saveDemandForecasts(parsed.demandForecasts);
      if (parsed.nextBestActions) this.saveNextBestActions(parsed.nextBestActions);
      if (parsed.tenants) this.saveTenants(parsed.tenants);
      if (parsed.deadLetterJobs) this.saveDeadLetterJobs(parsed.deadLetterJobs);
      if (parsed.integrations) this.saveIntegrations(parsed.integrations);
      if (parsed.suppliers) this.saveSuppliers(parsed.suppliers);
      if (parsed.rfqs) this.saveRfqs(parsed.rfqs);
      if (parsed.warranties) this.saveWarranties(parsed.warranties);
      if (parsed.amcs) this.saveAMCs(parsed.amcs);
      if (parsed.tickets) this.saveTickets(parsed.tickets);
      return true;
    } catch (err) {
      console.error('Import failed:', err);
      return false;
    }
  },

  // Wipe all mock/test data for a pristine fresh production start
  wipeToCleanProductionState() {
    this.saveCompanyProfile(DEFAULT_COMPANY_PROFILE);
    this.saveLeads([]);
    this.saveCustomers([]);
    this.saveProducts(AADITECH_SPECIALIZED_PRODUCTS);
    this.saveQuotations([]);
    this.saveInventory([]);
    this.savePurchaseOrders([]);
    this.saveSalesOrders([]);
    this.saveWorkOrders([]);
    this.saveRMAs([]);
    this.savePartners([]);
    this.saveDealRegistrations([]);
    this.saveCommissions([]);
    this.saveWorkflowRules(INITIAL_WORKFLOW_RULES);
    this.saveDeadStock([]);
    this.saveDemandForecasts([]);
    this.saveNextBestActions([]);
    this.saveTenants(INITIAL_TENANTS);
    this.saveDeadLetterJobs([]);
    this.saveIntegrations(INITIAL_INTEGRATIONS);
    this.saveSuppliers(INITIAL_SUPPLIERS);
    this.saveRfqs([]);
    this.saveWarranties([]);
    this.saveAMCs([]);
    this.saveTickets([]);
    this.saveCampaigns([]);
    this.saveGeMTenders([]);
    this.saveOutboundTargets([]);
    this.saveHardwareRefreshAssets([]);
    this.saveTelegramMessages([
      {
        id: 'tg-prod-init',
        sender: 'bot',
        text: '🟢 **SYSTEM READY FOR PRODUCTION OPERATION**\n\nAadiTech Solution Autonomous IT Hardware OS is now running in **Pristine Clean Production Mode**.\n\n• Zero test leads, mock quotes, or simulated orders\n• Real Product Master Catalog active (including ATS Hi-REL Power Systems)\n• Telegram Exception Gate armed for margin < 15%\n• Omnichannel Inbound listener active for WhatsApp, Website, IndiaMART & Email.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }
    ]);
    this.saveAuditLogs([
      {
        id: `AUD-INIT-${Date.now()}`,
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        agent: 'System Administrator',
        action: 'PRODUCTION_INITIALIZATION',
        entityType: 'SYSTEM',
        entityId: 'ATS-PROD-001',
        details: 'All simulated testing artifacts, mock leads, quotes, and orders completely wiped. System switched to fresh live production environment with zero test artifacts.',
        rulesChecked: 'Rule #64: Production Data Integrity & Sanitization',
        approvalRequired: false,
        status: 'AUTO_EXECUTED'
      }
    ]);
    this.setEnvironmentMode('PRODUCTION');
  },

  // Load comprehensive testing dataset for end-to-end evaluation
  loadTestingDemoState() {
    this.saveCompanyProfile(DEFAULT_COMPANY_PROFILE);
    this.saveLeads(INITIAL_LEADS);
    this.saveCustomers(INITIAL_CUSTOMERS);
    this.saveProducts(AADITECH_SPECIALIZED_PRODUCTS);
    this.saveQuotations(INITIAL_QUOTATIONS);
    this.saveInventory(INITIAL_INVENTORY);
    this.savePurchaseOrders(INITIAL_PURCHASE_ORDERS);
    this.saveSalesOrders(INITIAL_SALES_ORDERS);
    this.saveWorkOrders(INITIAL_WORK_ORDERS);
    this.saveRMAs(INITIAL_RMAS);
    this.savePartners(INITIAL_PARTNERS);
    this.saveDealRegistrations(INITIAL_DEAL_REGISTRATIONS);
    this.saveCommissions(INITIAL_COMMISSIONS);
    this.saveWorkflowRules(INITIAL_WORKFLOW_RULES);
    this.saveDeadStock(INITIAL_DEAD_STOCK);
    this.saveDemandForecasts(INITIAL_DEMAND_FORECASTS);
    this.saveNextBestActions(INITIAL_NEXT_BEST_ACTIONS);
    this.saveTenants(INITIAL_TENANTS);
    this.saveDeadLetterJobs(INITIAL_DEAD_LETTER_JOBS);
    this.saveIntegrations(INITIAL_INTEGRATIONS);
    this.saveSuppliers(INITIAL_SUPPLIERS);
    this.saveRfqs(INITIAL_RFQS);
    this.saveWarranties(INITIAL_WARRANTIES);
    this.saveAMCs(INITIAL_AMCS);
    this.saveTickets(INITIAL_TICKETS);
    this.saveCampaigns(INITIAL_CAMPAIGNS);
    this.saveGeMTenders(INITIAL_GEM_TENDERS);
    this.saveOutboundTargets(INITIAL_OUTBOUND_TARGETS);
    this.saveHardwareRefreshAssets(INITIAL_HARDWARE_REFRESH_ASSETS);
    this.saveTelegramMessages(INITIAL_TELEGRAM_MESSAGES);
    this.saveAuditLogs(INITIAL_AUDIT_LOGS);
    this.setEnvironmentMode('TESTING');
  },

  // Reset to factory defaults
  resetAllData() {
    Object.values(STORAGE_KEYS).forEach(k => {
      localStorage.removeItem(k);
    });
    this.setEnvironmentMode('TESTING');
  }
};
