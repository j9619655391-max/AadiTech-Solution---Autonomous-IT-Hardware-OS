/**
 * Autonomous IT Hardware Sales & Marketing Operating System
 * TypeScript Types & Domain Interfaces
 */

export type LeadStatus = 'NEW' | 'CONTACTED' | 'QUALIFIED' | 'BOM_GENERATED' | 'QUOTED' | 'NEGOTIATING' | 'WON' | 'LOST';
export type LeadScore = 'HOT' | 'WARM' | 'COLD' | 'NURTURE';
export type ChannelSource =
  | 'WEBSITE'
  | 'WHATSAPP'
  | 'INDIAMART'
  | 'JUSTDIAL'
  | 'EMAIL'
  | 'TELEGRAM'
  | 'REFERRAL'
  | 'GEM_TENDER'
  | 'OUTBOUND_HUNTER'
  | 'HARDWARE_REFRESH'
  | 'PARTNER_PORTAL'
  | 'OEM_PASS';

export interface Lead {
  id: string;
  name: string;
  company: string;
  email: string;
  phone: string;
  source: ChannelSource;
  status: LeadStatus;
  score: LeadScore;
  scoreReason: string;
  intentScore: number; // 0 - 100
  requirement: string;
  estimatedBudget: number;
  location: string;
  gstin?: string;
  createdAt: string;
  lastInteraction: string;
  tenderNumber?: string;
  bidClosingDate?: string;
  oemBrand?: string;
  refreshAssetDetails?: string;
}

export interface Customer360 {
  id: string;
  name: string;
  gstin: string;
  contactPerson: string;
  email: string;
  phone: string;
  city: string;
  state: string;
  creditLimit: number;
  currentOutstanding: number;
  paymentRiskScore: 'LOW' | 'MEDIUM' | 'HIGH';
  lifetimeValue: number;
  totalOrders: number;
  activeWarrantiesCount: number;
  activeAMCCount: number;
  lastPurchaseDate: string;
  preferredBrands: string[];
}

export interface Product {
  id: string;
  sku: string;
  brand: string;
  model: string;
  category: 'LAPTOP' | 'DESKTOP' | 'SERVER' | 'NETWORKING' | 'POWER_STORAGE' | 'ACCESSORIES';
  specs: string;
  unitCost: number;
  freightCost: number;
  riskBuffer: number;
  landedCost: number;
  sellingPrice: number;
  minPrice: number;
  targetMarginPct: number;
  gstRate: number; // e.g. 18
  hsn: string;
  warrantyMonths: number;
  stockBhiwandi: number;
  stockDelhi: number;
  stockBangalore: number;
  reservedStock: number;
  leadTimeDays: number;
}

export interface BOMItem {
  id: string;
  category: string;
  name: string;
  sku?: string;
  qty: number;
  unitCost: number;
  unitSell: number;
  hsn: string;
  gstRate: number;
}

export interface Quotation {
  id: string;
  quoteNumber: string;
  customerName: string;
  customerGstin: string;
  billingAddress: string;
  items: BOMItem[];
  subtotal: number;
  freight: number;
  cgst: number;
  sgst: number;
  igst: number;
  totalAmount: number;
  totalCost: number;
  marginPct: number;
  status: 'DRAFT' | 'PENDING_APPROVAL' | 'APPROVED' | 'SENT' | 'ACCEPTED' | 'REVISED' | 'REJECTED';
  approvalTierRequired: 'NONE' | 'MANAGER' | 'OWNER_TELEGRAM';
  validityDays: number;
  deliveryWeeks: number;
  paymentTerms: string;
  createdDate: string;
}

export interface TelegramApprovalCard {
  id: string;
  type: 'QUOTATION_MARGIN' | 'DISCOUNT_EXCEPTION' | 'CREDIT_LIMIT' | 'HIGH_VALUE_PURCHASE' | 'NEW_SUPPLIER';
  title: string;
  referenceId: string;
  amount: number;
  marginPct?: number;
  customerName: string;
  requestedBy: string;
  reason: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'MODIFIED';
  timeoutMinutes: number;
  createdAt: string;
  escalationLevel: 'NONE' | 'MANAGER_ALERT' | 'OWNER_ESCALATED';
}

export interface TelegramMessage {
  id: string;
  sender: 'user' | 'bot';
  text: string;
  timestamp: string;
  approvalCard?: TelegramApprovalCard;
  quickActions?: string[];
}

export interface Supplier {
  id: string;
  name: string;
  location: string;
  gstin: string;
  rating: number; // out of 5
  deliveryScore: number; // percentage
  defectRate: number; // percentage
  warrantySupportScore: number; // percentage
  paymentTerms: string;
  primaryBrands: string[];
}

export interface SupplierQuote {
  supplierId: string;
  supplierName: string;
  pricePerUnit: number;
  deliveryDays: number;
  warrantyYears: number;
  availability: 'IN_STOCK' | '3_DAYS' | '7_DAYS';
  reliabilityScore: number;
  aiRecommended?: boolean;
}

export interface RFQ {
  id: string;
  rfqNumber: string;
  productName: string;
  qty: number;
  requiredByDate: string;
  targetPrice: number;
  quotes: SupplierQuote[];
  status: 'OPEN' | 'QUOTES_RECEIVED' | 'PO_RAISED';
  selectedSupplier?: string;
}

export interface SerialInventory {
  id: string;
  serialNumber: string;
  sku: string;
  productName: string;
  warehouse: 'BHIWANDI_HUB' | 'DELHI_OKHLA' | 'BANGALORE_ECITY';
  binLocation: string;
  state: 'AVAILABLE' | 'RESERVED' | 'ALLOCATED' | 'PICKED' | 'QC_CHECK' | 'IN_TRANSIT' | 'SOLD' | 'RMA';
  cost: number;
  supplier: string;
  ageDays: number;
  isDeadStock?: boolean;
}

export interface WarrantyAsset {
  id: string;
  serialNumber: string;
  customerName: string;
  productName: string;
  purchaseDate: string;
  warrantyExpiryDate: string;
  daysRemaining: number;
  alertStatus: 'SAFE' | 'EXPIRING_90' | 'EXPIRING_60' | 'EXPIRING_30' | 'EXPIRING_15' | 'EXPIRED';
  hasActiveAMC: boolean;
}

export interface AMCContract {
  id: string;
  contractNumber: string;
  customerName: string;
  assetCount: number;
  annualFee: number;
  startDate: string;
  endDate: string;
  slaHours: number;
  scheduledVisitsPerYear: number;
  completedVisits: number;
  status: 'ACTIVE' | 'UP_FOR_RENEWAL' | 'EXPIRED';
}

export interface ServiceTicket {
  id: string;
  ticketNumber: string;
  customerName: string;
  serialNumber: string;
  issueDescription: string;
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'OPEN' | 'TECHNICIAN_ASSIGNED' | 'PARTS_ORDERED' | 'RESOLVED' | 'CLOSED';
  technician: string;
  slaTimeRemainingHours: number;
  createdAt: string;
}

export interface MarketingCampaign {
  id: string;
  name: string;
  targetSegment: string;
  channel: 'WHATSAPP' | 'EMAIL' | 'OMNICHANNEL' | 'LINKEDIN';
  status: 'DRAFT' | 'ACTIVE' | 'COMPLETED';
  reach: number;
  qualifiedLeads: number;
  ordersWon: number;
  revenueGenerated: number;
  roas: number;
  messagePreview: string;
}

export interface AIAgent {
  id: string;
  name: string;
  code: 'LEAD' | 'SALES' | 'PRICING' | 'BOM' | 'PROCUREMENT' | 'INVENTORY' | 'FINANCE' | 'SERVICE' | 'MARKETING';
  description: string;
  status: 'IDLE' | 'PROCESSING' | 'WAITING_APPROVAL' | 'SUCCESS';
  currentTask: string;
  tasksCompletedToday: number;
  confidenceScore: number; // 0 - 100
  recentActivity: string;
}

export interface PurchaseOrder {
  id: string;
  poNumber: string;
  rfqId?: string;
  supplierId: string;
  supplierName: string;
  productName: string;
  qty: number;
  unitPrice: number;
  totalAmount: number;
  gstAmount: number;
  deliveryWarehouse: string;
  status: 'ISSUED' | 'DISPATCHED' | 'QC_INSPECTION' | 'RECEIVED' | 'CANCELLED';
  expectedDelivery: string;
  createdDate: string;
}

export interface CompanyProfile {
  name: string;
  tagline: string;
  website: string;
  phone: string;
  email: string;
  gstin: string;
  pan: string;
  address: string;
  bankName: string;
  accountName: string;
  accountNumber: string;
  ifscCode: string;
  branch: string;
  upiId: string;
  defaultMarginThreshold: number; // e.g. 15
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  agent: string;
  action: string;
  entityType: string;
  entityId: string;
  details: string;
  rulesChecked: string;
  approvalRequired: boolean;
  status: 'AUTO_EXECUTED' | 'TELEGRAM_APPROVED' | 'REJECTED' | 'ESCALATED';
}

export interface SalesOrder {
  id: string;
  orderNumber: string;
  quoteId?: string;
  customerId: string;
  customerName: string;
  customerGst: string;
  items: {
    sku: string;
    productName: string;
    qty: number;
    unitPrice: number;
    total: number;
    serialNumbers?: string[];
  }[];
  subtotal: number;
  gstAmount: number;
  totalAmount: number;
  paymentStatus: 'PENDING' | 'ADVANCE_RECEIVED' | 'PAID' | 'CREDIT_TERMS';
  fulfillmentStatus: 'ORDER_CONFIRMED' | 'PICKED_IN_QC' | 'PACKED' | 'DISPATCHED' | 'DELIVERED';
  courierName?: 'BlueDart Express' | 'Delhivery Freight' | 'Safexpress Logistics' | 'DTDC Air';
  awbNumber?: string;
  eWayBillNumber?: string;
  irnNumber?: string;
  destinationCity: string;
  deliveryAddress: string;
  createdDate: string;
  expectedDelivery: string;
}

export interface InstallationWorkOrder {
  id: string;
  workOrderNumber: string;
  orderId: string;
  customerName: string;
  siteAddress: string;
  hardwareSummary: string;
  assignedTechnician: string;
  technicianPhone: string;
  scheduledDate: string;
  status: 'SCHEDULED' | 'TECHNICIAN_ON_SITE' | 'CONFIGURING' | 'COMPLETED';
  checklist: {
    item: string;
    done: boolean;
  }[];
  customerSignoff: boolean;
  remarks?: string;
}

export interface RMARequest {
  id: string;
  rmaNumber: string;
  customerName: string;
  serialNumber: string;
  productModel: string;
  issueReported: string;
  status: 'RMA_INITIATED' | 'PICKUP_SCHEDULED' | 'UNDER_DIAGNOSTICS' | 'REPLACED_DISPATCHED' | 'CLOSED';
  pickupAddress: string;
  technicianAssigned: string;
  createdDate: string;
}

export interface PartnerAccount {
  id: string;
  partnerName: string;
  partnerType: 'SYSTEM_INTEGRATOR' | 'REGIONAL_RESELLER' | 'OEM_PARTNER';
  tier: 'SILVER' | 'GOLD' | 'PLATINUM';
  contactPerson: string;
  email: string;
  phone: string;
  city: string;
  discountMarginPct: number;
  registeredDealsCount: number;
  totalRevenueGenerated: number;
  commissionEarned: number;
  commissionPaid: number;
}

export interface DealRegistration {
  id: string;
  dealNumber: string;
  partnerId: string;
  partnerName: string;
  endCustomerName: string;
  solutionType: string;
  estimatedValue: number;
  status: 'LOCKED_APPROVED' | 'PENDING_REVIEW' | 'WON' | 'LOST';
  validUntil: string;
  protectionDaysRemaining: number;
}

export interface CommissionRecord {
  id: string;
  partnerName: string;
  salesOrderNumber: string;
  dealValue: number;
  commissionRatePct: number;
  commissionAmount: number;
  payoutStatus: 'PENDING_APPROVAL' | 'PROCESSED' | 'PAID';
  disbursedDate?: string;
}

export interface WorkflowRule {
  id: string;
  ruleCode: string;
  name: string;
  triggerEvent: string;
  condition: string;
  aiDecision: string;
  action: string;
  channel: 'TELEGRAM' | 'WHATSAPP' | 'SYSTEM_EVENT' | 'EMAIL';
  status: 'ACTIVE' | 'PAUSED';
  executionsCount: number;
  lastTriggered: string;
}

export interface EventBusMessage {
  id: string;
  eventId: string;
  eventType: string;
  sourceAgent: string;
  targetModule: string;
  payloadSnippet: string;
  status: 'DISPATCHED' | 'PROCESSED' | 'ACKNOWLEDGED';
  latencyMs: number;
  timestamp: string;
}

export interface KnowledgeDocument {
  id: string;
  title: string;
  category: 'HARDWARE_DATASHEET' | 'WARRANTY_POLICY' | 'SLA_TERMS' | 'RMA_PROCEDURE';
  productLine: string;
  snippet: string;
  docSize: string;
  lastUpdated: string;
}

// ==========================================
// Sections 54 - 60: Forecasting, Analytics & LTV
// ==========================================

export interface DeadStockItem {
  id: string;
  sku: string;
  productName: string;
  warehouse: string;
  ageDays: number;
  qty: number;
  unitBookCost: number;
  totalBookValue: number;
  estimatedMarketValue: number;
  monthlyHoldingCost: number;
  aiRecommendation: 'LIQUIDATE_25_DISCOUNT' | 'BUNDLE_WITH_SERVERS' | 'CHANNEL_PARTNER_BULK' | 'RETURN_SUPPLIER_CREDIT';
  recommendationNote: string;
  status: 'PENDING_ACTION' | 'OFFER_DISPATCHED' | 'LIQUIDATED';
}

export interface DemandForecast {
  id: string;
  category: 'LAPTOPS' | 'RACK_SERVERS' | 'SWITCHES_ROUTERS' | 'UTM_FIREWALLS' | 'POWER_SYSTEMS';
  timeHorizon: '7_DAYS' | '14_DAYS' | '30_DAYS' | '60_DAYS' | '90_DAYS';
  predictedUnits: number;
  currentAvailableStock: number;
  pipelineDemand: number;
  recommendedOrderUnits: number;
  urgency: 'HIGH_STOCKOUT_RISK' | 'NORMAL_BUFFER' | 'EXCESS_STOCK';
  keyDriver: string;
}

export interface SalesForecastSummary {
  period: 'CURRENT_MONTH' | 'NEXT_30_DAYS' | 'NEXT_60_DAYS';
  pipelineDealsCount: number;
  grossPipelineValue: number;
  weightedProjectedRevenue: number;
  projectedGrossProfit: number;
  projectedMarginPct: number;
  historicalWinRatePct: number;
  topDeals: {
    customerName: string;
    value: number;
    probabilityPct: number;
    stage: string;
  }[];
}

export interface CashFlowForecastItem {
  month: string;
  expectedCollections: number; // inflows from debtors
  supplierPayables: number; // outflows to distributors
  operatingExpenses: number; // salaries, rent, logistics
  gstPayableEstimate: number;
  netCashFlow: number;
  projectedClosingBalance: number;
  runwayStatus: 'OPTIMAL' | 'MODERATE_SURPLUS' | 'TIGHT_CAPITAL';
}

export interface NextBestAction {
  id: string;
  entityType: 'LEAD' | 'CUSTOMER' | 'QUOTE' | 'WARRANTY';
  entityName: string;
  priority: 'URGENT' | 'HIGH' | 'MEDIUM';
  actionTitle: string;
  rationale: string;
  projectedRevenueImpact: number;
  suggestedChannel: 'WHATSAPP' | 'TELEGRAM' | 'PHONE' | 'EMAIL';
  status: 'RECOMMENDED' | 'TRIGGERED' | 'DISMISSED';
}

export interface LostDealAnalysis {
  id: string;
  dealNumber: string;
  customerName: string;
  productRequested: string;
  dealValue: number;
  primaryLossReason: 'PRICE_TOO_HIGH' | 'COMPETITOR_UNDERCUT' | 'DELIVERY_LEAD_TIME' | 'SPEC_MISMATCH' | 'STRICT_CREDIT_TERMS';
  competitorWinner?: string;
  lossDate: string;
  aiPostMortemInsight: string;
  correctiveStrategy: string;
}

export interface CustomerLTVAnalysis {
  id: string;
  customerName: string;
  industry: string;
  currentLifetimeSpend: number;
  projected3YearLTV: number;
  expansionOpportunities: {
    opportunityName: string;
    potentialValue: number;
    readiness: 'IMMEDIATE' | 'NEXT_QUARTER' | 'LONG_TERM';
  }[];
  retentionRisk: 'LOW' | 'MEDIUM' | 'HIGH';
}

// ==========================================
// Sections 3, 4, 61, 62, 64, 65, 66: System, Multi-Tenant, Observability & API
// ==========================================

export interface TenantAccount {
  id: string;
  tenantCode: string;
  companyName: string;
  gstin: string;
  stateCode: string;
  operatingCurrency: string;
  activeUsersCount: number;
  plan: 'ENTERPRISE_DISTRIBUTOR' | 'SYSTEM_INTEGRATOR_PRO';
  storageQuotaMb: number;
  storageUsedMb: number;
  status: 'ACTIVE' | 'SANDBOX';
  isCurrent: boolean;
}

export interface UserRoleDefinition {
  roleId: string;
  roleName: string;
  department: string;
  allowedActions: string[];
  restrictedActions: string[];
  description: string;
}

export interface SystemHealthMetric {
  serviceId: string;
  serviceName: string;
  category: 'API' | 'EVENT_BUS' | 'DATABASE' | 'MESSAGING' | 'COMPLIANCE' | 'ERP_SYNC';
  status: 'OPERATIONAL' | 'DEGRADED' | 'MAINTENANCE';
  latencyMs: number;
  uptimePercentage: number;
  lastChecked: string;
  endpointsActive: number;
}

export interface DeadLetterJob {
  id: string;
  jobName: string;
  sourceModule: string;
  targetDestination: string;
  payloadSummary: string;
  errorMessage: string;
  retryCount: number;
  maxRetries: number;
  status: 'DEAD_LETTER' | 'RETRYING' | 'RESOLVED';
  failedAt: string;
}

export interface IntegrationConnector {
  id: string;
  name: string;
  category: 'ACCOUNTING_ERP' | 'LOGISTICS_COURIER' | 'PAYMENT_GATEWAY' | 'COMMUNICATION' | 'B2B_PORTAL';
  provider: string;
  connectionStatus: 'CONNECTED' | 'DISCONNECTED' | 'SYNCING';
  lastSyncTimestamp: string;
  syncedRecordsToday: number;
  endpointUrl: string;
  iconType: string;
}

export interface ApiEndpointDoc {
  id: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  path: string;
  summary: string;
  category: 'LEADS' | 'BOM' | 'QUOTES' | 'ORDERS' | 'INVENTORY' | 'TELEMETRY';
  sampleResponse: string;
  authRequired: boolean;
}

export interface GeMTenderBid {
  id: string;
  bidNumber: string;
  departmentName: string;
  ministry: string;
  title: string;
  category: 'POWER_SYSTEMS' | 'SERVERS_STORAGE' | 'LAPTOPS_COMPUTING' | 'NETWORKING';
  estimatedBudget: number;
  bidClosingDate: string;
  emdAmount: number;
  specs: string;
  qualificationStatus: 'MATCHED_ATS_PRODUCTS' | 'OEM_MAJ_REQUIRED' | 'UNDER_EVALUATION';
  turnkeyMarginEstimate: number; // e.g. 24%
}

export interface OutboundProspectAccount {
  id: string;
  companyName: string;
  industry: string;
  location: string;
  expansionTrigger: string;
  targetContact: {
    name: string;
    designation: string;
    email: string;
    phone: string;
  };
  recommendedPitch: string;
  projectedOpportunityValue: number;
  outreachStatus: 'DISCOVERED' | 'SEQUENCE_ACTIVE' | 'RESPONDED_CONVERTED';
}

export interface HardwareRefreshAsset {
  id: string;
  customerId: string;
  customerName: string;
  hardwareCategory: string;
  originalDeploymentDate: string;
  assetAgeMonths: number;
  deployedQuantity: number;
  deployedModels: string;
  suggestedReplacementModel: string;
  estimatedRefreshBudget: number;
  healthScore: number; // 0 - 100
  refreshStatus: 'ELIGIBLE_FOR_REFRESH' | 'PROPOSAL_SENT' | 'REPLACED';
}

