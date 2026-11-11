import { authenticatedFetch } from './services/authClient';
import React, { useState } from 'react';
import { Header } from './components/Header';
import { TelegramCommandHub } from './components/TelegramCommandHub';
import { ExecutiveDashboard } from './components/ExecutiveDashboard';
import { CRMAndLeadsView } from './components/CRMAndLeadsView';
import { LiveCRMWorkspace } from './components/LiveCRMWorkspace';
import { LiveInventoryWorkspace } from './components/LiveInventoryWorkspace';
import { SalesAndBOMBuilder } from './components/SalesAndBOMBuilder';
import { LiveBOMWorkspace } from './components/LiveBOMWorkspace';
import { QuotationAndNegotiation } from './components/QuotationAndNegotiation';
import { ApprovalEngineView } from './components/ApprovalEngineView';
import { ProcurementAndInventory } from './components/ProcurementAndInventory';
import { OrdersAndLogisticsView } from './components/OrdersAndLogisticsView';
import { PortalsAndResellersView } from './components/PortalsAndResellersView';
import { WorkflowsAndRAGView } from './components/WorkflowsAndRAGView';
import { FinanceAndServiceView } from './components/FinanceAndServiceView';
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

  // Add Real Customer
  const handleAddCustomer = (newCustomer: Customer360) => {
    setCustomers(prev => {
      const updated = [newCustomer, ...prev];
      storageService.saveCustomers(updated);
      return updated;
    });
    const audit: AuditEvent = {
      id: `AUD-${Date.now()}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      agent: 'AI CRM Agent',
      action: 'CUSTOMER_ONBOARDED',
      entityType: 'CUSTOMER',
      entityId: newCustomer.id,
      details: `New customer account ${newCustomer.name} (GST: ${newCustomer.gstin}) onboarded with ₹${(newCustomer.creditLimit / 100000).toFixed(1)}L credit limit.`,
      rulesChecked: 'Rule #28: B2B Credit Limit & KYC Verification',
      approvalRequired: false,
      status: 'AUTO_EXECUTED'
    };
    setAuditLogs(prev => {
      const updated = [audit, ...prev];
      storageService.saveAuditLogs(updated);
      return updated;
    });
  };

  // Add Real Product SKU
  const handleAddProduct = (newProduct: Product) => {
    setProducts(prev => {
      const updated = [newProduct, ...prev];
      storageService.saveProducts(updated);
      return updated;
    });
    const audit: AuditEvent = {
      id: `AUD-${Date.now()}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      agent: 'AI Inventory Agent',
      action: 'PRODUCT_REGISTERED',
      entityType: 'PRODUCT',
      entityId: newProduct.id,
      details: `Registered new SKU ${newProduct.sku} (${newProduct.brand} ${newProduct.model}) at ₹${newProduct.unitCost} cost / ₹${newProduct.sellingPrice} sell.`,
      rulesChecked: 'Rule #12: Master SKU Registry & Margin Guard',
      approvalRequired: false,
      status: 'AUTO_EXECUTED'
    };
    setAuditLogs(prev => {
      const updated = [audit, ...prev];
      storageService.saveAuditLogs(updated);
      return updated;
    });
  };

  // Add Real Serialized Hardware Unit
  const handleAddInventoryItem = (newInv: SerialInventory) => {
    setInventory(prev => {
      const updated = [newInv, ...prev];
      storageService.saveInventory(updated);
      return updated;
    });
    const audit: AuditEvent = {
      id: `AUD-${Date.now()}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      agent: 'AI Warehouse Agent',
      action: 'SERIAL_INWARDED',
      entityType: 'INVENTORY',
      entityId: newInv.id,
      details: `Inwarded serial ${newInv.serialNumber} (${newInv.sku}) at ${newInv.warehouse} bin ${newInv.binLocation}.`,
      rulesChecked: 'Rule #15: Serialized Hardware Inward & QC Validation',
      approvalRequired: false,
      status: 'AUTO_EXECUTED'
    };
    setAuditLogs(prev => {
      const updated = [audit, ...prev];
      storageService.saveAuditLogs(updated);
      return updated;
    });
  };

  // Add Real RFQ
  const handleAddRFQ = (newRFQ: RFQ) => {
    setRfqs(prev => {
      const updated = [newRFQ, ...prev];
      storageService.saveRfqs(updated);
      return updated;
    });
    const audit: AuditEvent = {
      id: `AUD-${Date.now()}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      agent: 'AI Procurement Agent',
      action: 'RFQ_BROADCASTED',
      entityType: 'RFQ',
      entityId: newRFQ.id,
      details: `RFQ ${newRFQ.rfqNumber} for ${newRFQ.qty}x ${newRFQ.productName} broadcasted to authorized distributors.`,
      rulesChecked: 'Rule #18: Multi-Distributor Competitive Tender',
      approvalRequired: false,
      status: 'AUTO_EXECUTED'
    };
    setAuditLogs(prev => {
      const updated = [audit, ...prev];
      storageService.saveAuditLogs(updated);
      return updated;
    });
  };

  // Add Lead
  const handleAddLead = (newLead: Lead) => {
    setLeads(prev => {
      const updated = [newLead, ...prev];
      storageService.saveLeads(updated);
      return updated;
    });
    const audit: AuditEvent = {
      id: `AUD-${Date.now()}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      agent: 'AI Lead Agent',
      action: 'LEAD_CAPTURED',
      entityType: 'LEAD',
      entityId: newLead.id,
      details: `Captured ${newLead.company} via ${newLead.source}. Calculated Intent Score: ${newLead.intentScore}/100.`,
      rulesChecked: 'Rule #6: Inbound Lead Intake & Auto-Scoring',
      approvalRequired: false,
      status: 'AUTO_EXECUTED'
    };
    setAuditLogs(prev => {
      const updated = [audit, ...prev];
      storageService.saveAuditLogs(updated);
      return updated;
    });
  };

  // BOM to Quotation Transition
  const handleGenerateQuote = (bomItems: BOMItem[], targetMargin: number) => {
    const subtotal = bomItems.reduce((acc, it) => acc + (it.unitSell * it.qty), 0);
    const totalCost = bomItems.reduce((acc, it) => acc + (it.unitCost * it.qty), 0);
    const freight = 5000;
    const cgst = Math.round(subtotal * 0.09);
    const sgst = Math.round(subtotal * 0.09);
    const totalAmount = subtotal + freight + cgst + sgst;
    const marginPct = Number((((subtotal - totalCost) / subtotal) * 100).toFixed(1));

    const newQuoteNumber = `QT-2026-${Math.floor(100 + Math.random() * 900)}`;
    const requiresOwnerApproval = marginPct < companyProfile.defaultMarginThreshold;

    const newQuote: Quotation = {
      id: newQuoteNumber,
      quoteNumber: newQuoteNumber,
      customerName: 'FinStack Technologies Ltd',
      customerGstin: '27AABCF1290K1ZP',
      billingAddress: 'Level 8, Platina Tower, Bandra Kurla Complex, Mumbai, MH - 400051',
      items: bomItems,
      subtotal,
      freight,
      cgst,
      sgst,
      igst: 0,
      totalAmount,
      totalCost,
      marginPct,
      status: requiresOwnerApproval ? 'PENDING_APPROVAL' : 'APPROVED',
      approvalTierRequired: requiresOwnerApproval ? 'OWNER_TELEGRAM' : 'NONE',
      validityDays: 15,
      deliveryWeeks: 1,
      paymentTerms: '30% Advance with PO, Balance against Delivery',
      createdDate: new Date().toISOString().split('T')[0]
    };

    setQuotations(prev => {
      const updated = [newQuote, ...prev];
      storageService.saveQuotations(updated);
      return updated;
    });
    setActiveQuoteId(newQuote.id);
    setActiveTab('quotes');

    if (requiresOwnerApproval) {
      const card: TelegramApprovalCard = {
        id: `appr-${Date.now()}`,
        type: 'QUOTATION_MARGIN',
        title: `Margin Exception: ${newQuoteNumber}`,
        referenceId: newQuoteNumber,
        amount: totalAmount,
        marginPct,
        customerName: newQuote.customerName,
        requestedBy: 'AI Sales Agent (via BOM Builder)',
        reason: `Deal calculated at ${marginPct}% margin, which is below the ${companyProfile.defaultMarginThreshold}% autonomous boundary. Total value: ₹${totalAmount.toLocaleString('en-IN')}.`,
        status: 'PENDING',
        timeoutMinutes: 10,
        createdAt: new Date().toLocaleTimeString(),
        escalationLevel: 'OWNER_ESCALATED'
      };

      const tgMsg: TelegramMessage = {
        id: `tg-${Date.now()}`,
        sender: 'bot',
        text: `🔔 **NEW APPROVAL GATE DISPATCHED**\nQuotation **${newQuoteNumber}** generated for **${newQuote.customerName}** has margin **${marginPct}%** (<${companyProfile.defaultMarginThreshold}%).`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        approvalCard: card
      };

      setTelegramMessages(prev => {
        const updated = [...prev, tgMsg];
        storageService.saveTelegramMessages(updated);
        return updated;
      });
    }
  };

  // RFQ to PO
  const handleRaisePO = (rfqId: string, supplierId: string) => {
    const rfq = rfqs.find(r => r.id === rfqId);
    const quote = rfq?.quotes?.find(q => q.supplierId === supplierId);
    const sup = suppliers.find(s => s.id === supplierId);
    const poNum = `PO-2026-${Math.floor(100 + Math.random() * 900)}`;
    const unitP = quote ? quote.pricePerUnit : (rfq?.targetPrice || 50000);
    const qty = rfq?.qty || 1;
    const baseTotal = unitP * qty;
    const gst = Math.round(baseTotal * 0.18);

    const newPO: PurchaseOrder = {
      id: poNum,
      poNumber: poNum,
      supplierId: supplierId,
      supplierName: sup?.name || quote?.supplierName || 'Authorized Distributor',
      rfqId: rfqId,
      productName: rfq?.productName || 'IT Hardware Equipment',
      qty: qty,
      unitPrice: unitP,
      totalAmount: baseTotal + gst,
      gstAmount: gst,
      deliveryWarehouse: 'BHIWANDI_HUB',
      status: 'ISSUED',
      expectedDelivery: 'Within 3 Business Days',
      createdDate: new Date().toISOString().split('T')[0]
    };

    setPurchaseOrders(prev => {
      const updated = [newPO, ...prev];
      storageService.savePurchaseOrders(updated);
      return updated;
    });

    const audit: AuditEvent = {
      id: `AUD-${Date.now()}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      agent: 'AI Procurement Agent',
      action: 'PO_GENERATED',
      entityType: 'PO',
      entityId: poNum,
      details: `Purchase Order ${poNum} issued to ${newPO.supplierName} for ₹${newPO.totalAmount.toLocaleString('en-IN')}. GRN scheduled for Bhiwandi QC inspection.`,
      rulesChecked: 'Rule #17: Procurement RFQ & Supplier Scorecard',
      approvalRequired: false,
      status: 'AUTO_EXECUTED'
    };
    setAuditLogs(prev => {
      const updated = [audit, ...prev];
      storageService.saveAuditLogs(updated);
      return updated;
    });
  };

  // AMC Renewal
  const handleTriggerRenewal = (contractId: string) => {
    setAmcs(prev =>
      prev.map(c => c.id === contractId ? { ...c, status: 'ACTIVE' } : c)
    );
    alert('Autonomous 1-Year Comprehensive AMC Renewal Quote dispatched via WhatsApp & Email to customer finance team.');
  };

  // Technician Assignment
  const handleAssignTechnician = (ticketId: string, techName: string) => {
    setTickets(prev =>
      prev.map(t => t.id === ticketId ? { ...t, status: 'TECHNICIAN_ASSIGNED', technician: techName } : t)
    );
  };

  // Orders & Fulfillment Handlers
  const handleUpdateOrderStatus = (orderId: string, status: SalesOrder['fulfillmentStatus']) => {
    setSalesOrders(prev => {
      const updated = prev.map(o => o.id === orderId ? { ...o, fulfillmentStatus: status } : o);
      storageService.saveSalesOrders(updated);
      return updated;
    });
  };

  const handleDispatchOrder = (orderId: string, courier: SalesOrder['courierName'], awb: string, eWayBill: string) => {
    setSalesOrders(prev => {
      const updated = prev.map(o => {
        if (o.id === orderId) {
          return {
            ...o,
            fulfillmentStatus: 'DISPATCHED' as const,
            courierName: courier,
            awbNumber: awb,
            eWayBillNumber: eWayBill,
            irnNumber: o.irnNumber || `irn_${Date.now()}_nic_einvoice_verified`
          };
        }
        return o;
      });
      storageService.saveSalesOrders(updated);
      return updated;
    });

    const targetOrder = salesOrders.find(o => o.id === orderId);
    if (targetOrder) {
      const newEvent: EventBusMessage = {
        id: `EVT-${Date.now()}`,
        eventId: `EVT_DSP_${Date.now().toString().slice(-4)}`,
        eventType: 'DispatchReleased',
        sourceAgent: 'AI Logistics Agent',
        targetModule: 'Customer Portal & SMS Gateway',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        payloadSnippet: `Order ${targetOrder.orderNumber} dispatched via ${courier} AWB #${awb} e-Way Bill #${eWayBill}`,
        status: 'DISPATCHED',
        latencyMs: 38
      };
      setEventBusMessages(prev => {
        const updated = [newEvent, ...prev];
        storageService.saveEventBusMessages(updated);
        return updated;
      });

      const audit: AuditEvent = {
        id: `AUD-${Date.now()}`,
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        agent: 'AI Logistics & Dispatch Agent',
        action: 'ORDER_DISPATCHED',
        entityType: 'ORDER',
        entityId: targetOrder.orderNumber,
        details: `Dispatched order to ${targetOrder.customerName} via ${courier} (AWB: ${awb}). GST e-Way Bill transmitted.`,
        rulesChecked: 'Rule #31: Warehouse QC Seal & Courier Dispatch Compliance',
        approvalRequired: false,
        status: 'AUTO_EXECUTED'
      };
      setAuditLogs(prev => {
        const updated = [audit, ...prev];
        storageService.saveAuditLogs(updated);
        return updated;
      });
    }
  };

  const handleToggleWorkOrderChecklist = (woId: string, index: number) => {
    setWorkOrders(prev => {
      const updated = prev.map(w => {
        if (w.id === woId) {
          const newChecklist = [...w.checklist];
          newChecklist[index] = { ...newChecklist[index], done: !newChecklist[index].done };
          return { ...w, checklist: newChecklist };
        }
        return w;
      });
      storageService.saveWorkOrders(updated);
      return updated;
    });
  };

  const handleUpdateWorkOrderStatus = (woId: string, status: InstallationWorkOrder['status']) => {
    setWorkOrders(prev => {
      const updated = prev.map(w => {
        if (w.id === woId) {
          return {
            ...w,
            status,
            customerSignoff: status === 'COMPLETED' ? true : w.customerSignoff
          };
        }
        return w;
      });
      storageService.saveWorkOrders(updated);
      return updated;
    });
  };

  const handleCreateWorkOrder = (wo: InstallationWorkOrder) => {
    setWorkOrders(prev => {
      const updated = [wo, ...prev];
      storageService.saveWorkOrders(updated);
      return updated;
    });
    const audit: AuditEvent = {
      id: `AUD-${Date.now()}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      agent: 'AI Field Service Agent',
      action: 'WORK_ORDER_SCHEDULED',
      entityType: 'WORK_ORDER',
      entityId: wo.workOrderNumber,
      details: `On-site commissioning work order assigned to ${wo.assignedTechnician} for ${wo.customerName}.`,
      rulesChecked: 'Rule #34: Turnkey On-Site Deployment Protocol',
      approvalRequired: false,
      status: 'AUTO_EXECUTED'
    };
    setAuditLogs(prev => {
      const updated = [audit, ...prev];
      storageService.saveAuditLogs(updated);
      return updated;
    });
  };

  const handleAddRMA = (rma: RMARequest) => {
    setRmas(prev => {
      const updated = [rma, ...prev];
      storageService.saveRMAs(updated);
      return updated;
    });
    const audit: AuditEvent = {
      id: `AUD-${Date.now()}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      agent: 'AI RMA & Reverse Logistics Agent',
      action: 'RMA_CLAIM_RAISED',
      entityType: 'RMA',
      entityId: rma.rmaNumber,
      details: `DOA Advance replacement initiated for ${rma.customerName} (SN: ${rma.serialNumber}). Assigned to ${rma.technicianAssigned}.`,
      rulesChecked: 'Rule #35: 14-Day DOA Hardware Replacement Policy',
      approvalRequired: false,
      status: 'AUTO_EXECUTED'
    };
    setAuditLogs(prev => {
      const updated = [audit, ...prev];
      storageService.saveAuditLogs(updated);
      return updated;
    });
  };

  // 1-Click Accept Quotation & Conversion to Sales Order
  const handleAcceptQuotation = (quoteId: string) => {
    let convertedOrderNumber = '';
    setQuotations(prev => {
      const updated = prev.map(q => {
        if (q.id === quoteId) {
          convertedOrderNumber = `SO-2026-${Math.floor(100 + Math.random() * 900)}`;
          return { ...q, status: 'WON' as const };
        }
        return q;
      });
      storageService.saveQuotations(updated);
      return updated;
    });

    const quote = quotations.find(q => q.id === quoteId);
    if (quote) {
      const newSO: SalesOrder = {
        id: `so-${Date.now()}`,
        orderNumber: convertedOrderNumber || `SO-2026-${Math.floor(100 + Math.random() * 900)}`,
        quoteId: quote.id,
        customerId: quote.customerId || 'CUST-AUTO',
        customerName: quote.customerName,
        customerGst: '27AABCF1290K1ZP',
        destinationCity: 'Mumbai',
        deliveryAddress: 'Enterprise IT Data Center, Mumbai, Maharashtra 400051',
        items: quote.items.map(item => ({
          productName: item.productName,
          sku: item.productId || 'SKU-ENT',
          qty: item.qty,
          unitPrice: item.unitPrice,
          total: item.total,
          serialNumbers: [`SN-${Math.floor(100000 + Math.random() * 900000)}`]
        })),
        subtotal: quote.subtotal,
        gstAmount: quote.taxAmount,
        totalAmount: quote.totalAmount,
        fulfillmentStatus: 'ORDER_CONFIRMED',
        paymentStatus: 'PAID',
        createdDate: new Date().toISOString().split('T')[0],
        expectedDelivery: new Date(Date.now() + 86400000 * 3).toISOString().split('T')[0]
      };

      setSalesOrders(prev => {
        const updated = [newSO, ...prev];
        storageService.saveSalesOrders(updated);
        return updated;
      });

      const audit: AuditEvent = {
        id: `AUD-${Date.now()}`,
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        agent: 'AI Order Processing Agent',
        action: 'ORDER_CONVERTED_FROM_QUOTE',
        entityType: 'ORDER',
        entityId: newSO.orderNumber,
        details: `Quotation ${quote.quoteNumber} accepted by customer. Generated Sales Order ${newSO.orderNumber} for ₹${quote.totalAmount.toLocaleString('en-IN')}.`,
        rulesChecked: 'Rule #27: Quote-to-Cash Automation Pipeline',
        approvalRequired: false,
        status: 'AUTO_EXECUTED'
      };
      setAuditLogs(prev => {
        const updated = [audit, ...prev];
        storageService.saveAuditLogs(updated);
        return updated;
      });
    }
  };

  // Deal Registration Handler
  const handleRegisterDeal = (deal: DealRegistration) => {
    setDealRegistrations(prev => {
      const updated = [deal, ...prev];
      storageService.saveDealRegistrations(updated);
      return updated;
    });
    setPartners(prev => {
      const updated = prev.map(p => p.id === deal.partnerId ? { ...p, registeredDealsCount: p.registeredDealsCount + 1 } : p);
      storageService.savePartners(updated);
      return updated;
    });
    const audit: AuditEvent = {
      id: `AUD-${Date.now()}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      agent: 'AI Partner Channel Agent',
      action: 'DEAL_REGISTERED',
      entityType: 'DEAL',
      entityId: deal.dealNumber,
      details: `Registered deal for ${deal.partnerName} on end-customer ${deal.endCustomerName} (₹${deal.estimatedValue.toLocaleString('en-IN')}) with 60-day price protection lock.`,
      rulesChecked: 'Rule #44: Channel Partner Deal Protection Protocol',
      approvalRequired: false,
      status: 'AUTO_EXECUTED'
    };
    setAuditLogs(prev => {
      const updated = [audit, ...prev];
      storageService.saveAuditLogs(updated);
      return updated;
    });
  };

  // Approve Commission
  const handleApproveCommission = (commId: string) => {
    setCommissions(prev => {
      const updated = prev.map(c => c.id === commId ? { ...c, payoutStatus: 'PAID' as const, disbursedDate: new Date().toISOString().split('T')[0] } : c);
      storageService.saveCommissions(updated);
      return updated;
    });
  };

  // Workflow Handlers
  const handleToggleWorkflowRule = (ruleId: string) => {
    setWorkflowRules(prev => {
      const updated = prev.map(r => r.id === ruleId ? { ...r, status: (r.status === 'ACTIVE' ? 'PAUSED' : 'ACTIVE') as any } : r);
      storageService.saveWorkflowRules(updated);
      return updated;
    });
  };

  const handleExecuteWorkflowRule = (ruleId: string) => {
    const targetRule = workflowRules.find(r => r.id === ruleId);
    if (targetRule) {
      setWorkflowRules(prev => {
        const updated = prev.map(r => r.id === ruleId ? {
          ...r,
          executionsCount: r.executionsCount + 1,
          lastTriggered: 'Just now'
        } : r);
        storageService.saveWorkflowRules(updated);
        return updated;
      });

      const newMsg: EventBusMessage = {
        id: `EVT-${Date.now()}`,
        eventId: `EVT_WF_${Date.now().toString().slice(-4)}`,
        eventType: 'WorkflowTriggerExecuted',
        sourceAgent: 'Autonomous Workflow Engine',
        targetModule: targetRule.channel,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        payloadSnippet: `Dispatched action: "${targetRule.action}" upon condition check: [${targetRule.condition}]`,
        status: 'PROCESSED',
        latencyMs: 42
      };
      setEventBusMessages(prev => {
        const updated = [newMsg, ...prev];
        storageService.saveEventBusMessages(updated);
        return updated;
      });

      alert(`Workflow rule "${targetRule.name}" simulated successfully! Action: ${targetRule.action} dispatched via ${targetRule.channel}.`);
    }
  };

  const handleCreateWorkflowRule = (rule: WorkflowRule) => {
    setWorkflowRules(prev => {
      const updated = [rule, ...prev];
      storageService.saveWorkflowRules(updated);
      return updated;
    });
  };

  // Predictive Analytics Handlers
  const handleUpdateDeadStock = (items: DeadStockItem[]) => {
    setDeadStock(items);
    storageService.saveDeadStock(items);
  };

  const handleUpdateDemandForecasts = (forecasts: DemandForecast[]) => {
    setDemandForecasts(forecasts);
    storageService.saveDemandForecasts(forecasts);
  };

  const handleTriggerNextBestAction = (actionId: string) => {
    const updated = nextBestActions.map(a => a.id === actionId ? { ...a, status: 'TRIGGERED' as const } : a);
    setNextBestActions(updated);
    storageService.saveNextBestActions(updated);
  };

  // System Hub Handlers
  const handleSwitchTenant = (tenantId: string) => {
    const updated = tenants.map(t => ({
      ...t,
      isCurrent: t.id === tenantId
    }));
    setTenants(updated);
    storageService.saveTenants(updated);
  };

  const handleRetryDeadLetterJob = (jobId: string) => {
    const updated = deadLetterJobs.map(j => {
      if (j.id === jobId) {
        return {
          ...j,
          status: 'RESOLVED' as const,
          retryCount: j.retryCount + 1
        };
      }
      return j;
    });
    setDeadLetterJobs(updated);
    storageService.saveDeadLetterJobs(updated);
  };

  const handleToggleIntegration = (id: string) => {
    const updated = integrations.map(item => {
      if (item.id === id) {
        return {
          ...item,
          connectionStatus: item.connectionStatus === 'CONNECTED' ? ('DISCONNECTED' as const) : ('CONNECTED' as const),
          lastSyncTimestamp: 'Just now'
        };
      }
      return item;
    });
    setIntegrations(updated);
    storageService.saveIntegrations(updated);
  };

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
          Preview modules: most reports, orders and inventory still use browser or demo data. Only Live MySQL CRM has server-backed master records.
          Do not treat other dashboard figures or claimed automation as verified live business operations.
        </div>}
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
