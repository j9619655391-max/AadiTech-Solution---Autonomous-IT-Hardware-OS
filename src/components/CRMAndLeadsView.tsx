import React, { useState } from 'react';
import {
  Building2,
  Phone,
  Mail,
  MapPin,
  Flame,
  Clock,
  CheckCircle,
  Plus,
  Search,
  Filter,
  ArrowRight,
  ShieldCheck,
  CreditCard,
  Layers,
  Sparkles,
  ExternalLink,
  Landmark,
  Crosshair,
  RefreshCw,
  Send,
  AlertTriangle,
  FileText,
  BadgePercent,
  Check,
  Briefcase,
  Calendar,
  DollarSign
} from 'lucide-react';
import {
  Lead,
  Customer360,
  ChannelSource,
  LeadScore,
  GeMTenderBid,
  OutboundProspectAccount,
  HardwareRefreshAsset,
  DealRegistration
} from '../types';
import { storageService } from '../services/storageService';

interface CRMAndLeadsViewProps {
  leads: Lead[];
  customers: Customer360[];
  gemTenders?: GeMTenderBid[];
  outboundTargets?: OutboundProspectAccount[];
  hardwareRefreshAssets?: HardwareRefreshAsset[];
  dealRegistrations?: DealRegistration[];
  onSelectLeadForBOM: (lead: Lead) => void;
  onAddLead: (lead: Lead) => void;
  onAddCustomer?: (customer: Customer360) => void;
  onConvertTenderToLead?: (tender: GeMTenderBid) => void;
  onLaunchOutboundSequence?: (target: OutboundProspectAccount) => void;
  onTriggerRefreshProposal?: (asset: HardwareRefreshAsset) => void;
}

export const CRMAndLeadsView: React.FC<CRMAndLeadsViewProps> = ({
  leads,
  customers,
  gemTenders: propGemTenders,
  outboundTargets: propOutboundTargets,
  hardwareRefreshAssets: propRefreshAssets,
  dealRegistrations: propDealRegistrations,
  onSelectLeadForBOM,
  onAddLead,
  onAddCustomer,
  onConvertTenderToLead,
  onLaunchOutboundSequence,
  onTriggerRefreshProposal
}) => {
  // Navigation Sub-Views
  const [activeSubView, setActiveSubView] = useState<
    'PIPELINE' | 'GEM_TENDERS' | 'OUTBOUND_HUNTER' | 'HARDWARE_REFRESH' | 'CUSTOMER_360'
  >('PIPELINE');

  const [selectedChannel, setSelectedChannel] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCustomer, setSelectedCustomer] = useState<Customer360 | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showAddCustomerModal, setShowAddCustomerModal] = useState(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  // Local state for interactive action updates
  const [gemTendersList, setGemTendersList] = useState<GeMTenderBid[]>(() =>
    propGemTenders && propGemTenders.length > 0 ? propGemTenders : storageService.loadGeMTenders()
  );
  const [outboundList, setOutboundList] = useState<OutboundProspectAccount[]>(() =>
    propOutboundTargets && propOutboundTargets.length > 0 ? propOutboundTargets : storageService.loadOutboundTargets()
  );
  const [refreshList, setRefreshList] = useState<HardwareRefreshAsset[]>(() =>
    propRefreshAssets && propRefreshAssets.length > 0 ? propRefreshAssets : storageService.loadHardwareRefreshAssets()
  );

  const showNotification = (msg: string) => {
    setActionNotice(msg);
    setTimeout(() => setActionNotice(null), 5000);
  };

  // Convert GeM Tender to Lead and route to BOM Builder
  const handleTenderAction = (tender: GeMTenderBid) => {
    const tenderLead: Lead = {
      id: `LD-GEM-${Math.floor(1000 + Math.random() * 9000)}`,
      name: `Tender Officer (${tender.departmentName.split(' ')[0]})`,
      company: `${tender.departmentName} [GeM]`,
      email: 'gem.biddesk@gov.in',
      phone: '+91 22 2201 5490',
      source: 'GEM_TENDER',
      status: 'QUALIFIED',
      score: 'HOT',
      scoreReason: `GeM Bid #${tender.bidNumber} auto-qualified. Estimated Turnkey Margin: ${tender.turnkeyMarginEstimate}%. Matched with ATS High-REL Catalog.`,
      intentScore: 96,
      requirement: `${tender.title} — Specs: ${tender.specs}`,
      estimatedBudget: tender.estimatedBudget,
      location: 'Western Railway / Mumbai Central',
      gstin: '27AAAGM0289H1Z4',
      createdAt: 'Just now',
      lastInteraction: `Bid Closing: ${tender.bidClosingDate}`,
      tenderNumber: tender.bidNumber,
      bidClosingDate: tender.bidClosingDate
    };

    onAddLead(tenderLead);
    if (onConvertTenderToLead) {
      onConvertTenderToLead(tender);
    }
    showNotification(`🏛️ GeM Bid #${tender.bidNumber} converted to active Lead! Opening Solution BOM Builder...`);
    onSelectLeadForBOM(tenderLead);
  };

  // Launch Outbound Sequence
  const handleLaunchOutbound = (target: OutboundProspectAccount) => {
    const updated = outboundList.map((item) =>
      item.id === target.id ? { ...item, outreachStatus: 'SEQUENCE_ACTIVE' as const } : item
    );
    setGemTendersList(storageService.loadGeMTenders());
    setOutboundList(updated);
    storageService.saveOutboundTargets(updated);

    const outboundLead: Lead = {
      id: `LD-OUT-${Math.floor(1000 + Math.random() * 9000)}`,
      name: `${target.targetContact.name} (${target.targetContact.designation})`,
      company: target.companyName,
      email: target.targetContact.email,
      phone: target.targetContact.phone,
      source: 'OUTBOUND_HUNTER',
      status: 'QUALIFIED',
      score: 'HOT',
      scoreReason: `AI Hunter detected: ${target.expansionTrigger}. Verified Decision Maker.`,
      intentScore: 92,
      requirement: target.recommendedPitch,
      estimatedBudget: target.projectedOpportunityValue,
      location: target.location,
      createdAt: 'Just now',
      lastInteraction: 'Outreach Sequence Dispatched via Email & WhatsApp'
    };

    onAddLead(outboundLead);
    if (onLaunchOutboundSequence) {
      onLaunchOutboundSequence(target);
    }
    showNotification(`🎯 AI Cold Sequence dispatched to ${target.targetContact.name} (${target.companyName})! Lead added to pipeline.`);
  };

  // Trigger Hardware Refresh Proposal
  const handleTriggerRefresh = (asset: HardwareRefreshAsset) => {
    const updated = refreshList.map((item) =>
      item.id === asset.id ? { ...item, refreshStatus: 'PROPOSAL_SENT' as const } : item
    );
    setRefreshList(updated);
    storageService.saveHardwareRefreshAssets(updated);

    const refreshLead: Lead = {
      id: `LD-REF-${Math.floor(1000 + Math.random() * 9000)}`,
      name: `Procurement Lead (${asset.customerName})`,
      company: asset.customerName,
      email: 'procurement@tatamotors.com',
      phone: '+91 98220 99401',
      source: 'HARDWARE_REFRESH',
      status: 'QUALIFIED',
      score: 'HOT',
      scoreReason: `Hardware Refresh Cycle: ${asset.deployedQuantity}x ${asset.deployedModels} reached ${asset.assetAgeMonths} months. Health score: ${asset.healthScore}/100.`,
      intentScore: 94,
      requirement: `Upgrade ${asset.deployedQuantity}x units to ${asset.suggestedReplacementModel} + Trade-in buyback credit.`,
      estimatedBudget: asset.estimatedRefreshBudget,
      location: 'Pune / Pimpri Industrial Belt',
      createdAt: 'Just now',
      lastInteraction: 'Automated 3-Year Lifecycle Refresh Proposal Dispatched',
      refreshAssetDetails: `${asset.deployedQuantity}x ${asset.deployedModels} (${asset.assetAgeMonths} mo)`
    };

    onAddLead(refreshLead);
    if (onTriggerRefreshProposal) {
      onTriggerRefreshProposal(asset);
    }
    showNotification(`🔄 3-Year Lifecycle Upgrade Proposal generated for ${asset.customerName}! Added to pipeline.`);
  };

  // New Customer form state
  const [newCustForm, setNewCustForm] = useState({
    name: '',
    gstin: '',
    creditLimit: 1000000,
    paymentTerms: '30_DAYS_NET',
    state: 'Maharashtra',
    stateCode: '27',
    primaryContact: '',
    phone: '',
    email: '',
    address: ''
  });

  const handleCreateCustomer = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCustForm.name) return;

    const newCust: Customer360 = {
      id: `CUST-${Math.floor(100 + Math.random() * 900)}`,
      name: newCustForm.name,
      gstin: newCustForm.gstin || '27AABCS0000A1Z5',
      contactPerson: newCustForm.primaryContact || 'Procurement Head',
      email: newCustForm.email || `procurement@${newCustForm.name.toLowerCase().replace(/[^a-z0-9]/g, '') || 'company'}.com`,
      phone: newCustForm.phone || '+91 98200 11223',
      city: newCustForm.state === 'Maharashtra' ? 'Mumbai' : 'Bengaluru',
      state: newCustForm.state,
      creditLimit: Number(newCustForm.creditLimit),
      currentOutstanding: 0,
      paymentRiskScore: 'LOW',
      lifetimeValue: 0,
      totalOrders: 0,
      activeWarrantiesCount: 0,
      activeAMCCount: 0,
      lastPurchaseDate: new Date().toISOString().split('T')[0],
      preferredBrands: ['Lenovo', 'Dell', 'HP', 'Cisco']
    };

    if (onAddCustomer) {
      onAddCustomer(newCust);
    }
    setShowAddCustomerModal(false);
    showNotification(`✅ Customer Account ${newCust.name} successfully created and verified!`);
    setNewCustForm({
      name: '',
      gstin: '',
      creditLimit: 1000000,
      paymentTerms: '30_DAYS_NET',
      state: 'Maharashtra',
      stateCode: '27',
      primaryContact: '',
      phone: '',
      email: '',
      address: ''
    });
  };

  // New Lead form state
  const [newLeadForm, setNewLeadForm] = useState({
    name: '',
    company: '',
    email: '',
    phone: '',
    source: 'WHATSAPP' as ChannelSource,
    requirement: '',
    estimatedBudget: 500000,
    location: 'Mumbai'
  });

  const filteredLeads = leads.filter((lead) => {
    const matchesChannel = selectedChannel === 'ALL' || lead.source === selectedChannel;
    const matchesSearch =
      lead.company.toLowerCase().includes(searchQuery.toLowerCase()) ||
      lead.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      lead.requirement.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (lead.tenderNumber && lead.tenderNumber.toLowerCase().includes(searchQuery.toLowerCase()));
    return matchesChannel && matchesSearch;
  });

  const handleCreateLead = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newLeadForm.company || !newLeadForm.name) return;

    const createdLead: Lead = {
      id: `LD-${Math.floor(1000 + Math.random() * 9000)}`,
      name: newLeadForm.name,
      company: newLeadForm.company,
      email: newLeadForm.email || 'procurement@company.in',
      phone: newLeadForm.phone || '+91 98200 00000',
      source: newLeadForm.source,
      status: 'QUALIFIED',
      score: newLeadForm.estimatedBudget > 1000000 ? 'HOT' : 'WARM',
      scoreReason: 'Captured via Inbound/Outbound gateway; verified requirement & budget scale.',
      intentScore: newLeadForm.estimatedBudget > 1000000 ? 91 : 78,
      requirement: newLeadForm.requirement,
      estimatedBudget: Number(newLeadForm.estimatedBudget),
      location: newLeadForm.location,
      createdAt: 'Just now',
      lastInteraction: 'New Lead Ingested'
    };

    onAddLead(createdLead);
    setShowAddModal(false);
    showNotification(`✅ Lead ${createdLead.company} captured and scored!`);
    setNewLeadForm({
      name: '',
      company: '',
      email: '',
      phone: '',
      source: 'WHATSAPP',
      requirement: '',
      estimatedBudget: 500000,
      location: 'Mumbai'
    });
  };

  const getScoreBadge = (score: LeadScore) => {
    switch (score) {
      case 'HOT':
        return (
          <span className="flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-400 border border-rose-500/30">
            <Flame className="w-3 h-3 text-rose-400" /> HOT LEAD
          </span>
        );
      case 'WARM':
        return (
          <span className="flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-400 border border-amber-500/30">
            WARM
          </span>
        );
      case 'COLD':
        return (
          <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700">
            COLD
          </span>
        );
      case 'NURTURE':
        return (
          <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-300 border border-blue-500/30">
            NURTURE
          </span>
        );
    }
  };

  const getSourceBadge = (source: ChannelSource) => {
    switch (source) {
      case 'GEM_TENDER':
        return (
          <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-700/60 flex items-center gap-1">
            <Landmark className="w-2.5 h-2.5" /> GeM Tender
          </span>
        );
      case 'OUTBOUND_HUNTER':
        return (
          <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-700/60 flex items-center gap-1">
            <Crosshair className="w-2.5 h-2.5" /> AI Outbound
          </span>
        );
      case 'HARDWARE_REFRESH':
        return (
          <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-700/60 flex items-center gap-1">
            <RefreshCw className="w-2.5 h-2.5" /> Refresh Loop
          </span>
        );
      case 'WHATSAPP':
        return (
          <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-900/60 text-emerald-300 border border-emerald-700/50">
            WhatsApp
          </span>
        );
      case 'INDIAMART':
        return (
          <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-900/60 text-amber-300 border border-amber-700/50">
            IndiaMART
          </span>
        );
      case 'WEBSITE':
        return (
          <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-blue-900/60 text-blue-300 border border-blue-700/50">
            Website RFQ
          </span>
        );
      case 'EMAIL':
        return (
          <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
            Email RFQ
          </span>
        );
      case 'PARTNER_PORTAL':
        return (
          <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-indigo-900/60 text-indigo-300 border border-indigo-700/50">
            B2B Partner
          </span>
        );
      case 'OEM_PASS':
        return (
          <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-sky-900/60 text-sky-300 border border-sky-700/50">
            OEM Deal Reg
          </span>
        );
      default:
        return (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
            {source}
          </span>
        );
    }
  };

  // Calculate high-level counts
  const tenderCount = gemTendersList.length;
  const outboundCount = outboundList.length;
  const refreshCount = refreshList.length;
  const totalPipelineBudget = leads.reduce((acc, l) => acc + l.estimatedBudget, 0);

  return (
    <div className="space-y-6">
      {/* Action Notification Toast */}
      {actionNotice && (
        <div className="p-3.5 bg-blue-600/90 border border-blue-400 text-white text-xs font-semibold rounded-xl flex items-center justify-between shadow-lg shadow-blue-500/20 animate-fade-in">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-amber-300 shrink-0" />
            <span>{actionNotice}</span>
          </div>
          <button
            onClick={() => setActionNotice(null)}
            className="text-xs text-blue-200 hover:text-white ml-3 underline"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Top Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Building2 className="w-5 h-5 text-blue-400" />
            <span>360° Enterprise Lead Generation & CRM Pipeline</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            6 Core Streams: Digital Inbound, GeM Tenders, AI Outbound B2B Hunter, 3-Yr Hardware Refresh Loop, Reseller Network & OEM Deal Reg.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            id="btn-crm-add-lead"
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-md shadow-blue-500/20 transition-all"
          >
            <Plus className="w-4 h-4" />
            <span>Capture New Lead</span>
          </button>
        </div>
      </div>

      {/* 6-Channel Strategic Matrix Banner */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div
          onClick={() => {
            setActiveSubView('PIPELINE');
            setSelectedChannel('ALL');
          }}
          className={`p-3 rounded-xl border transition-all cursor-pointer ${
            activeSubView === 'PIPELINE' && selectedChannel === 'ALL'
              ? 'bg-blue-950/40 border-blue-500'
              : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-bold text-slate-400">Stream 1</span>
            <Phone className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <p className="text-xs font-bold text-white mt-1">Digital Inbound</p>
          <span className="text-[11px] text-slate-400">WhatsApp / Web / Mart</span>
        </div>

        <div
          onClick={() => setActiveSubView('GEM_TENDERS')}
          className={`p-3 rounded-xl border transition-all cursor-pointer ${
            activeSubView === 'GEM_TENDERS'
              ? 'bg-emerald-950/40 border-emerald-500'
              : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-bold text-emerald-400">Stream 2</span>
            <Landmark className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <p className="text-xs font-bold text-white mt-1">GeM & PSU Bids</p>
          <span className="text-[11px] text-emerald-400 font-semibold">{tenderCount} Active Bids</span>
        </div>

        <div
          onClick={() => setActiveSubView('OUTBOUND_HUNTER')}
          className={`p-3 rounded-xl border transition-all cursor-pointer ${
            activeSubView === 'OUTBOUND_HUNTER'
              ? 'bg-purple-950/40 border-purple-500'
              : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-bold text-purple-400">Stream 3</span>
            <Crosshair className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <p className="text-xs font-bold text-white mt-1">AI B2B Hunter</p>
          <span className="text-[11px] text-purple-400 font-semibold">{outboundCount} Accounts</span>
        </div>

        <div
          onClick={() => setActiveSubView('HARDWARE_REFRESH')}
          className={`p-3 rounded-xl border transition-all cursor-pointer ${
            activeSubView === 'HARDWARE_REFRESH'
              ? 'bg-cyan-950/40 border-cyan-500'
              : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-bold text-cyan-400">Stream 4</span>
            <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <p className="text-xs font-bold text-white mt-1">3-Yr Refresh Loop</p>
          <span className="text-[11px] text-cyan-400 font-semibold">{refreshCount} Fleets Eligible</span>
        </div>

        <div
          onClick={() => {
            setActiveSubView('PIPELINE');
            setSelectedChannel('PARTNER_PORTAL');
          }}
          className={`p-3 rounded-xl border transition-all cursor-pointer ${
            selectedChannel === 'PARTNER_PORTAL'
              ? 'bg-indigo-950/40 border-indigo-500'
              : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-bold text-indigo-400">Stream 5</span>
            <Briefcase className="w-3.5 h-3.5 text-indigo-400" />
          </div>
          <p className="text-xs font-bold text-white mt-1">B2B Resellers</p>
          <span className="text-[11px] text-indigo-300 font-semibold">Sub-Dealers & SIs</span>
        </div>

        <div
          onClick={() => {
            setActiveSubView('CUSTOMER_360');
          }}
          className={`p-3 rounded-xl border transition-all cursor-pointer ${
            activeSubView === 'CUSTOMER_360'
              ? 'bg-amber-950/40 border-amber-500'
              : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-bold text-amber-400">Ledger</span>
            <ShieldCheck className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <p className="text-xs font-bold text-white mt-1">Customer 360</p>
          <span className="text-[11px] text-amber-300 font-semibold">{customers.length} Verified Accounts</span>
        </div>
      </div>

      {/* Sub-View Mode Switcher */}
      <div className="flex items-center gap-1.5 border-b border-slate-800 pb-2 overflow-x-auto no-scrollbar">
        <button
          onClick={() => setActiveSubView('PIPELINE')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-colors whitespace-nowrap ${
            activeSubView === 'PIPELINE'
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Active Leads Pipeline ({leads.length})</span>
        </button>

        <button
          onClick={() => setActiveSubView('GEM_TENDERS')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-colors whitespace-nowrap ${
            activeSubView === 'GEM_TENDERS'
              ? 'bg-emerald-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
          }`}
        >
          <Landmark className="w-3.5 h-3.5 text-emerald-400" />
          <span>GeM & PSU Tenders Radar ({tenderCount})</span>
        </button>

        <button
          onClick={() => setActiveSubView('OUTBOUND_HUNTER')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-colors whitespace-nowrap ${
            activeSubView === 'OUTBOUND_HUNTER'
              ? 'bg-purple-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
          }`}
        >
          <Crosshair className="w-3.5 h-3.5 text-purple-400" />
          <span>AI Outbound B2B Hunter ({outboundCount})</span>
        </button>

        <button
          onClick={() => setActiveSubView('HARDWARE_REFRESH')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-colors whitespace-nowrap ${
            activeSubView === 'HARDWARE_REFRESH'
              ? 'bg-cyan-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
          }`}
        >
          <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
          <span>3-Yr Hardware Refresh Scanner ({refreshCount})</span>
        </button>

        <button
          onClick={() => setActiveSubView('CUSTOMER_360')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-colors whitespace-nowrap ${
            activeSubView === 'CUSTOMER_360'
              ? 'bg-amber-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5 text-amber-400" />
          <span>Customer 360 Ledger ({customers.length})</span>
        </button>
      </div>

      {/* ========================================================================= */}
      {/* SUB-VIEW 1: ACTIVE LEADS PIPELINE */}
      {/* ========================================================================= */}
      {activeSubView === 'PIPELINE' && (
        <div className="space-y-4">
          {/* Channel Filters and Search */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar py-1">
              {[
                { key: 'ALL', label: 'All Channels' },
                { key: 'WHATSAPP', label: 'WhatsApp' },
                { key: 'INDIAMART', label: 'IndiaMART' },
                { key: 'WEBSITE', label: 'Website' },
                { key: 'GEM_TENDER', label: 'GeM Tenders' },
                { key: 'OUTBOUND_HUNTER', label: 'AI Hunter' },
                { key: 'HARDWARE_REFRESH', label: 'Refresh Loop' },
                { key: 'PARTNER_PORTAL', label: 'Partners' },
                { key: 'EMAIL', label: 'Email RFQ' }
              ].map((ch) => (
                <button
                  key={ch.key}
                  onClick={() => setSelectedChannel(ch.key)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
                    selectedChannel === ch.key
                      ? 'bg-blue-600 text-white'
                      : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  {ch.label}
                </button>
              ))}
            </div>

            <div className="relative w-full md:w-72">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search leads, tender #, company..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-xl pl-9 pr-3.5 py-1.5 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>
          </div>

          {/* Lead Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredLeads.map((lead) => (
              <div
                key={lead.id}
                className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-2xl p-5 shadow-sm transition-all space-y-3.5"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="text-sm font-bold text-white tracking-tight">{lead.company}</h3>
                      {getSourceBadge(lead.source)}
                    </div>
                    <div className="text-xs text-slate-300 font-medium mt-0.5 flex items-center gap-2 flex-wrap">
                      <span>{lead.name}</span>
                      <span className="text-slate-600">&bull;</span>
                      <span className="text-slate-400 flex items-center gap-1">
                        <MapPin className="w-3 h-3 text-slate-500" /> {lead.location}
                      </span>
                      {lead.tenderNumber && (
                        <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-1.5 py-0.5 rounded border border-emerald-800">
                          Bid: {lead.tenderNumber}
                        </span>
                      )}
                    </div>
                  </div>

                  {getScoreBadge(lead.score)}
                </div>

                {/* AI Requirement Snapshot */}
                <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800/80 text-xs">
                  <span className="text-[10px] uppercase font-semibold text-slate-400 block mb-1">
                    Requirement & Specifications:
                  </span>
                  <p className="text-slate-200 font-medium leading-relaxed">{lead.requirement}</p>
                </div>

                {/* Score Reason & Intent Bar */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-slate-400">AI Intent & Qualification:</span>
                    <span className="text-emerald-400 font-bold">{lead.intentScore} / 100</span>
                  </div>
                  <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                    <div
                      className="bg-gradient-to-r from-blue-500 to-emerald-400 h-full rounded-full"
                      style={{ width: `${lead.intentScore}%` }}
                    />
                  </div>
                  <p className="text-[11px] text-slate-400 italic">"{lead.scoreReason}"</p>
                </div>

                {/* Footer Metrics and BOM Builder CTA */}
                <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
                  <div>
                    <span className="text-[10px] text-slate-400 block">Est. Opportunity:</span>
                    <strong className="text-white text-xs font-semibold">
                      ₹{lead.estimatedBudget.toLocaleString('en-IN')}
                    </strong>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      id={`btn-lead-bom-${lead.id}`}
                      onClick={() => onSelectLeadForBOM(lead)}
                      className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs flex items-center gap-1.5 transition-colors shadow-sm"
                    >
                      <Layers className="w-3.5 h-3.5" />
                      <span>Build Solution BOM</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {filteredLeads.length === 0 && (
            <div className="p-8 text-center bg-slate-900 border border-slate-800 rounded-2xl space-y-2">
              <p className="text-sm font-semibold text-slate-300">No leads found in this channel filter.</p>
              <p className="text-xs text-slate-500">
                Switch channel tab to "All Channels" or click "Capture Inbound Lead" to register a live prospect.
              </p>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* SUB-VIEW 2: GeM & PUBLIC TENDERS RADAR (Stream 2) */}
      {/* ========================================================================= */}
      {activeSubView === 'GEM_TENDERS' && (
        <div className="space-y-4">
          <div className="bg-emerald-950/30 border border-emerald-800/60 rounded-2xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Landmark className="w-4 h-4 text-emerald-400" />
                <span>GeM (Government e-Marketplace) & Public Sector Hardware Bids</span>
              </h3>
              <p className="text-xs text-emerald-300/80 mt-0.5">
                Targeting Indian Railways, DRDO, Defence, and State Municipal IT contracts. Realizes 22% - 32% high-reliability turnkey margins.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono px-2.5 py-1 rounded bg-emerald-900/60 text-emerald-200 border border-emerald-700">
                Pipeline Value: ₹{(gemTendersList.reduce((a, b) => a + b.estimatedBudget, 0) / 10000000).toFixed(2)} Cr
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {gemTendersList.map((tender) => (
              <div
                key={tender.id}
                className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-3.5 flex flex-col justify-between"
              >
                <div className="space-y-2.5">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold">
                      {tender.bidNumber}
                    </span>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800">
                      Margin Est: {tender.turnkeyMarginEstimate}%
                    </span>
                  </div>

                  <div>
                    <h4 className="text-xs font-bold text-white leading-snug">{tender.title}</h4>
                    <p className="text-[11px] text-slate-400 mt-1 font-medium">{tender.departmentName}</p>
                    <span className="text-[10px] text-slate-500 block">{tender.ministry}</span>
                  </div>

                  <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800/80 text-[11px] text-slate-300 space-y-1">
                    <span className="text-[10px] uppercase font-bold text-slate-400 block">Tender Specifications:</span>
                    <p className="text-slate-300">{tender.specs}</p>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[11px] pt-1 border-t border-slate-800/60">
                    <div>
                      <span className="text-[10px] text-slate-500 block">Estimated Budget:</span>
                      <strong className="text-white">₹{(tender.estimatedBudget / 100000).toFixed(1)} Lakh</strong>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 block">Bid Due Date:</span>
                      <span className="text-amber-400 font-semibold">{tender.bidClosingDate}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 block">EMD Amount:</span>
                      <span className="text-slate-300 font-mono">
                        {tender.emdAmount === 0 ? 'Exempt (MSME)' : `₹${tender.emdAmount.toLocaleString('en-IN')}`}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 block">ATS Product Match:</span>
                      <span className="text-emerald-400 font-semibold">Matched (ATS-DC-48V)</span>
                    </div>
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-800/80">
                  <button
                    onClick={() => handleTenderAction(tender)}
                    className="w-full py-2 px-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs flex items-center justify-center gap-1.5 shadow-md shadow-emerald-500/20 transition-all"
                  >
                    <Layers className="w-3.5 h-3.5" />
                    <span>Bid on GeM & Build BOM</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SUB-VIEW 3: AI OUTBOUND B2B HUNTER (Stream 3) */}
      {/* ========================================================================= */}
      {activeSubView === 'OUTBOUND_HUNTER' && (
        <div className="space-y-4">
          <div className="bg-purple-950/30 border border-purple-800/60 rounded-2xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Crosshair className="w-4 h-4 text-purple-400" />
                <span>AI Outbound B2B Hunter (Account-Based Prospecting)</span>
              </h3>
              <p className="text-xs text-purple-300/80 mt-0.5">
                Monitors corporate expansion signals (MCA filings, Series A/B funding, new office leases in BKC/Pune/Bengaluru). Direct outreach to verified CIOs/IT Directors.
              </p>
            </div>
            <span className="text-xs font-mono px-2.5 py-1 rounded bg-purple-900/60 text-purple-200 border border-purple-700">
              Uncontested High Margin: 18% - 24%
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {outboundList.map((target) => (
              <div
                key={target.id}
                className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-3.5 flex flex-col justify-between"
              >
                <div className="space-y-2.5">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">
                      {target.industry}
                    </span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      target.outreachStatus === 'SEQUENCE_ACTIVE'
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        : 'bg-slate-800 text-slate-400 border border-slate-700'
                    }`}>
                      {target.outreachStatus === 'SEQUENCE_ACTIVE' ? 'Sequence Active' : 'Ready to Hunt'}
                    </span>
                  </div>

                  <div>
                    <h4 className="text-xs font-bold text-white">{target.companyName}</h4>
                    <p className="text-[11px] text-slate-400 mt-0.5 flex items-center gap-1">
                      <MapPin className="w-3 h-3 text-slate-500" /> {target.location}
                    </p>
                  </div>

                  {/* Expansion Signal */}
                  <div className="p-2.5 rounded-xl bg-purple-950/40 border border-purple-800/40 text-[11px] space-y-1">
                    <span className="text-[10px] uppercase font-bold text-purple-400 block">AI Expansion Signal:</span>
                    <p className="text-purple-200">{target.expansionTrigger}</p>
                  </div>

                  {/* Target Contact */}
                  <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-[11px] space-y-1">
                    <span className="text-[10px] uppercase font-bold text-slate-400 block">Verified Decision Maker:</span>
                    <p className="text-white font-semibold">{target.targetContact.name}</p>
                    <span className="text-slate-400 text-[10px] block">{target.targetContact.designation}</span>
                    <span className="text-blue-400 font-mono text-[10px] block">{target.targetContact.email}</span>
                  </div>

                  <div className="flex items-center justify-between text-[11px] pt-1 border-t border-slate-800/60">
                    <div>
                      <span className="text-[10px] text-slate-500 block">Target Budget:</span>
                      <strong className="text-white">₹{(target.projectedOpportunityValue / 100000).toFixed(1)} Lakh</strong>
                    </div>
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-800/80">
                  <button
                    disabled={target.outreachStatus === 'SEQUENCE_ACTIVE'}
                    onClick={() => handleLaunchOutbound(target)}
                    className={`w-full py-2 px-3 rounded-xl font-semibold text-xs flex items-center justify-center gap-1.5 transition-all ${
                      target.outreachStatus === 'SEQUENCE_ACTIVE'
                        ? 'bg-slate-800 text-slate-400 cursor-not-allowed border border-slate-700'
                        : 'bg-purple-600 hover:bg-purple-500 text-white shadow-md shadow-purple-500/20'
                    }`}
                  >
                    <Send className="w-3.5 h-3.5" />
                    <span>{target.outreachStatus === 'SEQUENCE_ACTIVE' ? 'Outreach in Progress' : 'Launch AI Cold Sequence'}</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SUB-VIEW 4: HARDWARE REFRESH & EOL SCANNER (Stream 4) */}
      {/* ========================================================================= */}
      {activeSubView === 'HARDWARE_REFRESH' && (
        <div className="space-y-4">
          <div className="bg-cyan-950/30 border border-cyan-800/60 rounded-2xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <RefreshCw className="w-4 h-4 text-cyan-400" />
                <span>3-Year Hardware Lifecycle & Installed Fleet Refresh Scanner</span>
              </h3>
              <p className="text-xs text-cyan-300/80 mt-0.5">
                Proactively audits customer hardware age (servers, corporate laptops, switch fabrics). Automatically generates trade-in buyback & upgrade proposals.
              </p>
            </div>
            <span className="text-xs font-mono px-2.5 py-1 rounded bg-cyan-900/60 text-cyan-200 border border-cyan-700">
              Highest Win-Rate: &gt;65% Client Loyalty
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {refreshList.map((asset) => (
              <div
                key={asset.id}
                className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-3.5 flex flex-col justify-between"
              >
                <div className="space-y-2.5">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                      {asset.hardwareCategory}
                    </span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      asset.refreshStatus === 'PROPOSAL_SENT'
                        ? 'bg-amber-950 text-amber-400 border border-amber-800'
                        : 'bg-rose-950 text-rose-400 border border-rose-800'
                    }`}>
                      {asset.refreshStatus === 'PROPOSAL_SENT' ? 'Proposal Dispatched' : `Fleet Age: ${asset.assetAgeMonths} Mos`}
                    </span>
                  </div>

                  <div>
                    <h4 className="text-xs font-bold text-white">{asset.customerName}</h4>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      Deployed: {asset.deployedQuantity}x {asset.deployedModels}
                    </p>
                    <span className="text-[10px] text-slate-500 block">Installed On: {asset.originalDeploymentDate}</span>
                  </div>

                  {/* Health Score */}
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-400">Asset Health Score:</span>
                      <span className={`font-bold ${asset.healthScore < 50 ? 'text-rose-400' : 'text-amber-400'}`}>
                        {asset.healthScore}% (Needs EOL Refresh)
                      </span>
                    </div>
                    <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                      <div
                        className="bg-gradient-to-r from-rose-500 to-amber-400 h-full rounded-full"
                        style={{ width: `${asset.healthScore}%` }}
                      />
                    </div>
                  </div>

                  {/* Recommended Upgrade */}
                  <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-[11px] space-y-1">
                    <span className="text-[10px] uppercase font-bold text-slate-400 block">Recommended Replacement:</span>
                    <p className="text-emerald-400 font-semibold">{asset.suggestedReplacementModel}</p>
                    <span className="text-slate-400 text-[10px] block">Includes Trade-in Buyback valuation</span>
                  </div>

                  <div className="flex items-center justify-between text-[11px] pt-1 border-t border-slate-800/60">
                    <div>
                      <span className="text-[10px] text-slate-500 block">Upgrade Budget:</span>
                      <strong className="text-white">₹{(asset.estimatedRefreshBudget / 100000).toFixed(1)} Lakh</strong>
                    </div>
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-800/80">
                  <button
                    disabled={asset.refreshStatus === 'PROPOSAL_SENT'}
                    onClick={() => handleTriggerRefresh(asset)}
                    className={`w-full py-2 px-3 rounded-xl font-semibold text-xs flex items-center justify-center gap-1.5 transition-all ${
                      asset.refreshStatus === 'PROPOSAL_SENT'
                        ? 'bg-slate-800 text-slate-400 cursor-not-allowed border border-slate-700'
                        : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-md shadow-cyan-500/20'
                    }`}
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>{asset.refreshStatus === 'PROPOSAL_SENT' ? 'Upgrade Proposal In Pipeline' : 'Trigger Buyback & Upgrade Proposal'}</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SUB-VIEW 5: CUSTOMER 360 & CREDIT INTELLIGENCE */}
      {/* ========================================================================= */}
      {activeSubView === 'CUSTOMER_360' && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
                <span>Customer 360 Ledger & Credit Intelligence</span>
              </h3>
              <p className="text-xs text-slate-400">
                Unified corporate history, GSTIN, credit limits, active warranties, and AMC contract coverage
              </p>
            </div>
            <button
              onClick={() => setShowAddCustomerModal(true)}
              className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs flex items-center gap-1.5 transition-colors shadow-sm self-start sm:self-auto"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add B2B Customer Account</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {customers.map((cust) => (
              <div
                key={cust.id}
                onClick={() => setSelectedCustomer(cust)}
                className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all space-y-2.5"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <h4 className="text-xs font-bold text-white">{cust.name}</h4>
                    <span className="text-[10px] font-mono text-slate-400">GST: {cust.gstin}</span>
                  </div>
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                      cust.paymentRiskScore === 'LOW'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                    }`}
                  >
                    Risk: {cust.paymentRiskScore}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
                  <div>
                    <span className="text-slate-400 text-[10px] block">Credit Limit:</span>
                    <span className="text-white font-medium">₹{(cust.creditLimit / 100000).toFixed(1)}L</span>
                  </div>
                  <div>
                    <span className="text-slate-400 text-[10px] block">Outstanding:</span>
                    <span
                      className={`font-semibold ${
                        cust.currentOutstanding > 0 ? 'text-amber-400' : 'text-emerald-400'
                      }`}
                    >
                      ₹{(cust.currentOutstanding / 100000).toFixed(2)}L
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 text-[10px] block">Active Warranties:</span>
                    <span className="text-slate-300 font-medium">{cust.activeWarrantiesCount} Serials</span>
                  </div>
                  <div>
                    <span className="text-slate-400 text-[10px] block">Lifetime Value:</span>
                    <span className="text-emerald-400 font-bold">₹{(cust.lifetimeValue / 100000).toFixed(1)}L</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* CAPTURE LEAD MODAL */}
      {/* ========================================================================= */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Plus className="w-5 h-5 text-blue-400" />
                <span>Capture New B2B Lead</span>
              </h3>
              <button onClick={() => setShowAddModal(false)} className="text-slate-400 hover:text-white">
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateLead} className="space-y-3.5 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Company / Department Name *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Tata Motors Supply Hub"
                    value={newLeadForm.company}
                    onChange={(e) => setNewLeadForm({ ...newLeadForm, company: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Contact Person *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Rajesh Patil (IT Lead)"
                    value={newLeadForm.name}
                    onChange={(e) => setNewLeadForm({ ...newLeadForm, name: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Phone / WhatsApp *</label>
                  <input
                    type="text"
                    required
                    placeholder="+91 98200 XXXXX"
                    value={newLeadForm.phone}
                    onChange={(e) => setNewLeadForm({ ...newLeadForm, phone: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Lead Source Stream *</label>
                  <select
                    value={newLeadForm.source}
                    onChange={(e) => setNewLeadForm({ ...newLeadForm, source: e.target.value as ChannelSource })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                  >
                    <option value="WHATSAPP">WhatsApp Business Bot</option>
                    <option value="INDIAMART">IndiaMART B2B Portal</option>
                    <option value="WEBSITE">Website RFQ Form</option>
                    <option value="GEM_TENDER">GeM / PSU Government Tender</option>
                    <option value="OUTBOUND_HUNTER">AI Outbound B2B Hunter</option>
                    <option value="HARDWARE_REFRESH">3-Year Hardware Refresh Loop</option>
                    <option value="PARTNER_PORTAL">B2B Reseller & SI Portal</option>
                    <option value="OEM_PASS">OEM Deal Reg (Lenovo/Cisco/Dell)</option>
                    <option value="EMAIL">Direct Email RFQ</option>
                    <option value="JUSTDIAL">Justdial Directory</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Email Address</label>
                  <input
                    type="email"
                    placeholder="procurement@company.com"
                    value={newLeadForm.email}
                    onChange={(e) => setNewLeadForm({ ...newLeadForm, email: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Location / City</label>
                  <input
                    type="text"
                    placeholder="Mumbai / Pune / Bhiwandi"
                    value={newLeadForm.location}
                    onChange={(e) => setNewLeadForm({ ...newLeadForm, location: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                  />
                </div>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Estimated Budget (INR) *</label>
                <input
                  type="number"
                  required
                  min={10000}
                  value={newLeadForm.estimatedBudget}
                  onChange={(e) => setNewLeadForm({ ...newLeadForm, estimatedBudget: Number(e.target.value) })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-mono"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Hardware Requirement & Specs *</label>
                <textarea
                  rows={3}
                  required
                  placeholder="e.g. 50x Lenovo ThinkPad T14 + 3x Cisco PoE switches + APC 3kVA UPS..."
                  value={newLeadForm.requirement}
                  onChange={(e) => setNewLeadForm({ ...newLeadForm, requirement: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                />
              </div>

              <div className="pt-3 flex justify-end gap-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold shadow-md"
                >
                  Ingest & Score Lead
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* ADD B2B CUSTOMER ACCOUNT MODAL */}
      {/* ========================================================================= */}
      {showAddCustomerModal && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Building2 className="w-5 h-5 text-emerald-400" />
                <span>Onboard Real B2B Customer Account</span>
              </h3>
              <button onClick={() => setShowAddCustomerModal(false)} className="text-slate-400 hover:text-white">
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateCustomer} className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">Company / Customer Legal Name *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Reliance Retail IT Division"
                  value={newCustForm.name}
                  onChange={(e) => setNewCustForm({ ...newCustForm, name: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">GSTIN Number (15 Characters) *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. 27AABCS1234F1Z9"
                    maxLength={15}
                    value={newCustForm.gstin}
                    onChange={(e) => {
                      const val = e.target.value.toUpperCase();
                      const code = val.slice(0, 2);
                      setNewCustForm({
                        ...newCustForm,
                        gstin: val,
                        stateCode: code || newCustForm.stateCode
                      });
                    }}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-mono uppercase"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Operating State</label>
                  <select
                    value={newCustForm.state}
                    onChange={(e) => {
                      const st = e.target.value;
                      const codeMap: Record<string, string> = {
                        Maharashtra: '27',
                        Karnataka: '29',
                        Delhi: '07',
                        Gujarat: '24',
                        'Tamil Nadu': '33',
                        Telangana: '36'
                      };
                      setNewCustForm({
                        ...newCustForm,
                        state: st,
                        stateCode: codeMap[st] || '27'
                      });
                    }}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                  >
                    <option value="Maharashtra">Maharashtra (27)</option>
                    <option value="Karnataka">Karnataka (29)</option>
                    <option value="Delhi">Delhi (07)</option>
                    <option value="Gujarat">Gujarat (24)</option>
                    <option value="Tamil Nadu">Tamil Nadu (33)</option>
                    <option value="Telangana">Telangana (36)</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Authorized Credit Limit (INR)</label>
                  <input
                    type="number"
                    value={newCustForm.creditLimit}
                    onChange={(e) => setNewCustForm({ ...newCustForm, creditLimit: Number(e.target.value) })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-mono"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Payment Terms</label>
                  <select
                    value={newCustForm.paymentTerms}
                    onChange={(e) => setNewCustForm({ ...newCustForm, paymentTerms: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                  >
                    <option value="100_ADVANCE">100% Advance (RTGS/NEFT)</option>
                    <option value="30_PERCENT_ADVANCE">30% Advance + Bal vs Delivery</option>
                    <option value="15_DAYS_NET">15 Days Net</option>
                    <option value="30_DAYS_NET">30 Days Net</option>
                    <option value="45_DAYS_NET">45 Days Net (Govt/MNC)</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Contact Person Name</label>
                  <input
                    type="text"
                    placeholder="e.g. Amit Kulkarni"
                    value={newCustForm.primaryContact}
                    onChange={(e) => setNewCustForm({ ...newCustForm, primaryContact: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Contact Phone</label>
                  <input
                    type="tel"
                    placeholder="+91 98200 55443"
                    value={newCustForm.phone}
                    onChange={(e) => setNewCustForm({ ...newCustForm, phone: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                  />
                </div>
              </div>

              <div className="pt-3 flex justify-end gap-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddCustomerModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold shadow-md flex items-center gap-1.5"
                >
                  <CheckCircle className="w-4 h-4" />
                  <span>Save Account to Ledger</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
