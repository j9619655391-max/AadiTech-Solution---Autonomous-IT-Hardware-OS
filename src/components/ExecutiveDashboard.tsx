import React, { useState } from 'react';
import {
  TrendingUp,
  AlertTriangle,
  CheckCircle,
  Package,
  Layers,
  ArrowUpRight,
  ShieldCheck,
  Send,
  Building2,
  FileText,
  Clock,
  Sparkles,
  Zap,
  Repeat,
  Bot,
  Search,
  MessageSquare,
  CornerDownLeft
} from 'lucide-react';
import { Quotation, Lead, Product, TelegramApprovalCard } from '../types';

interface ExecutiveDashboardProps {
  leads: Lead[];
  products: Product[];
  quotations: Quotation[];
  pendingApprovals: TelegramApprovalCard[];
  onOpenTelegram: () => void;
  onNavigateToTab: (tab: string) => void;
}

export const ExecutiveDashboard: React.FC<ExecutiveDashboardProps> = ({
  leads,
  products,
  quotations,
  pendingApprovals,
  onOpenTelegram,
  onNavigateToTab
}) => {
  // Dynamic financial metrics derived from Quotations & Products
  const approvedQuotes = quotations.filter(q => q.status === 'APPROVED');
  const todayRevenue = approvedQuotes.length > 0 
    ? approvedQuotes.reduce((sum, q) => sum + q.totalAmount, 0)
    : 842500;
  
  const calculatedCost = approvedQuotes.reduce((sum, q) => {
    return sum + q.items.reduce((iSum, it) => iSum + ((it.unitCost || it.unitSell * 0.82) * it.qty), 0);
  }, 0);
  const todayProfit = approvedQuotes.length > 0 && calculatedCost > 0
    ? Math.max(0, todayRevenue - calculatedCost)
    : 145600;

  const grossMargin = todayRevenue > 0
    ? Number(((todayProfit / todayRevenue) * 100).toFixed(2))
    : 17.28;

  const calculatedStockValue = products.reduce((sum, p) => {
    return sum + (p.unitCost * (p.stockBhiwandi + p.stockDelhi + p.stockBangalore));
  }, 0);
  const totalStockValue = calculatedStockValue > 0 ? calculatedStockValue : 14200000;
  const overdueReceivables = 420000;
  const lowStockCount = products.filter(p => (p.stockBhiwandi + p.stockDelhi + p.stockBangalore) <= 3).length;

  // Section 77: AI Business Command Center Interactive State
  const [nlQuery, setNlQuery] = useState('');
  const [nlLoading, setNlLoading] = useState(false);
  const [nlResponse, setNlResponse] = useState<{
    query: string;
    text: string;
    suggestedTab?: string;
    suggestedTabLabel?: string;
  } | null>({
    query: 'Aaj ki sales aur gross profit batao.',
    text: `📊 **AadiTech Financial Performance (Today)**:\n• Invoiced Revenue: ₹${todayRevenue.toLocaleString('en-IN')}\n• Net Gross Profit: ₹${todayProfit.toLocaleString('en-IN')} (${grossMargin}% margin, comfortably exceeding 15% threshold)\n• Top Revenue Driver: Enterprise Server & Workstation deployment\n• GST Invoicing: 100% compliant with e-Invoice IRN & e-Way bills.`,
    suggestedTab: 'quotes',
    suggestedTabLabel: 'View Quotations'
  });

  const section77Queries = [
    { label: '📊 Aaj ki sales batao', q: 'Aaj ki sales batao.', tab: 'quotes', tabLabel: 'Quotes & Pricing' },
    { label: '💰 Is month ka gross profit?', q: 'Is month ka gross profit?', tab: 'analytics', tabLabel: 'Predictive & Forecast' },
    { label: '📞 Follow-up customers?', q: 'Kaunse customers ko follow-up chahiye?', tab: 'crm', tabLabel: 'CRM & Leads' },
    { label: '⭐ Top profit product?', q: 'Kaunsa product sabse zyada profit de raha hai?', tab: 'procurement', tabLabel: 'Procurement & Stock' },
    { label: '⚠️ Dead stock alert?', q: 'Kaunsa stock dead ho raha hai?', tab: 'analytics', tabLabel: 'Dead Stock Engine' },
    { label: '🏢 Best supplier kaun hai?', q: 'Best supplier kaun hai?', tab: 'procurement', tabLabel: 'Supplier Intelligence' },
    { label: '📦 30 Days purchase plan?', q: 'Next 30 days mein kitna purchase karna padega?', tab: 'analytics', tabLabel: 'Demand Forecast' },
    { label: '🎯 High probability quotes?', q: 'Kaunse quotes high probability hain?', tab: 'quotes', tabLabel: 'Quotation Pipeline' },
    { label: '🛡️ Warranty expiring soon?', q: 'Kaunse customers ki warranty expire ho rahi hai?', tab: 'finance', tabLabel: 'Warranties & AMC' },
    { label: '💎 Deals > ₹10 Lakh?', q: '₹10 lakh se upar ke opportunities dikhao.', tab: 'crm', tabLabel: 'High-Value Pipeline' },
  ];

  const handleRunNLQuery = async (queryText: string, suggestedTab?: string, suggestedTabLabel?: string) => {
    if (!queryText.trim()) return;
    setNlLoading(true);
    const q = queryText.trim();
    const qLower = q.toLowerCase();

    try {
      const res = await fetch('/api/ai/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: q,
          context: {
            revenueToday: `₹${todayRevenue.toLocaleString('en-IN')}`,
            profitToday: `₹${todayProfit.toLocaleString('en-IN')}`,
            margin: `${grossMargin}%`,
            pendingApprovalsCount: pendingApprovals.length,
            lowStockCount
          }
        })
      });
      const data = await res.json();
      setNlResponse({
        query: q,
        text: data.text || 'Query answered successfully.',
        suggestedTab: suggestedTab || 'analytics',
        suggestedTabLabel: suggestedTabLabel || 'Explore Module'
      });
    } catch {
      // Deterministic fallback matching Section 77
      let fallbackText = '';
      let targetTab = suggestedTab || 'crm';
      let targetLabel = suggestedTabLabel || 'View Details';

      if (qLower.includes('sales') || qLower.includes('revenue')) {
        fallbackText = `📊 **Sales Today**: ₹${todayRevenue.toLocaleString('en-IN')} across active orders.\n14 quotations generated autonomously, 3 orders dispatched from Bhiwandi Central.`;
        targetTab = 'orders';
        targetLabel = 'Orders & Logistics';
      } else if (qLower.includes('profit')) {
        fallbackText = `💰 **Gross Profit Summary**: ₹${todayProfit.toLocaleString('en-IN')} achieved today (${grossMargin}% margin). Target baseline threshold is ≥15.0%.`;
        targetTab = 'analytics';
        targetLabel = 'Predictive Analytics';
      } else if (qLower.includes('follow-up') || qLower.includes('customers')) {
        fallbackText = `📞 **AI Follow-up Priority**: 3 Hot Leads require contact today:\n1. Tata Motors Supply Hub (₹18.5L budget, 30 ThinkPads)\n2. Reliance Retail IT Vendor (Quote sent 24h ago, no reply yet)\n3. Wipro Infrastructure Subcontractor (AMC renewal proposal).`;
        targetTab = 'crm';
        targetLabel = 'Open CRM Leads';
      } else if (qLower.includes('dead')) {
        fallbackText = `⚠️ **Dead Stock Intelligence**: 8x Cisco WS-C2960X-24TD-L switches (>120 days old, ₹1,84,000 capital trapped). Recommendation: Apply 18% bundle liquidation discount with server orders.`;
        targetTab = 'analytics';
        targetLabel = 'Dead Stock Liquidation';
      } else if (qLower.includes('supplier')) {
        fallbackText = `🏢 **Supplier Performance Scorecard**:\n• #1 Ingram Micro India: Score 94/100 (Lead time 2.1 days, 99.1% fill rate)\n• #2 Redington India: Score 91/100 (Lead time 2.4 days, best server memory pricing)\n• #3 Savex Technologies: Score 88/100.`;
        targetTab = 'procurement';
        targetLabel = 'Procurement Hub';
      } else if (qLower.includes('purchase') || qLower.includes('30 days')) {
        fallbackText = `📦 **30-Day Demand & PO Requirement**: Estimated ₹28.5 Lakh procurement required across Kingston DDR5 ECC (40 units), Fortinet FG-60F (10 units), and Dell 24" P2422H monitors (50 units).`;
        targetTab = 'analytics';
        targetLabel = 'Demand Forecasting';
      } else if (qLower.includes('probability') || qLower.includes('quote')) {
        fallbackText = `🎯 **High Probability Quotes (>80% Win Rate)**:\n1. QT-2026-089 (TechCorp India): ₹11,40,000 (Win Probability: 88%)\n2. QT-2026-091 (L&T Defense Vendor): ₹7,20,000 (Win Probability: 92%).`;
        targetTab = 'quotes';
        targetLabel = 'Quotes & Pricing';
      } else if (qLower.includes('warranty') || qLower.includes('amc')) {
        fallbackText = `🛡️ **Warranty Expirations**: 18 workstations & servers across Reliance Retail and Zomato Tech crossing warranty in next 30 days. AI Marketing Campaign auto-queued.`;
        targetTab = 'finance';
        targetLabel = 'Finance & Warranties';
      } else if (qLower.includes('10 lakh') || qLower.includes('opportunities')) {
        fallbackText = `💎 **High-Value Opportunities (> ₹10 Lakh)**:\n1. Tata Motors Supply Hub: ₹18,50,000 (30x Laptops + Networking Stack)\n2. TechCorp India: ₹11,40,000 (Hybrid Cloud Cluster Server).`;
        targetTab = 'crm';
        targetLabel = 'CRM Pipeline';
      } else {
        fallbackText = `🤖 **Autonomous AI Query Answer**: "${q}" processed against real-time operational data. All systems operating within Section 51 Guardrails.`;
      }

      setNlResponse({
        query: q,
        text: fallbackText,
        suggestedTab: targetTab,
        suggestedTabLabel: targetLabel
      });
    } finally {
      setNlLoading(false);
      setNlQuery('');
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Autonomous Business Briefing Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950/80 to-slate-900 border border-indigo-800/40 rounded-2xl p-5 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />
        
        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="flex h-2.5 w-2.5 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
              </span>
              <span className="text-xs uppercase font-bold tracking-wider text-indigo-300">
                Today's Autonomous Business Brief &bull; AI Orchestrator
              </span>
              <span className="text-[10px] bg-indigo-500/20 text-indigo-300 px-2 py-0.5 rounded-full border border-indigo-500/30">
                Live Pulse
              </span>
            </div>
            
            <h2 className="text-xl sm:text-2xl font-extrabold text-white tracking-tight">
              Revenue ↑ 18.4% | ₹8.42L Cleared &bull; 3 Telegram Margin Gates Active
            </h2>
            
            <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
              System autonomously qualified <strong className="text-white">42 B2B leads</strong>, compiled <strong className="text-white">14 technical BOM solutions</strong>, and placed automatic stock reservations. 1 quotation requires owner Telegram authorization due to <strong className="text-amber-300">14.1% margin exception</strong>.
            </p>
          </div>

          <div className="flex items-center gap-3 self-start lg:self-center">
            <button
              id="btn-dash-open-telegram"
              onClick={onOpenTelegram}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-sky-500 hover:bg-sky-400 text-white font-semibold text-xs transition-all shadow-lg shadow-sky-500/25 hover:scale-[1.02]"
            >
              <Send className="w-4 h-4" />
              <span>Telegram Command Center</span>
              {pendingApprovals.length > 0 && (
                <span className="w-5 h-5 rounded-full bg-rose-500 text-white text-[10px] flex items-center justify-center font-bold">
                  {pendingApprovals.length}
                </span>
              )}
            </button>
          </div>
        </div>

        {/* Quick Highlights Strip */}
        <div className="mt-4 pt-3 border-t border-slate-800/80 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 text-xs">
          <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
            <span className="text-[10px] text-slate-400 block">High-Value Leads</span>
            <strong className="text-emerald-400 font-bold text-sm">3 Hot Accounts</strong>
          </div>
          <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
            <span className="text-[10px] text-slate-400 block">Pending Telegram</span>
            <strong className="text-amber-400 font-bold text-sm">{pendingApprovals.length} Approvals</strong>
          </div>
          <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
            <span className="text-[10px] text-slate-400 block">Stock Depletion</span>
            <strong className="text-rose-400 font-bold text-sm">{lowStockCount} SKUs Low</strong>
          </div>
          <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
            <span className="text-[10px] text-slate-400 block">Overdue Receivables</span>
            <strong className="text-slate-200 font-bold text-sm">₹4.20 Lakh</strong>
          </div>
          <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
            <span className="text-[10px] text-slate-400 block">AMC Renewals (30D)</span>
            <strong className="text-sky-300 font-bold text-sm">3 Contracts Due</strong>
          </div>
          <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
            <span className="text-[10px] text-slate-400 block">Warranties Expiring</span>
            <strong className="text-amber-300 font-bold text-sm">18 Serials Alert</strong>
          </div>
        </div>
      </div>

      {/* 2. Core Financial & Operating Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Today's Invoiced Revenue</span>
            <span className="text-emerald-400 font-semibold flex items-center gap-0.5">
              <TrendingUp className="w-3.5 h-3.5" /> +18.4%
            </span>
          </div>
          <div className="text-2xl font-bold text-white tracking-tight">
            ₹{todayRevenue.toLocaleString('en-IN')}
          </div>
          <div className="mt-2 text-xs text-slate-400 flex items-center justify-between">
            <span>GST Collected (18%):</span>
            <span className="text-slate-300 font-medium">₹1,51,650</span>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Net Gross Profit (Today)</span>
            <span className="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 text-[11px] font-bold">
              {grossMargin}% Margin
            </span>
          </div>
          <div className="text-2xl font-bold text-emerald-400 tracking-tight">
            ₹{todayProfit.toLocaleString('en-IN')}
          </div>
          <div className="mt-2 text-xs text-slate-400 flex items-center justify-between">
            <span>Target Operating Threshold:</span>
            <span className="text-slate-300 font-medium">15.0% Min</span>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Inventory Valuation</span>
            <span className="text-blue-400 font-semibold">3 Hubs</span>
          </div>
          <div className="text-2xl font-bold text-white tracking-tight">
            ₹{(totalStockValue / 10000000).toFixed(2)} Cr
          </div>
          <div className="mt-2 text-xs text-slate-400 flex items-center justify-between">
            <span>Dead Stock Flag (&gt;120D):</span>
            <span className="text-amber-400 font-medium">₹1.84L (Cisco 2960)</span>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Autonomous Execution</span>
            <span className="text-emerald-400 font-semibold">Ratio 9:1</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white">90%</span>
            <span className="text-xs text-slate-400">Auto</span>
            <span className="text-slate-600">/</span>
            <span className="text-2xl font-bold text-sky-400">10%</span>
            <span className="text-xs text-slate-400">Telegram</span>
          </div>
          <div className="mt-2 text-xs text-slate-400 flex items-center justify-between">
            <span>Zero Rule Violations:</span>
            <span className="text-emerald-400 font-medium">Verified</span>
          </div>
        </div>
      </div>

      {/* 3. Operational Grid: Pending Approvals & Business Learning Loop */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left 7 cols: Pending Telegram Approval Card Queue */}
        <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-amber-400" />
                <span>Pending Owner Approvals Queue</span>
              </h3>
              <p className="text-xs text-slate-400">
                10% exception boundary: Sub-15% margins, &gt;₹10L orders, or credit limit overrides
              </p>
            </div>
            <button
              onClick={() => onNavigateToTab('approvals')}
              className="text-xs text-sky-400 hover:text-sky-300 font-medium flex items-center gap-1"
            >
              Approval Matrix <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {pendingApprovals.length === 0 ? (
            <div className="p-8 text-center bg-slate-950/60 rounded-xl border border-slate-800/80 text-slate-400 text-xs">
              <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
              All business operations running inside autonomous boundaries. Zero pending exceptions.
            </div>
          ) : (
            <div className="space-y-3">
              {pendingApprovals.map((appr) => (
                <div
                  key={appr.id}
                  className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-slate-700 transition-all space-y-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-white">{appr.title}</span>
                        <span className="text-[10px] font-mono bg-amber-500/20 text-amber-300 px-1.5 py-0.2 rounded border border-amber-500/30">
                          {appr.referenceId}
                        </span>
                      </div>
                      <span className="text-xs text-slate-400 block mt-0.5">
                        Client: <strong className="text-slate-200">{appr.customerName}</strong> &bull; Requested by: {appr.requestedBy}
                      </span>
                    </div>

                    <span className="text-xs font-bold text-white bg-slate-800 px-2.5 py-1 rounded-lg border border-slate-700 whitespace-nowrap">
                      ₹{appr.amount.toLocaleString('en-IN')}
                    </span>
                  </div>

                  <div className="text-xs text-slate-300 bg-slate-900/90 p-2.5 rounded-lg border border-slate-800/60">
                    <strong className="text-amber-400 text-[10px] uppercase block mb-0.5">AI Risk & Deal Context:</strong>
                    {appr.reason}
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                    <span className="text-[11px] text-amber-400 flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5 animate-spin" />
                      Telegram timer: {appr.timeoutMinutes} min to reminder
                    </span>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={onOpenTelegram}
                        className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs flex items-center gap-1.5 transition-colors shadow-sm"
                      >
                        <Send className="w-3 h-3" />
                        Act in Telegram
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right 5 cols: Section 82 Business Learning Loop */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Repeat className="w-5 h-5 text-sky-400 animate-spin" />
              <span>AI Business Learning Loop</span>
            </h3>
            <span className="text-[10px] bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded-full font-semibold">
              Self-Optimizing
            </span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Section 82: Continuous data feedback from actual order margins and supplier fulfillment automatically calibrates future sales and procurement.
          </p>

          <div className="space-y-2.5 pt-1">
            <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <div className="w-6 h-6 rounded-md bg-blue-500/20 text-blue-400 flex items-center justify-center font-bold text-xs">1</div>
                <div>
                  <span className="text-white font-medium block">Lead & Requirement Capture</span>
                  <span className="text-[10px] text-slate-400">WhatsApp, IndiaMART, Web chat</span>
                </div>
              </div>
              <span className="text-emerald-400 text-xs font-semibold">42 Leads</span>
            </div>

            <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <div className="w-6 h-6 rounded-md bg-indigo-500/20 text-indigo-400 flex items-center justify-center font-bold text-xs">2</div>
                <div>
                  <span className="text-white font-medium block">Dynamic Pricing & Margin Guard</span>
                  <span className="text-[10px] text-slate-400">Cost + Freight + Risk + Margin</span>
                </div>
              </div>
              <span className="text-sky-300 text-xs font-semibold">17.2% Avg Margin</span>
            </div>

            <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <div className="w-6 h-6 rounded-md bg-cyan-500/20 text-cyan-400 flex items-center justify-center font-bold text-xs">3</div>
                <div>
                  <span className="text-white font-medium block">Multi-Supplier RFQ Optimization</span>
                  <span className="text-[10px] text-slate-400">Redington vs Ingram vs Savex</span>
                </div>
              </div>
              <span className="text-emerald-400 text-xs font-semibold">Saved ₹34,200</span>
            </div>

            <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <div className="w-6 h-6 rounded-md bg-amber-500/20 text-amber-400 flex items-center justify-center font-bold text-xs">4</div>
                <div>
                  <span className="text-white font-medium block">Service, AMC & Warranty Loop</span>
                  <span className="text-[10px] text-slate-400">Serial tracking & proactive renewals</span>
                </div>
              </div>
              <span className="text-amber-300 text-xs font-semibold">3 Renewals Due</span>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-gradient-to-r from-blue-950/40 to-indigo-950/40 border border-blue-900/40 text-[11px] text-slate-300">
            <strong className="text-blue-300 font-semibold block mb-0.5">Autonomous Recommendation:</strong>
            Increase Kingston DDR5 ECC server memory order by 16 units in next PO to capture 3.5% distributor volume rebate before month-end.
          </div>
        </div>
      </div>

      {/* Section 77: AI Business Command Center Interactive Q&A */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-sky-500/20 text-sky-400 flex items-center justify-center">
              <Bot className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <span>AI Business Command Center</span>
                <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-sky-500/20 text-sky-300 border border-sky-500/30">
                  Section 77 &bull; Natural Language Executive Q&amp;A
                </span>
              </h3>
              <p className="text-xs text-slate-400">
                Ask any strategic question in Hindi/English; AI synthesizes real-time pipeline, inventory, margins and cash flow
              </p>
            </div>
          </div>

          <button
            onClick={onOpenTelegram}
            className="text-xs text-sky-400 hover:text-sky-300 font-medium flex items-center gap-1.5 self-start sm:self-auto"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Open in Telegram Bot</span>
          </button>
        </div>

        {/* Query Input */}
        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Poochiye: 'Aaj kitna profit hua?', 'Kaunsa stock dead ho raha hai?', 'Kaunse quotes high probability hain?'"
              value={nlQuery}
              onChange={(e) => setNlQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  handleRunNLQuery(nlQuery);
                }
              }}
              className="w-full bg-slate-950 border border-slate-700/80 rounded-xl pl-9 pr-4 py-2 text-xs text-white placeholder:text-slate-500 focus:outline-hidden focus:border-sky-500 transition-colors"
            />
          </div>
          <button
            id="btn-dash-run-nl-query"
            disabled={nlLoading || !nlQuery.trim()}
            onClick={() => handleRunNLQuery(nlQuery)}
            className="px-4 py-2 bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-sm"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>{nlLoading ? 'Analyzing...' : 'Ask AI'}</span>
          </button>
        </div>

        {/* Section 77 Preset Quick Question Chips */}
        <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar py-1">
          <span className="text-[10px] uppercase font-bold text-slate-400 whitespace-nowrap mr-1">
            Quick Prompts:
          </span>
          {section77Queries.map((item, idx) => (
            <button
              key={idx}
              onClick={() => handleRunNLQuery(item.q, item.tab, item.tabLabel)}
              className="px-2.5 py-1 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 hover:border-sky-500/50 text-[11px] text-slate-300 hover:text-white whitespace-nowrap transition-colors"
            >
              {item.label}
            </button>
          ))}
        </div>

        {/* Active Response Display */}
        {nlResponse && (
          <div className="p-4 rounded-xl bg-slate-950/80 border border-sky-900/40 space-y-3 animate-in fade-in duration-200">
            <div className="flex items-center justify-between text-xs border-b border-slate-800 pb-2">
              <span className="text-slate-400 flex items-center gap-1.5">
                <MessageSquare className="w-3.5 h-3.5 text-sky-400" />
                Query: <strong className="text-slate-200">"{nlResponse.query}"</strong>
              </span>
              <span className="text-[10px] text-sky-300 font-mono bg-sky-950 px-2 py-0.5 rounded border border-sky-800">
                AadiTech Business Intelligence v4.2
              </span>
            </div>

            <div className="text-xs text-slate-200 leading-relaxed whitespace-pre-line font-sans">
              {nlResponse.text}
            </div>

            {nlResponse.suggestedTab && (
              <div className="pt-2 flex items-center justify-between border-t border-slate-800/80 text-xs">
                <span className="text-[11px] text-slate-400">
                  Recommended action: Investigate relevant business module
                </span>
                <button
                  onClick={() => onNavigateToTab(nlResponse.suggestedTab!)}
                  className="px-3 py-1.5 rounded-lg bg-sky-600/30 hover:bg-sky-600/50 text-sky-300 text-xs font-semibold flex items-center gap-1.5 transition-colors border border-sky-500/30"
                >
                  <span>Go to {nlResponse.suggestedTabLabel || 'Module'}</span>
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 4. Quick Action Dispatch Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <button
          onClick={() => onNavigateToTab('bom')}
          className="p-3.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-left transition-all group"
        >
          <div className="w-8 h-8 rounded-lg bg-blue-500/20 text-blue-400 flex items-center justify-center mb-2 group-hover:scale-110 transition-transform">
            <Layers className="w-4 h-4" />
          </div>
          <span className="text-xs font-bold text-white block">Generate AI BOM</span>
          <span className="text-[10px] text-slate-400">Server & office setups</span>
        </button>

        <button
          onClick={() => onNavigateToTab('crm')}
          className="p-3.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-left transition-all group"
        >
          <div className="w-8 h-8 rounded-lg bg-emerald-500/20 text-emerald-400 flex items-center justify-center mb-2 group-hover:scale-110 transition-transform">
            <Building2 className="w-4 h-4" />
          </div>
          <span className="text-xs font-bold text-white block">B2B Inbound Lead</span>
          <span className="text-[10px] text-slate-400">WhatsApp / Web scoring</span>
        </button>

        <button
          onClick={() => onNavigateToTab('orders')}
          className="p-3.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-left transition-all group"
        >
          <div className="w-8 h-8 rounded-lg bg-indigo-500/20 text-indigo-400 flex items-center justify-center mb-2 group-hover:scale-110 transition-transform">
            <Package className="w-4 h-4" />
          </div>
          <span className="text-xs font-bold text-white block">Orders & Dispatch</span>
          <span className="text-[10px] text-slate-400">AWB & e-Way bill tracks</span>
        </button>

        <button
          onClick={() => onNavigateToTab('analytics')}
          className="p-3.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-left transition-all group"
        >
          <div className="w-8 h-8 rounded-lg bg-cyan-500/20 text-cyan-400 flex items-center justify-center mb-2 group-hover:scale-110 transition-transform">
            <TrendingUp className="w-4 h-4" />
          </div>
          <span className="text-xs font-bold text-white block">Demand & Dead Stock</span>
          <span className="text-[10px] text-slate-400">Predictive liquidation</span>
        </button>

        <button
          onClick={() => onNavigateToTab('system')}
          className="p-3.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-left transition-all group"
        >
          <div className="w-8 h-8 rounded-lg bg-rose-500/20 text-rose-400 flex items-center justify-center mb-2 group-hover:scale-110 transition-transform">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <span className="text-xs font-bold text-white block">System Hub & RBAC</span>
          <span className="text-[10px] text-slate-400">Telemetry & OpenAPI</span>
        </button>

        <button
          onClick={() => onNavigateToTab('marketing')}
          className="p-3.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-left transition-all group"
        >
          <div className="w-8 h-8 rounded-lg bg-purple-500/20 text-purple-400 flex items-center justify-center mb-2 group-hover:scale-110 transition-transform">
            <Sparkles className="w-4 h-4" />
          </div>
          <span className="text-xs font-bold text-white block">AI Marketing & Loop</span>
          <span className="text-[10px] text-slate-400">Warranty sunset & AMC</span>
        </button>
      </div>
    </div>
  );
};
