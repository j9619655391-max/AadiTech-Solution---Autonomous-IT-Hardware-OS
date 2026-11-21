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
  // Browser-local previews are NOT authoritative accounting, stock, orders,
  // tax or approved supplier/Telegram operations. Never infer invoicing from
  // quotation status, or a margin from estimated/default SKU costs.
  const localLeadPreviewCount = leads.length;
  const localQuotePreviewCount = quotations.length;
  const localCatalogPreviewCount = products.length;

  // Section 77: AI Business Command Center Interactive State
  const [nlQuery, setNlQuery] = useState('');
  const [nlLoading, setNlLoading] = useState(false);
  const [nlResponse, setNlResponse] = useState<{
    query: string;
    text: string;
    suggestedTab?: string;
    suggestedTabLabel?: string;
  } | null>(null);

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
    const query = queryText.trim();
    if (!query || nlLoading) return;
    setNlLoading(true);
    try {
      // The server currently returns 501 for non-authoritative business queries.
      // Do NOT supply browser-local fake financial context, nor manufacture
      // a successful answer when the service rejects or cannot be reached.
      const res = await fetch('/api/ai/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query })
      });
      if (!res.ok) throw new Error('Business command not enabled');
      const data: unknown = await res.json();
      if (!data || typeof data !== 'object' || !('text' in data) ||
          typeof data.text !== 'string' || !data.text.trim())
        throw new Error('No verified business answer available');
      setNlResponse({
        query,
        text: data.text,
        suggestedTab: suggestedTab || 'system',
        suggestedTabLabel: suggestedTabLabel || 'View Status'
      });
    } catch {
      setNlResponse({
        query,
        text: 'NOT VERIFIED: The server has not supplied an authoritative answer. No revenue, margin, inventory, lead, order, GST or dispatch figures have been inferred. Review the relevant server-backed module and its release HOLD.',
        suggestedTab: suggestedTab || 'system',
        suggestedTabLabel: suggestedTabLabel || 'View Status'
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
                Engineering Status &bull; Nonproduction Preview
              </span>
              <span className="text-[10px] bg-indigo-500/20 text-indigo-300 px-2 py-0.5 rounded-full border border-indigo-500/30">
                RELEASE HOLD
              </span>
            </div>
            
            <h2 className="text-xl sm:text-2xl font-extrabold text-white tracking-tight">
              Financial posting, inventory availability and external dispatch NOT VERIFIED
            </h2>
            
            <p className="text-sm text-slate-300 max-w-3xl leading-relaxed">
              Browser-local preview counts are not sales, official invoices, supplier acknowledgments, stock reservations or production authorization. Server-backed approval evidence and genuine independent provider acceptance remain required.
            </p>
          </div>

          <div className="flex items-center gap-3 self-start lg:self-center">
            <button
              id="btn-dash-open-telegram"
              onClick={onOpenTelegram}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-sky-500 hover:bg-sky-400 text-white font-semibold text-xs transition-all shadow-lg shadow-sky-500/25 hover:scale-[1.02]"
            >
              <Send className="w-4 h-4" />
              <span>Telegram Preview (No Send)</span>
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
            <strong className="text-emerald-400 font-bold text-sm">{localLeadPreviewCount} Local Leads</strong>
          </div>
          <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
            <span className="text-[10px] text-slate-400 block">Local Approval Previews</span>
            <strong className="text-amber-400 font-bold text-sm">{pendingApprovals.length} Held Previews</strong>
          </div>
          <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
            <span className="text-[10px] text-slate-400 block">Catalog Previews</span>
            <strong className="text-rose-400 font-bold text-sm">{localCatalogPreviewCount} Local SKUs</strong>
          </div>
          <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
            <span className="text-[10px] text-slate-400 block">Receivables (Authoritative)</span>
            <strong className="text-slate-200 font-bold text-sm">NOT VERIFIED</strong>
          </div>
          <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
            <span className="text-[10px] text-slate-400 block">Quotation Previews</span>
            <strong className="text-sky-300 font-bold text-sm">{localQuotePreviewCount} Local Drafts</strong>
          </div>
          <div className="bg-slate-900/60 p-2 rounded-lg border border-slate-800">
            <span className="text-[10px] text-slate-400 block">Warranty Ledger</span>
            <strong className="text-amber-300 font-bold text-sm">NOT VERIFIED</strong>
          </div>
        </div>
      </div>

      {/* 2. Core Financial & Operating Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Invoiced Revenue (Server Ledger)</span>
            <span className="text-emerald-400 font-semibold flex items-center gap-0.5">
              <ShieldCheck className="w-3.5 h-3.5" /> HELD
            </span>
          </div>
          <div className="text-2xl font-bold text-white tracking-tight">
            NOT VERIFIED
          </div>
          <div className="mt-2 text-xs text-slate-400 flex items-center justify-between">
            <span>GST IRN / collection evidence:</span>
            <span className="text-slate-300 font-medium">NOT VERIFIED</span>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Posted Gross Profit (Server Ledger)</span>
            <span className="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 text-[11px] font-bold">
              NOT VERIFIED
            </span>
          </div>
          <div className="text-2xl font-bold text-emerald-400 tracking-tight">
            NOT VERIFIED
          </div>
          <div className="mt-2 text-xs text-slate-400 flex items-center justify-between">
            <span>Pricing & posting:</span>
            <span className="text-slate-300 font-medium">Independent approval required</span>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Authoritative Inventory Valuation</span>
            <span className="text-blue-400 font-semibold">UNPOSTED</span>
          </div>
          <div className="text-2xl font-bold text-white tracking-tight">
            NOT VERIFIED
          </div>
          <div className="mt-2 text-xs text-slate-400 flex items-center justify-between">
            <span>Stock ownership / costing:</span>
            <span className="text-amber-400 font-medium">NOT VERIFIED</span>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Autonomous Execution Authority</span>
            <span className="text-emerald-400 font-semibold">HELD</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white">DISABLED</span>
            <span className="text-xs text-slate-400">Pending verified authority</span>
            
            
            
          </div>
          <div className="mt-2 text-xs text-slate-400 flex items-center justify-between">
            <span>Independent compliance assessment:</span>
            <span className="text-amber-400 font-medium">NOT VERIFIED</span>
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
                Browser-local queue is a preview; only server-authorized reviews can affect status. External dispatch disabled.
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
              No local preview approval cards. This does not mean verified compliance, approvals, or operating authority.
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
                    <strong className="text-amber-400 text-[10px] uppercase block mb-0.5">Unverified Preview Context:</strong>
                    {appr.reason}
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                    <span className="text-[11px] text-amber-400 flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5 animate-spin" />
                      Local preview timer: {appr.timeoutMinutes} min to reminder
                    </span>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={onOpenTelegram}
                        className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs flex items-center gap-1.5 transition-colors shadow-sm"
                      >
                        <Send className="w-3 h-3" />
                        Open Telegram Preview
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
              <span>Business Workflow Status (Preview)</span>
            </h3>
            <span className="text-[10px] bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded-full font-semibold">
              NOT ACTIVE
            </span>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            No verified production learning loop or automatic price/stock changes. Workflow cards below describe planned modules, not executed business events.
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
              <span className="text-emerald-400 text-xs font-semibold">{localLeadPreviewCount} Local Leads</span>
            </div>

            <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <div className="w-6 h-6 rounded-md bg-indigo-500/20 text-indigo-400 flex items-center justify-center font-bold text-xs">2</div>
                <div>
                  <span className="text-white font-medium block">Dynamic Pricing & Margin Guard</span>
                  <span className="text-[10px] text-slate-400">Cost + Freight + Risk + Margin</span>
                </div>
              </div>
              <span className="text-sky-300 text-xs font-semibold">NOT VERIFIED</span>
            </div>

            <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <div className="w-6 h-6 rounded-md bg-cyan-500/20 text-cyan-400 flex items-center justify-center font-bold text-xs">3</div>
                <div>
                  <span className="text-white font-medium block">Multi-Supplier RFQ Optimization</span>
                  <span className="text-[10px] text-slate-400">Vendor data requires confirmation</span>
                </div>
              </div>
              <span className="text-emerald-400 text-xs font-semibold">NOT MEASURED</span>
            </div>

            <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <div className="w-6 h-6 rounded-md bg-amber-500/20 text-amber-400 flex items-center justify-center font-bold text-xs">4</div>
                <div>
                  <span className="text-white font-medium block">Service, AMC & Warranty Loop</span>
                  <span className="text-[10px] text-slate-400">Serial tracking & proactive renewals</span>
                </div>
              </div>
              <span className="text-amber-300 text-xs font-semibold">NOT VERIFIED</span>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-gradient-to-r from-blue-950/40 to-indigo-950/40 border border-blue-900/40 text-[11px] text-slate-300">
            <strong className="text-blue-300 font-semibold block mb-0.5">Production Action: DISABLED</strong>
            Do not order stock or revise supplier terms without approved PO, independent pricing evidence, available-to-sell/ownership validation and explicit authorized release.
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
                Ask any strategic question in Hindi/English; Server-backed answer only; figures are unavailable until independently verified
              </p>
            </div>
          </div>

          <button
            onClick={onOpenTelegram}
            className="text-xs text-sky-400 hover:text-sky-300 font-medium flex items-center gap-1.5 self-start sm:self-auto"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Open Telegram Preview</span>
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
                Business answer / release HOLD
              </span>
            </div>

            <div className="text-xs text-slate-200 leading-relaxed whitespace-pre-line font-sans">
              {nlResponse.text}
            </div>

            {nlResponse.suggestedTab && (
              <div className="pt-2 flex items-center justify-between border-t border-slate-800/80 text-xs">
                <span className="text-[11px] text-slate-400">
                  Navigation only: review evidence and release HOLD
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
