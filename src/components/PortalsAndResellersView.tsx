import React, { useState } from 'react';
import {
  Users,
  Building2,
  FileCheck2,
  ShieldCheck,
  Award,
  DollarSign,
  Briefcase,
  CheckCircle2,
  Clock,
  Send,
  ExternalLink,
  Download,
  AlertCircle,
  Plus,
  ArrowUpRight,
  TrendingUp,
  FileText,
  Lock
} from 'lucide-react';
import {
  Quotation,
  SalesOrder,
  WarrantyAsset,
  AMCContract,
  PartnerAccount,
  DealRegistration,
  CommissionRecord,
  CompanyProfile
} from '../types';

interface PortalsAndResellersViewProps {
  quotations: Quotation[];
  salesOrders: SalesOrder[];
  warranties: WarrantyAsset[];
  amcs: AMCContract[];
  partners: PartnerAccount[];
  dealRegistrations: DealRegistration[];
  commissions: CommissionRecord[];
  companyProfile: CompanyProfile;
  onAcceptQuotation: (quoteId: string) => void;
  onRegisterDeal: (deal: DealRegistration) => void;
  onApproveCommission: (commissionId: string) => void;
}

export const PortalsAndResellersView: React.FC<PortalsAndResellersViewProps> = ({
  quotations,
  salesOrders,
  warranties,
  amcs,
  partners,
  dealRegistrations,
  commissions,
  companyProfile,
  onAcceptQuotation,
  onRegisterDeal,
  onApproveCommission
}) => {
  const [activePortalTab, setActivePortalTab] = useState<'customer_portal' | 'partner_portal' | 'commission_engine'>('customer_portal');

  // Customer portal requires a server-authenticated customer principal.
  // This admin/browser view must not pretend to be a different legal customer.

  // Deal registration form
  const [isDealModalOpen, setIsDealModalOpen] = useState(false);
  const [dealForm, setDealForm] = useState({
    partnerId: partners[0]?.id || 'PARTNER-01',
    endCustomerName: '',
    solutionType: 'Enterprise HCI Server Cluster & 25G Switching',
    estimatedValue: '3500000'
  });

  // No server-authorized deal protection/price-lock API is installed.
  // This handler intentionally cannot create, approve, or sign a deal.
  const handleRegisterDealSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setIsDealModalOpen(false);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <div className="p-2 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
                <Users className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-white tracking-tight">
                  Portals, Reseller Network & Commission Engine
                </h2>
                <p className="text-xs text-slate-400">
                  Sections 43–45 are held previews; no authenticated customer portal, legal deal lock or financial payout
                </p>
              </div>
            </div>
          </div>

          {/* Quick Tab Switcher */}
          <div className="flex items-center gap-1.5 p-1 rounded-xl bg-slate-950 border border-slate-800 text-xs">
            <button
              onClick={() => setActivePortalTab('customer_portal')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
                activePortalTab === 'customer_portal'
                  ? 'bg-purple-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Customer Self-Service
            </button>
            <button
              onClick={() => setActivePortalTab('partner_portal')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
                activePortalTab === 'partner_portal'
                  ? 'bg-purple-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Partner & Deal Reg
            </button>
            <button
              onClick={() => setActivePortalTab('commission_engine')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
                activePortalTab === 'commission_engine'
                  ? 'bg-purple-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Commission Engine
            </button>
          </div>
        </div>

        {/* Global Portals Metric Snapshot */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Registered Channel Partners</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-lg font-bold text-white">{partners.length}</span>
              <span className="text-[10px] text-purple-400 font-medium">Pan-India Network</span>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Protected Deals Locked</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-lg font-bold text-cyan-400">{dealRegistrations.length}</span>
              <span className="text-[10px] text-emerald-400 font-medium">60-Day Price Lock</span>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Local Partner Revenue Preview (Unverified)</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-lg font-bold text-emerald-400 font-mono">
                ₹{((partners.reduce((sum, p) => sum + p.totalRevenueGenerated, 0)) / 10000000).toFixed(2)} Cr
              </span>
              <span className="text-[10px] text-slate-400 font-medium">NOT VERIFIED</span>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Commissions Disbursed</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-lg font-bold text-purple-300 font-mono">
                ₹{((partners.reduce((sum, p) => sum + p.commissionPaid, 0)) / 100000).toFixed(2)}L
              </span>
              <span className="text-[10px] text-emerald-400 font-medium">100% Tax Compliant</span>
            </div>
          </div>
        </div>
      </div>

      {/* Authenticated customer principals and tenant-scoped APIs are not yet provisioned. */}
      {activePortalTab === 'customer_portal' && (
        <div className="p-8 bg-slate-900 border border-amber-800/50 rounded-2xl space-y-3 text-sm text-slate-300">
          <h3 className="font-bold text-amber-300">Customer Portal — NOT AVAILABLE / RELEASE HOLD</h3>
          <p>A verified customer login, tenant/object authorization and issued customer-specific records are required before displaying quotations, deliveries, warranties or tax identifiers.</p>
          <p>No customer account is impersonated, no quotation can be e-signed here, and no customer acceptance, order, invoice or shipment is created from this preview.</p>
        </div>
      )}

      {/* Tab 2: Partner & Reseller Portal (Section 44) */}
      {activePortalTab === 'partner_portal' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Briefcase className="w-4 h-4 text-purple-400" />
                <span>Authorized Channel Reseller Network & Tiering</span>
              </h3>
              <p className="text-xs text-slate-400">
                Tier-based wholesale discounts, 60-day opportunity lock, and co-selling support.
              </p>
            </div>

            <button
              disabled
              title="Requires server-authorized deal registration and customer verification"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold shadow-sm transition-all"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Register Protected Deal</span>
            </button>
          </div>

          {/* Partner Accounts Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {partners.map((p) => {
              const tierColors = {
                PLATINUM: 'bg-gradient-to-r from-purple-500/20 to-indigo-500/20 text-purple-300 border-purple-500/40',
                GOLD: 'bg-gradient-to-r from-amber-500/20 to-yellow-500/20 text-amber-300 border-amber-500/40',
                SILVER: 'bg-gradient-to-r from-slate-500/20 to-zinc-500/20 text-slate-300 border-slate-500/40'
              };

              return (
                <div key={p.id} className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-3 text-xs shadow-sm">
                  <div className="flex items-start justify-between">
                    <div>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${tierColors[p.tier]}`}>
                        {p.tier} PARTNER
                      </span>
                      <h4 className="text-sm font-bold text-white mt-1.5">{p.partnerName}</h4>
                      <span className="text-[11px] text-slate-400 block">{p.city} &bull; {p.partnerType.replace(/_/g, ' ')}</span>
                    </div>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Wholesale Margin:</span>
                      <span className="font-semibold text-emerald-400">{p.discountMarginPct}% Guaranteed</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Deals Registered:</span>
                      <span className="font-semibold text-white">{p.registeredDealsCount} Protected</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Lifetime Revenue:</span>
                      <span className="font-mono text-cyan-300">₹{(p.totalRevenueGenerated / 100000).toFixed(1)}L</span>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800 text-[11px] text-slate-400">
                    Contact: <span className="text-slate-300 font-medium">{p.contactPerson}</span> ({p.phone})
                  </div>
                </div>
              );
            })}
          </div>

          {/* Deal Registrations Locked Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-3">
            <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-cyan-400" />
              <span>Active Deal Registrations & Price Protection Locks</span>
            </h4>

            <div className="space-y-2">
              {dealRegistrations.map((deal) => (
                <div
                  key={deal.id}
                  className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs"
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-white">{deal.dealNumber}</span>
                      <span className="px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 text-[10px] font-semibold border border-cyan-500/30">
                        {deal.status.replace(/_/g, ' ')}
                      </span>
                      <span className="text-[10px] text-emerald-400 font-medium">
                        {deal.protectionDaysRemaining} Days Protection Remaining
                      </span>
                    </div>
                    <h5 className="font-semibold text-slate-200 mt-1">
                      {deal.endCustomerName} &bull; <span className="text-slate-400 font-normal">{deal.solutionType}</span>
                    </h5>
                    <span className="text-[10px] text-slate-500 block">Registered by: {deal.partnerName}</span>
                  </div>

                  <div className="text-right">
                    <span className="font-mono text-sm font-bold text-emerald-400">
                      ₹{deal.estimatedValue.toLocaleString('en-IN')}
                    </span>
                    <span className="text-[10px] text-slate-400 block">Protected Opp Value</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Commission Engine (Section 45) */}
      {activePortalTab === 'commission_engine' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <DollarSign className="w-4 h-4 text-emerald-400" />
                <span>Commission Preview — No Automatic Payout</span>
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Section 45 &bull; Browser-only claim records; no posted commissions or authorized bank payout.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {commissions.map((comm) => (
                <div key={comm.id} className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3 text-xs">
                  <div className="flex items-start justify-between">
                    <div>
                      <h4 className="font-semibold text-white">{comm.partnerName}</h4>
                      <span className="text-[10px] text-slate-400 font-mono">Linked Sales Order: {comm.salesOrderNumber}</span>
                    </div>
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
                      comm.payoutStatus === 'PAID'
                        ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                        : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                    }`}>
                      {comm.payoutStatus.replace(/_/g, ' ')}
                    </span>
                  </div>

                  <div className="grid grid-cols-3 gap-2 p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px]">
                    <div>
                      <span className="text-slate-400 block text-[10px]">Order Value</span>
                      <span className="font-mono text-white font-semibold">₹{(comm.dealValue / 100000).toFixed(1)}L</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[10px]">Rate</span>
                      <span className="font-mono text-cyan-300 font-semibold">{comm.commissionRatePct}%</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[10px]">Commission</span>
                      <span className="font-mono text-emerald-400 font-semibold">₹{comm.commissionAmount.toLocaleString('en-IN')}</span>
                    </div>
                  </div>

                  <div className="flex items-center justify-between pt-1">
                    <span className="text-[10px] text-slate-500">
                      {comm.disbursedDate ? `Disbursed on ${comm.disbursedDate}` : 'Pending Bank RTGS Batch'}
                    </span>
                    {comm.payoutStatus !== 'PAID' && (
                      <button
                        disabled
                         title="Commission disbursement requires server-backed finance approval"
                        className="px-3 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs shadow-sm transition-all"
                      >
                        Payout HOLD
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Deal Registration Modal */}
      {isDealModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-md w-full shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-bold text-white">Register Deal for Price Protection</h3>
                <p className="text-xs text-slate-400">Price protection is unavailable without a signed partner agreement and reviewed server workflow</p>
              </div>
              <button
                onClick={() => setIsDealModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 text-lg leading-none"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleRegisterDealSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 mb-1">Select Channel Partner</label>
                <select
                  value={dealForm.partnerId}
                  onChange={(e) => setDealForm({ ...dealForm, partnerId: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white"
                >
                  {partners.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.partnerName} ({p.tier})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-300 mb-1">End-Customer Legal Entity Name</label>
                <input
                  type="text"
                  value={dealForm.endCustomerName}
                  onChange={(e) => setDealForm({ ...dealForm, endCustomerName: e.target.value })}
                  required
                  placeholder="e.g. Tata Motors Engineering Division"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Hardware Scope & Solution</label>
                <input
                  type="text"
                  value={dealForm.solutionType}
                  onChange={(e) => setDealForm({ ...dealForm, solutionType: e.target.value })}
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Estimated Deal Opportunity Value (₹ INR)</label>
                <input
                  type="number"
                  value={dealForm.estimatedValue}
                  onChange={(e) => setDealForm({ ...dealForm, estimatedValue: e.target.value })}
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-emerald-400 font-mono"
                />
              </div>

              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-[11px] text-slate-400 space-y-1">
                <span className="text-cyan-400 font-semibold block">AadiTech Deal Protection Policy:</span>
                <span>&bull; Price protection is not yet authorized or enforceable</span>
                <span>&bull; AI cannot approve prices, contract terms or commercial releases</span>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsDealModalOpen(false)}
                  className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-semibold text-xs shadow-sm"
                >
                  Deal Registration HOLD
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
