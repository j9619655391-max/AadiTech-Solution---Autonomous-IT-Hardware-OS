import React, { useState } from 'react';
import {
  CreditCard,
  ShieldCheck,
  Clock,
  Wrench,
  AlertTriangle,
  CheckCircle2,
  FileCheck,
  RefreshCw,
  TrendingUp,
  Receipt,
  UserCheck,
  Sparkles
} from 'lucide-react';
import { WarrantyAsset, AMCContract, ServiceTicket, Customer360, CompanyProfile } from '../types';

interface FinanceAndServiceViewProps {
  warranties: WarrantyAsset[];
  amcs: AMCContract[];
  tickets: ServiceTicket[];
  customers: Customer360[];
  companyProfile?: CompanyProfile;
  onTriggerRenewal: (contractId: string) => void;
  onAssignTechnician: (ticketId: string, techName: string) => void;
}

export const FinanceAndServiceView: React.FC<FinanceAndServiceViewProps> = ({
  warranties,
  amcs,
  tickets,
  customers,
  companyProfile,
  onTriggerRenewal,
  onAssignTechnician
}) => {
  const [activeTab, setActiveTab] = useState<'FINANCE_GST' | 'WARRANTY_AMC' | 'SERVICE_TICKETS'>('FINANCE_GST');

  // Credit Risk Simulator state (Section 29)
  const [selectedCustomerId, setSelectedCustomerId] = useState(customers[0]?.id || 'CUST-001');
  const [simulatedOrderValue, setSimulatedOrderValue] = useState<number>(650000);

  const activeCustomer = customers.find(c => c.id === selectedCustomerId) || customers[0];

  // Credit Risk calculation formula: (Order Value + Outstanding) vs Credit Limit
  const totalExposure = simulatedOrderValue + (activeCustomer?.currentOutstanding || 0);
  const creditLimit = activeCustomer?.creditLimit || 1000000;
  const isCreditExceeded = totalExposure > creditLimit;
  const creditUsagePct = ((totalExposure / creditLimit) * 100).toFixed(1);

  let creditDecision = 'APPROVE';
  if (isCreditExceeded) {
    creditDecision = 'REQUIRE OWNER APPROVAL & ADVANCE PAYMENT';
  } else if (Number(creditUsagePct) > 85) {
    creditDecision = 'REQUIRE 50% ADVANCE';
  }

  return (
    <div className="space-y-6">
      {/* Top Action Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <CreditCard className="w-5 h-5 text-emerald-400" />
            <span>Finance, GST, Warranty & AMC Operations (Sections 28–38)</span>
          </h2>
          <p className="text-xs text-slate-400">
            India GST compliance, autonomous credit exposure engine, serial warranty alerts, and SLA service ticketing
          </p>
        </div>

        <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
          <button
            onClick={() => setActiveTab('FINANCE_GST')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'FINANCE_GST' ? 'bg-emerald-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            Finance & GST
          </button>
          <button
            onClick={() => setActiveTab('WARRANTY_AMC')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'WARRANTY_AMC' ? 'bg-emerald-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            Warranty & AMC Lifecycle
          </button>
          <button
            onClick={() => setActiveTab('SERVICE_TICKETS')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'SERVICE_TICKETS' ? 'bg-emerald-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            Service Desk & SLAs
          </button>
        </div>
      </div>

      {/* TAB 1: FINANCE & INDIA GST COMPLIANCE */}
      {activeTab === 'FINANCE_GST' && (
        <div className="space-y-6">
          {/* Quick Metrics */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <span className="text-xs text-slate-400 block mb-1">Total Receivables Outstanding</span>
              <div className="text-2xl font-bold text-white font-mono">₹28,40,000</div>
              <span className="text-[11px] text-amber-400 block mt-1">₹4.20L Overdue &gt;30 Days</span>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <span className="text-xs text-slate-400 block mb-1">GST Input Tax Credit (ITC) Available</span>
              <div className="text-2xl font-bold text-emerald-400 font-mono">₹6,85,200</div>
              <span className="text-[11px] text-slate-400 block mt-1">GSTR-2B Verified vs Redington/Ingram</span>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <span className="text-xs text-slate-400 block mb-1">Cash Flow Projection (30 Days)</span>
              <div className="text-2xl font-bold text-sky-400 font-mono">+₹14.20 Lakh</div>
              <span className="text-[11px] text-emerald-400 block mt-1">Sufficient operating liquidity</span>
            </div>
          </div>

          {/* Credit Risk Engine (Section 29) */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-amber-400" />
                  <span>Autonomous Credit Risk & Limit Engine (Section 29)</span>
                </h3>
                <p className="text-xs text-slate-400">
                  Calculates total credit exposure before releasing warehouse pick lists
                </p>
              </div>
              <span className="text-[10px] font-mono bg-amber-500/20 text-amber-300 px-2 py-0.5 rounded border border-amber-500/30">
                Rule #29
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="space-y-3">
                <div>
                  <label className="text-slate-400 block mb-1">Select Customer Account:</label>
                  <select
                    value={selectedCustomerId}
                    onChange={(e) => setSelectedCustomerId(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                  >
                    {customers.map(c => (
                      <option key={c.id} value={c.id}>
                        {c.name} (Credit Cap: ₹{(c.creditLimit / 100000).toFixed(1)}L)
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="text-slate-400 block mb-1">Simulated New Order Value (INR):</label>
                  <input
                    type="number"
                    value={simulatedOrderValue}
                    onChange={(e) => setSimulatedOrderValue(Number(e.target.value))}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-mono"
                  />
                </div>

                <div className="p-3 rounded-lg bg-slate-950 text-[11px] space-y-1 text-slate-400">
                  <div><strong>Credit Cap:</strong> ₹{creditLimit.toLocaleString('en-IN')}</div>
                  <div><strong>Current Outstanding:</strong> ₹{activeCustomer?.currentOutstanding.toLocaleString('en-IN')}</div>
                  <div><strong>Total Exposure after Order:</strong> ₹{totalExposure.toLocaleString('en-IN')} ({creditUsagePct}%)</div>
                </div>
              </div>

              {/* AI Risk Decision Output */}
              <div className={`p-4 rounded-xl border space-y-3 flex flex-col justify-between ${
                isCreditExceeded
                  ? 'bg-rose-950/30 border-rose-800/60 text-rose-200'
                  : 'bg-emerald-950/30 border-emerald-800/60 text-emerald-200'
              }`}>
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold uppercase tracking-wider text-[11px]">
                      AI Credit Assessment Decision:
                    </span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      isCreditExceeded ? 'bg-rose-500/20 text-rose-300' : 'bg-emerald-500/20 text-emerald-300'
                    }`}>
                      {isCreditExceeded ? 'EXCEPTION' : 'AUTO-RELEASE'}
                    </span>
                  </div>
                  <div className="text-sm font-bold text-white mt-1">
                    {creditDecision}
                  </div>
                  <p className="text-slate-300 text-xs mt-2 leading-relaxed">
                    {isCreditExceeded
                      ? `Proposed order increases total exposure to ₹${totalExposure.toLocaleString('en-IN')}, breaching authorized credit line of ₹${creditLimit.toLocaleString('en-IN')}. Autonomous hold active. Dispatched to Telegram Owner Hub for exception review.`
                      : `Total exposure of ₹${totalExposure.toLocaleString('en-IN')} is within the ${creditUsagePct}% safety threshold. Sales order released autonomously for warehouse allocation.`}
                  </p>
                </div>

                <div className="text-[10px] text-slate-400 pt-2 border-t border-slate-800">
                  Rule Check: Section 29 Multi-factor credit validation &bull; Reconciled with {companyProfile?.bankName || 'HDFC Bank'} Current A/c ({companyProfile?.accountNumber || '50200088921102'})
                </div>
              </div>
            </div>
          </div>

          {/* AadiTech Solution Legal, Tax & Banking Master */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Receipt className="w-4 h-4 text-emerald-400" />
                  <span>{companyProfile?.name || 'AadiTech Solution'} &bull; Master Tax & Bank Settlement</span>
                </h3>
                <p className="text-xs text-slate-400">
                  Official India GST e-Invoice, RTGS/NEFT settlement rails, and merchant bank credentials
                </p>
              </div>
              <span className="text-[10px] font-mono bg-emerald-500/20 text-emerald-300 px-2.5 py-0.5 rounded border border-emerald-500/30">
                Active Master
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs">
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-400 block text-[10px]">Company Legal Entity</span>
                <span className="font-semibold text-white text-xs block mt-0.5">{companyProfile?.name || 'AadiTech Solution'}</span>
                <span className="text-[10px] text-sky-400 block mt-0.5 font-mono">{companyProfile?.website || 'https://aaditechs.in'}</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-400 block text-[10px]">GSTIN & PAN</span>
                <span className="font-semibold text-white text-xs block mt-0.5 font-mono">{companyProfile?.gstin || '27AADCS8129F1Z3'}</span>
                <span className="text-[10px] text-slate-400 block mt-0.5 font-mono">PAN: {companyProfile?.pan || 'AADCS8129F'}</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-400 block text-[10px]">Bank & Account Number</span>
                <span className="font-semibold text-white text-xs block mt-0.5">{companyProfile?.bankName || 'HDFC Bank Ltd'}</span>
                <span className="text-[10px] text-slate-400 block mt-0.5 font-mono">A/C: {companyProfile?.accountNumber || '50200088921102'}</span>
              </div>

              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-400 block text-[10px]">IFSC & Autonomous Guardrail</span>
                <span className="font-semibold text-white text-xs block mt-0.5 font-mono">{companyProfile?.ifscCode || 'HDFC0000128'}</span>
                <span className="text-[10px] text-emerald-400 block mt-0.5">Floor Margin: {companyProfile?.defaultMarginThreshold || 15}%</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: WARRANTY & AMC LIFECYCLE (Sections 36 & 37) */}
      {activeTab === 'WARRANTY_AMC' && (
        <div className="space-y-6">
          {/* Active Serial Warranties Alert */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Clock className="w-4 h-4 text-amber-400" />
                  <span>Proactive Warranty Sunset Alerts (Section 36)</span>
                </h3>
                <p className="text-xs text-slate-400">
                  Automated countdown tracking (90, 60, 30, 15, 7 days) triggering AMC upsell campaigns
                </p>
              </div>
              <span className="text-xs bg-amber-500/20 text-amber-300 px-2.5 py-0.5 rounded-full font-semibold">
                3 Fleet Expirations Imminent
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {warranties.map((w) => (
                <div key={w.id} className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5">
                  <div className="flex items-start justify-between">
                    <div>
                      <span className="text-xs font-bold text-white block">{w.productName}</span>
                      <span className="text-[10px] font-mono text-slate-400">SN: {w.serialNumber}</span>
                    </div>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                      w.daysRemaining <= 15
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30 animate-pulse'
                        : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    }`}>
                      {w.daysRemaining} Days Left
                    </span>
                  </div>

                  <div className="text-[11px] text-slate-400">
                    <div>Customer: <strong className="text-slate-200">{w.customerName}</strong></div>
                    <div>Expiry: <strong className="text-slate-300">{w.warrantyExpiryDate}</strong></div>
                    <div>Active AMC: <strong className={w.hasActiveAMC ? 'text-emerald-400' : 'text-rose-400'}>
                      {w.hasActiveAMC ? 'Covered' : 'None (High Upsell Opportunity)'}
                    </strong></div>
                  </div>

                  {!w.hasActiveAMC && (
                    <button className="w-full mt-2 py-1.5 rounded-lg bg-indigo-600/30 hover:bg-indigo-600/50 text-indigo-300 font-medium text-xs border border-indigo-500/30 transition-colors">
                      Trigger AMC Upsell Pitch
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* AMC Contracts Tracker (Section 37) */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <FileCheck className="w-4 h-4 text-emerald-400" />
                  <span>Annual Maintenance Contracts (AMC) & Renewal Engine (Section 37)</span>
                </h3>
                <p className="text-xs text-slate-400">
                  Scheduled preventive visits & automatic renewal quotation dispatch
                </p>
              </div>
            </div>

            <div className="space-y-3">
              {amcs.map((contract) => (
                <div key={contract.id} className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-white">{contract.contractNumber}</span>
                      <span className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.2 rounded font-mono">
                        {contract.assetCount} Assets Covered
                      </span>
                    </div>
                    <span className="text-slate-400 text-xs block mt-0.5">
                      Client: <strong className="text-slate-200">{contract.customerName}</strong> &bull; Period: {contract.startDate} to {contract.endDate}
                    </span>
                    <span className="text-[11px] text-emerald-400 block mt-1">
                      SLA: {contract.slaHours}-Hour Onsite &bull; Visits: {contract.completedVisits} / {contract.scheduledVisitsPerYear} Completed
                    </span>
                  </div>

                  <div className="flex items-center gap-4">
                    <div className="text-right">
                      <span className="text-[10px] text-slate-400 block">Annual Contract Fee:</span>
                      <span className="text-sm font-bold font-mono text-white">₹{contract.annualFee.toLocaleString('en-IN')}</span>
                    </div>

                    {contract.status === 'UP_FOR_RENEWAL' ? (
                      <button
                        onClick={() => onTriggerRenewal(contract.id)}
                        className="px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs shadow-md shadow-emerald-600/20 whitespace-nowrap"
                      >
                        Auto-Dispatch Renewal Quote
                      </button>
                    ) : (
                      <span className="px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-300 font-bold text-xs">
                        Active & In SLA
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: SERVICE TICKETING & SLAs (Section 38) */}
      {activeTab === 'SERVICE_TICKETS' && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Wrench className="w-4 h-4 text-blue-400" />
                <span>Field Service Helpdesk & Technician Dispatch (Section 38)</span>
              </h3>
              <p className="text-xs text-slate-400">
                High-priority SLA countdown timers & on-site diagnostic assignments
              </p>
            </div>
          </div>

          <div className="space-y-3">
            {tickets.map((t) => (
              <div key={t.id} className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3 text-xs">
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-white">{t.ticketNumber}</span>
                      <span className={`text-[10px] font-bold px-2 py-0.2 rounded uppercase ${
                        t.priority === 'CRITICAL'
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30 animate-pulse'
                          : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                      }`}>
                        {t.priority} Priority
                      </span>
                    </div>
                    <span className="text-slate-400 block mt-0.5">
                      Client: <strong className="text-slate-200">{t.customerName}</strong> &bull; Asset Serial: <strong className="font-mono text-slate-300">{t.serialNumber}</strong>
                    </span>
                  </div>

                  <div className="flex items-center gap-1.5 text-amber-400 font-mono font-semibold">
                    <Clock className="w-3.5 h-3.5" />
                    <span>SLA Buffer: {t.slaTimeRemainingHours} Hours Remaining</span>
                  </div>
                </div>

                <p className="text-slate-300 bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                  <strong>Reported Issue:</strong> {t.issueDescription}
                </p>

                <div className="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-slate-800/80">
                  <span className="text-slate-400">
                    Assigned Technician: <strong className="text-white">{t.technician}</strong>
                  </span>

                  {t.status === 'OPEN' && (
                    <button
                      onClick={() => onAssignTechnician(t.id, 'Sachin Kamble (Senior Field Engineer)')}
                      className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-colors"
                    >
                      Assign Field Engineer (Sachin K.)
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
