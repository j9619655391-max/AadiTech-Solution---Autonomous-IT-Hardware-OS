import React, { useState } from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Clock,
  Send,
  AlertTriangle,
  History,
  Sliders,
  Filter,
  FileCheck,
  Check
} from 'lucide-react';
import { TelegramApprovalCard, AuditEvent } from '../types';

interface ApprovalEngineViewProps {
  pendingApprovals: TelegramApprovalCard[];
  auditLogs: AuditEvent[];
  onApproveCard: (cardId: string) => void;
  onRejectCard: (cardId: string) => void;
  onOpenTelegram: () => void;
}

export const ApprovalEngineView: React.FC<ApprovalEngineViewProps> = ({
  pendingApprovals,
  auditLogs,
  onApproveCard,
  onRejectCard,
  onOpenTelegram
}) => {
  const [filterType, setFilterType] = useState<string>('ALL');

  const rulesMatrix = [
    { rule: 'Quotation Margin ≥ 15.0%', action: 'Auto-Approve (Autonomous)', tier: 'AI Engine', delay: 'Instant (0s)' },
    { rule: 'Quotation Margin 10.0% – 14.99%', action: 'Manager Tier Review', tier: 'Sales Manager', delay: '15 Mins' },
    { rule: 'Quotation Margin < 10.0%', action: 'Owner Telegram Authorization Required', tier: 'Business Owner', delay: 'Immediate Push' },
    { rule: 'Order Value > ₹10,00,000', action: 'Owner Telegram Authorization Required', tier: 'Business Owner', delay: 'Immediate Push' },
    { rule: 'Customer Credit Override', action: 'Finance & Risk Verification Required', tier: 'Finance Head', delay: '30 Mins' },
    { rule: 'New Supplier Onboarding', action: 'Procurement Manager + Compliance Check', tier: 'Procurement', delay: '2 Hours' }
  ];

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-amber-400" />
            <span>Autonomous Approval Engine & Matrix (Sections 23, 25 & 26)</span>
          </h2>
          <p className="text-xs text-slate-400">
            Rules-driven human-in-the-loop authorization gates with automatic Telegram escalation
          </p>
        </div>

        <button
          onClick={onOpenTelegram}
          className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-sky-500 hover:bg-sky-400 text-white text-xs font-semibold shadow-md shadow-sky-500/20 transition-all self-start sm:self-auto"
        >
          <Send className="w-3.5 h-3.5" />
          <span>Launch Telegram Command Center</span>
        </button>
      </div>

      {/* Configured Approval Matrix Rules */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <Sliders className="w-4 h-4 text-blue-400" />
          <span>Active Enterprise Approval Boundaries</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {rulesMatrix.map((item, idx) => (
            <div
              key={idx}
              className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 space-y-1.5 text-xs"
            >
              <div className="flex items-center justify-between">
                <span className="font-bold text-white">{item.rule}</span>
                <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-slate-800 text-slate-300">
                  {item.delay}
                </span>
              </div>
              <p className="text-slate-400 text-[11px]">{item.action}</p>
              <div className="pt-1 flex items-center justify-between text-[10px]">
                <span className="text-slate-500">Tier: <strong className="text-slate-300">{item.tier}</strong></span>
                <span className="text-emerald-400 flex items-center gap-0.5">
                  <Check className="w-3 h-3" /> Active
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Active Pending Approvals Queue */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Clock className="w-4 h-4 text-amber-400" />
            <span>Active Exception Approvals ({pendingApprovals.length})</span>
          </h3>
          <span className="text-xs text-slate-400">Syncs directly with Owner Telegram Bot</span>
        </div>

        {pendingApprovals.length === 0 ? (
          <div className="p-8 text-center bg-slate-950/60 rounded-xl border border-slate-800 text-slate-400 text-xs">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
            Zero pending approval blocks. The autonomous engine is auto-clearing orders within the 15% margin rule.
          </div>
        ) : (
          <div className="space-y-3">
            {pendingApprovals.map((appr) => (
              <div
                key={appr.id}
                className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-slate-700 transition-all space-y-3"
              >
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
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

                  <div className="text-right">
                    <span className="text-sm font-mono font-bold text-white block">
                      ₹{appr.amount.toLocaleString('en-IN')}
                    </span>
                    <span className="text-[11px] font-semibold text-amber-400">
                      Margin: {appr.marginPct}% (Min: 15%)
                    </span>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300">
                  <strong className="text-amber-400 text-[10px] uppercase block mb-1">
                    AI Context & Exception Justification:
                  </strong>
                  {appr.reason}
                </div>

                <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                  <div className="text-[11px] text-amber-400 flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 animate-spin" />
                    <span>Auto-escalation timer: {appr.timeoutMinutes} mins remaining before second reminder</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => onApproveCard(appr.id)}
                      className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs flex items-center gap-1 transition-colors shadow-sm"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Approve Exception</span>
                    </button>
                    <button
                      onClick={() => onRejectCard(appr.id)}
                      className="px-3 py-1.5 rounded-lg bg-rose-600/80 hover:bg-rose-600 text-white font-semibold text-xs flex items-center gap-1 transition-colors"
                    >
                      <XCircle className="w-3.5 h-3.5" />
                      <span>Reject</span>
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Section 53 Immutable Audit Trail */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <History className="w-4 h-4 text-blue-400" />
              <span>Immutable AI Audit Trail (Section 53)</span>
            </h3>
            <p className="text-xs text-slate-400">
              Audit log recording: Who, What, When, Why, AI Agent, Rule Triggered, and Final Resolution
            </p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 font-semibold border-b border-slate-800">
              <tr>
                <th className="p-3">Timestamp</th>
                <th className="p-3">AI Agent</th>
                <th className="p-3">Action & Entity</th>
                <th className="p-3">Rule Checked</th>
                <th className="p-3">Details</th>
                <th className="p-3 text-center">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {auditLogs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="p-3 font-mono text-slate-400 whitespace-nowrap text-[11px]">
                    {log.timestamp}
                  </td>
                  <td className="p-3 font-medium text-white whitespace-nowrap">
                    {log.agent}
                  </td>
                  <td className="p-3">
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-semibold block w-fit mb-0.5">
                      {log.action}
                    </span>
                    <span className="text-slate-400 text-[11px]">{log.entityId}</span>
                  </td>
                  <td className="p-3 text-slate-400 text-[11px] max-w-xs truncate">
                    {log.rulesChecked}
                  </td>
                  <td className="p-3 text-slate-300 text-[11px] max-w-sm">
                    {log.details}
                  </td>
                  <td className="p-3 text-center">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      log.status === 'AUTO_EXECUTED'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : log.status === 'TELEGRAM_APPROVED'
                        ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30'
                        : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    }`}>
                      {log.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
