import React, { useState } from 'react';
import {
  RotateCcw,
  Sparkles,
  ShieldAlert,
  CheckCircle2,
  Download,
  AlertTriangle,
  Layers,
  Database,
  X,
  Server,
  Trash2
} from 'lucide-react';
import { storageService } from '../services/storageService';

interface ResetAndEnvironmentModalProps {
  isOpen: boolean;
  onClose: () => void;
  onDataReload: () => void;
}

export const ResetAndEnvironmentModal: React.FC<ResetAndEnvironmentModalProps> = ({
  isOpen,
  onClose,
  onDataReload
}) => {
  const [currentMode, setCurrentMode] = useState<'TESTING' | 'PRODUCTION'>(() => storageService.getEnvironmentMode());
  const [actionStatus, setActionStatus] = useState<string | null>(null);
  const [confirmWipeModal, setConfirmWipeModal] = useState(false);
  const [confirmDemoModal,setConfirmDemoModal]=useState(false);

  if (!isOpen) return null;

  const handleExportBackup = () => {
    const json = storageService.exportFullBackup();
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aaditech_backup_pre_reset_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setActionStatus('Backup JSON downloaded successfully!');
    setTimeout(() => setActionStatus(null), 3500);
  };

  const handleExecuteWipeToProduction = () => {
    setConfirmWipeModal(false);
    setActionStatus('BLOCKED: Browser-local reset cannot authorize production. Existing records were preserved.');
  };

  const handleExecuteLoadTesting = () => {
    setConfirmDemoModal(false);
    try {
      storageService.loadTestingDemoState('OVERWRITE_BROWSER_DATA');
      setCurrentMode('TESTING');
      setActionStatus('Demo fixtures loaded into browser storage only — not production data.');
      setTimeout(()=>{onDataReload();onClose();},1500);
    }catch(e){
      setActionStatus(e instanceof Error?e.message:'Demo fixture import blocked');
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-5 my-8">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="w-10 h-10 rounded-xl bg-rose-600/20 border border-rose-500/30 flex items-center justify-center text-rose-400">
              <RotateCcw className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <span>Browser Demo Data &amp; Safety Controls</span>
                <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded-full border ${
                  currentMode === 'PRODUCTION'
                    ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                    : 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                }`}>
                  {currentMode === 'PRODUCTION' ? '🟢 Live Production' : '🧪 Testing Dataset'}
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                Browser-local fixture management only. No button here enables real production.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Status notification */}
        {actionStatus && (
          <div className="p-3 rounded-xl bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-xs flex items-center gap-2 animate-in fade-in">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{actionStatus}</span>
          </div>
        )}

        {/* Quick Backup Banner */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs">
          <div className="flex items-center gap-2.5">
            <Database className="w-4 h-4 text-blue-400 shrink-0" />
            <span className="text-slate-300">
              Always recommend downloading a backup before resetting data.
            </span>
          </div>
          <button
            onClick={handleExportBackup}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium transition-colors whitespace-nowrap self-start sm:self-auto"
          >
            <Download className="w-3.5 h-3.5 text-blue-400" />
            <span>Export Current JSON Backup</span>
          </button>
        </div>

        {/* Option 1: Clean Production Fresh Slate (Reset) */}
        <div className="p-5 rounded-2xl bg-gradient-to-br from-slate-950 to-rose-950/20 border border-rose-900/40 space-y-3">
          <div className="flex items-start justify-between gap-3">
            <div className="space-y-1">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Trash2 className="w-4 h-4 text-rose-400" />
                <span>Production Reset Blocked (requires authorized staging and backup)</span>
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Disabled: browser storage is not the authoritative MySQL database. Destructive reset cannot prove live deployment readiness.
              </p>
            </div>
            <span className="text-[10px] font-semibold text-rose-400 uppercase tracking-wider bg-rose-950 px-2 py-0.5 rounded border border-rose-800/60 whitespace-nowrap">
              RELEASE HOLD
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-[11px] text-slate-300">
            <div className="p-2 rounded-lg bg-slate-900/80 border border-slate-800">
              <strong className="text-rose-300 block">0 Leads</strong>
              Ready for real inbound
            </div>
            <div className="p-2 rounded-lg bg-slate-900/80 border border-slate-800">
              <strong className="text-rose-300 block">0 Quotations</strong>
              Fresh quote sequence
            </div>
            <div className="p-2 rounded-lg bg-slate-900/80 border border-slate-800">
              <strong className="text-rose-300 block">0 Orders</strong>
              Empty sales order ledger
            </div>
            <div className="p-2 rounded-lg bg-slate-900/80 border border-slate-800">
              <strong className="text-emerald-300 block">Unverified Catalog</strong>
              Verify supplier source
            </div>
          </div>

          <div className="pt-2 flex items-center justify-between">
            <span className="text-[11px] text-slate-400">
              No destructive wipe is performed; preserve existing browser-local records.
            </span>
            <button
              id="btn-confirm-wipe-fresh"
              disabled
              title="Requires independently verified staging and authorized backup"
              onClick={() => setConfirmWipeModal(true)}
              className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold shadow-md shadow-rose-600/20 flex items-center gap-1.5 transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Production Reset Disabled</span>
            </button>
          </div>
        </div>

        {/* Option 2: Load Testing & Verification Dataset */}
        <div className="p-5 rounded-2xl bg-gradient-to-br from-slate-950 to-blue-950/20 border border-blue-900/40 space-y-3">
          <div className="flex items-start justify-between gap-3">
            <div className="space-y-1">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Layers className="w-4 h-4 text-blue-400" />
                <span>Load Comprehensive Testing Dataset</span>
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Populate all 18 business modules with full end-to-end scenarios (42 leads, 14 quotes, 6 orders, warehouse stock, RFQs, RMAs, and Telegram approval cards) to test or demo anytime.
              </p>
            </div>
            <span className="text-[10px] font-semibold text-blue-400 uppercase tracking-wider bg-blue-950 px-2 py-0.5 rounded border border-blue-800/60 whitespace-nowrap">
              Evaluation
            </span>
          </div>

          <div className="pt-1 flex items-center justify-between">
            <span className="text-[11px] text-slate-400">
              Instantly restores all 88 blueprint test scenarios.
            </span>
            <button
              id="btn-load-testing-dataset"
              onClick={() => setConfirmDemoModal(true)}
              className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-md shadow-blue-600/20 flex items-center gap-1.5 transition-colors"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Load Full Testing Dataset</span>
            </button>
          </div>
        </div>

        {confirmDemoModal && (
          <div role="alertdialog" aria-label="Confirm demo data overwrite" className="p-4 rounded-xl bg-amber-950 border border-amber-800 text-xs space-y-3">
            <strong className="text-amber-200">Demo import will overwrite existing browser-local records.</strong>
            <p className="text-slate-300">Export a browser-only JSON copy first. This is not a MySQL backup and does not certify production state.</p>
            <div className="flex justify-end gap-2">
              <button onClick={() => setConfirmDemoModal(false)} className="px-3 py-1.5 rounded-lg bg-slate-700 text-white">Cancel</button>
              <button onClick={handleExecuteLoadTesting} className="px-3 py-1.5 rounded-lg bg-amber-700 text-white">Confirm overwrite browser demo data</button>
            </div>
          </div>
        )}
        {/* Confirmation Sub-Modal */}
        {confirmWipeModal && (
          <div className="p-4 rounded-xl bg-rose-950 border border-rose-800 text-xs space-y-3 animate-in fade-in">
            <div className="flex items-center gap-2 text-rose-300 font-bold">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>Confirm Final Action: Wipe all test data?</span>
            </div>
            <p className="text-slate-300">
              This will reset the platform into a clean production slate. All existing test records (leads, quotes, orders) will be cleared from local storage.
            </p>
            <div className="flex items-center justify-end gap-2 pt-1">
              <button
                onClick={() => setConfirmWipeModal(false)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              >
                Cancel
              </button>
              <button
                id="btn-confirm-wipe-execute"
                onClick={handleExecuteWipeToProduction}
                className="px-4 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold transition-colors"
              >
                Yes, Wipe &amp; Start Fresh
              </button>
            </div>
          </div>
        )}

        <div className="flex justify-end pt-2 border-t border-slate-800">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
