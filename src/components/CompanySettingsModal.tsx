import React, { useState } from 'react';
import {
  Building2,
  Globe,
  Phone,
  Mail,
  FileSpreadsheet,
  Download,
  Upload,
  RotateCcw,
  CheckCircle2,
  Shield,
  CreditCard,
  Sliders,
  ExternalLink
} from 'lucide-react';
import { CompanyProfile } from '../types';
import { storageService } from '../services/storageService';

interface CompanySettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  companyProfile: CompanyProfile;
  onSaveProfile: (profile: CompanyProfile) => void;
  onDataReload: () => void;
}

export const CompanySettingsModal: React.FC<CompanySettingsModalProps> = ({
  isOpen,
  onClose,
  companyProfile,
  onSaveProfile,
  onDataReload
}) => {
  const [formData, setFormData] = useState<CompanyProfile>(companyProfile);
  const [activeTab, setActiveTab] = useState<'PROFILE' | 'DATA_BACKUP'>('PROFILE');
  const [saveStatus, setSaveStatus] = useState<string | null>(null);
  const [importStatus, setImportStatus] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSaveProfile(formData);
    setSaveStatus('Company profile updated successfully!');
    setTimeout(() => setSaveStatus(null), 3000);
  };

  const handleExportJSON = () => {
    const json = storageService.exportFullBackup();
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aaditech_system_backup_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleImportFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (ev) => {
      const content = ev.target?.result as string;
      const success = storageService.importFullBackup(content);
      if (success) {
        setImportStatus('Data imported successfully! Reloading workspace...');
        setTimeout(() => {
          onDataReload();
          onClose();
        }, 1500);
      } else {
        setImportStatus('Error: Invalid JSON backup file.');
      }
    };
    reader.readAsText(file);
  };

  const handleResetData = () => {
    if (confirm('Are you sure you want to reset all data back to AadiTech Solution system defaults? Any unsaved edits will be cleared.')) {
      storageService.resetAllData();
      onDataReload();
      onClose();
    }
  };

  const handleWipeToClean = () => {
    if (confirm('CONFIRM PRODUCTION START: This will permanently wipe all test leads, quotes, orders, RMAs, tickets, and RFQs, setting the system to a clean production slate. Continue?')) {
      storageService.wipeToCleanProductionState();
      onDataReload();
      onClose();
    }
  };

  const handleLoadTestingData = () => {
    if (confirm('Load comprehensive testing dataset with all 88 blueprint scenarios for evaluation?')) {
      storageService.loadTestingDemoState();
      onDataReload();
      onClose();
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-5 my-8">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="w-10 h-10 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <Building2 className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">Company Profile & Real Data Center</h2>
              <p className="text-xs text-slate-400">
                AadiTech Solution Master Legal, GST, Bank & Data Persistence Configuration
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Tab pills */}
        <div className="flex items-center gap-2 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
          <button
            onClick={() => setActiveTab('PROFILE')}
            className={`flex-1 py-1.5 rounded-lg font-semibold transition-colors ${
              activeTab === 'PROFILE' ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            AadiTech Profile & GST
          </button>
          <button
            onClick={() => setActiveTab('DATA_BACKUP')}
            className={`flex-1 py-1.5 rounded-lg font-semibold transition-colors ${
              activeTab === 'DATA_BACKUP' ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            Real Data Backup, Import & Export
          </button>
        </div>

        {activeTab === 'PROFILE' && (
          <form onSubmit={handleSubmit} className="space-y-4 text-xs">
            {saveStatus && (
              <div className="p-3 rounded-lg bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4" />
                <span>{saveStatus}</span>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              <div>
                <label className="text-slate-300 font-medium block mb-1">Company Registered Name *</label>
                <input
                  type="text"
                  required
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white font-medium"
                />
              </div>

              <div>
                <label className="text-slate-300 font-medium block mb-1">Website URL *</label>
                <input
                  type="url"
                  required
                  value={formData.website}
                  onChange={(e) => setFormData({ ...formData, website: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white"
                />
              </div>

              <div>
                <label className="text-slate-300 font-medium block mb-1">GSTIN Number *</label>
                <input
                  type="text"
                  required
                  value={formData.gstin}
                  onChange={(e) => setFormData({ ...formData, gstin: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white font-mono"
                />
              </div>

              <div>
                <label className="text-slate-300 font-medium block mb-1">Company PAN *</label>
                <input
                  type="text"
                  required
                  value={formData.pan}
                  onChange={(e) => setFormData({ ...formData, pan: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white font-mono"
                />
              </div>

              <div>
                <label className="text-slate-300 font-medium block mb-1">Official Contact Phone *</label>
                <input
                  type="text"
                  required
                  value={formData.phone}
                  onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white font-mono"
                />
              </div>

              <div>
                <label className="text-slate-300 font-medium block mb-1">Official Quotes Email *</label>
                <input
                  type="email"
                  required
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white"
                />
              </div>

              <div className="sm:col-span-2">
                <label className="text-slate-300 font-medium block mb-1">Registered Address / Distribution Hub *</label>
                <input
                  type="text"
                  required
                  value={formData.address}
                  onChange={(e) => setFormData({ ...formData, address: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white"
                />
              </div>

              <div>
                <label className="text-slate-300 font-medium block mb-1">Bank Name</label>
                <input
                  type="text"
                  value={formData.bankName}
                  onChange={(e) => setFormData({ ...formData, bankName: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white"
                />
              </div>

              <div>
                <label className="text-slate-300 font-medium block mb-1">Bank Account Number</label>
                <input
                  type="text"
                  value={formData.accountNumber}
                  onChange={(e) => setFormData({ ...formData, accountNumber: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white font-mono"
                />
              </div>

              <div>
                <label className="text-slate-300 font-medium block mb-1">RTGS/NEFT IFSC Code</label>
                <input
                  type="text"
                  value={formData.ifscCode}
                  onChange={(e) => setFormData({ ...formData, ifscCode: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white font-mono"
                />
              </div>

              <div>
                <label className="text-slate-300 font-medium block mb-1">Autonomous Margin Guardrail (%)</label>
                <input
                  type="number"
                  step="0.5"
                  value={formData.defaultMarginThreshold}
                  onChange={(e) => setFormData({ ...formData, defaultMarginThreshold: Number(e.target.value) })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2.5 text-white font-mono"
                />
                <span className="text-[10px] text-slate-400 block mt-0.5">
                  Deals below this margin trigger Telegram Owner authorization.
                </span>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end gap-2.5">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
              >
                Close
              </button>
              <button
                type="submit"
                className="px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold shadow-md shadow-blue-500/25 transition-colors"
              >
                Save Profile Changes
              </button>
            </div>
          </form>
        )}

        {activeTab === 'DATA_BACKUP' && (
          <div className="space-y-4 text-xs">
            {importStatus && (
              <div className={`p-3 rounded-lg flex items-center gap-2 border ${
                importStatus.includes('Error')
                  ? 'bg-rose-500/20 text-rose-300 border-rose-500/30'
                  : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
              }`}>
                <CheckCircle2 className="w-4 h-4" />
                <span>{importStatus}</span>
              </div>
            )}

            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Download className="w-4 h-4 text-emerald-400" />
                <span>Export Real Data Backup (JSON)</span>
              </h3>
              <p className="text-slate-400 leading-relaxed">
                Download a complete, offline-compatible snapshot of all AadiTech Solution data (Active Leads, Quotations, Products, Serialized Inventory, Customers, Suppliers, AMCs & Tickets).
              </p>
              <button
                onClick={handleExportJSON}
                className="mt-2 flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold transition-colors shadow-sm"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download AadiTech JSON Backup</span>
              </button>
            </div>

            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Upload className="w-4 h-4 text-blue-400" />
                <span>Import Real Data Snapshot</span>
              </h3>
              <p className="text-slate-400 leading-relaxed">
                Restore or load your company's saved JSON database file to populate the platform with live records.
              </p>
              <label className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold cursor-pointer transition-colors shadow-sm">
                <Upload className="w-3.5 h-3.5" />
                <span>Select JSON File to Restore</span>
                <input
                  type="file"
                  accept=".json"
                  onChange={handleImportFile}
                  className="hidden"
                />
              </label>
            </div>

            <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-800/40 space-y-3">
              <div>
                <h3 className="text-sm font-bold text-rose-300 flex items-center gap-2">
                  <RotateCcw className="w-4 h-4 text-rose-400" />
                  <span>Production Reset &amp; Environment Controller</span>
                </h3>
                <p className="text-slate-400 leading-relaxed mt-1">
                  Once you have finished testing, wipe simulated records to start fresh in clean production mode, or reload the test dataset anytime.
                </p>
              </div>

              <div className="flex items-center gap-2 flex-wrap pt-1">
                <button
                  type="button"
                  id="btn-settings-wipe-clean"
                  onClick={handleWipeToClean}
                  className="px-3.5 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold transition-colors shadow-sm"
                >
                  Wipe Test Data &amp; Start Fresh (Production Slate)
                </button>
                <button
                  type="button"
                  id="btn-settings-load-testing"
                  onClick={handleLoadTestingData}
                  className="px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold transition-colors shadow-sm"
                >
                  Load Testing Dataset
                </button>
                <button
                  type="button"
                  onClick={handleResetData}
                  className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                >
                  Clear Storage
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
