import React from 'react';
import {
  Cpu,
  Send,
  ShieldCheck,
  Activity,
  Bell,
  Building2,
  Layers,
  Sparkles,
  Settings,
  Globe,
  ExternalLink,
  Truck,
  Users,
  GitBranch,
  TrendingUp,
  Server,
  RotateCcw,
  Database
} from 'lucide-react';
import { CompanyProfile } from '../types';
import { DEFAULT_COMPANY_PROFILE } from '../services/storageService';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  pendingApprovalsCount: number;
  openTelegramDrawer: () => void;
  isTelegramDrawerOpen: boolean;
  companyProfile?: CompanyProfile;
  onOpenSettings?: () => void;
  onOpenReset?: () => void;
  environmentMode?: 'TESTING' | 'PRODUCTION';
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  pendingApprovalsCount,
  openTelegramDrawer,
  isTelegramDrawerOpen,
  companyProfile = DEFAULT_COMPANY_PROFILE,
  onOpenSettings,
  onOpenReset,
  environmentMode = 'TESTING'
}) => {
  const tabs = [
    { id: 'dashboard', label: 'Executive Hub', icon: Activity },
    { id: 'telegram', label: 'Telegram Command', icon: Send, badge: pendingApprovalsCount },
    { id: 'crm', label: 'CRM & Leads', icon: Building2 },
    { id: 'bom', label: 'AI BOM Builder', icon: Cpu },
    { id: 'quotes', label: 'Quotes & Pricing', icon: Layers },
    { id: 'orders', label: 'Orders & Logistics', icon: Truck },
    { id: 'approvals', label: 'Approval Matrix', icon: ShieldCheck, badge: pendingApprovalsCount },
    { id: 'procurement', label: 'Procurement & Stock', icon: Layers },
    { id: 'analytics', label: 'Predictive & Forecast', icon: TrendingUp },
    { id: 'portals', label: 'Portals & Resellers', icon: Users },
    { id: 'workflows', label: 'Workflows & RAG', icon: GitBranch },
    { id: 'system', label: 'System Hub & API', icon: Server },
    { id: 'finance', label: 'Finance & Service', icon: ShieldCheck },
    { id: 'marketing', label: 'Marketing & Agents', icon: Sparkles },
  ];

  return (
    <header className="sticky top-0 z-40 bg-slate-900 border-b border-slate-800 text-slate-100 shadow-md">
      {/* Top tier brand bar */}
      <div className="px-4 py-2.5 flex flex-wrap items-center justify-between border-b border-slate-800/80 gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-blue-500/20">
            <Cpu className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold tracking-tight text-white">{companyProfile.name}</h1>
              <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                IT Hardware Platform
              </span>
              <a
                href={companyProfile.website}
                target="_blank"
                rel="noreferrer"
                className="hidden sm:inline-flex items-center gap-1 text-[11px] text-sky-400 hover:text-sky-300 underline underline-offset-2"
              >
                <span>{companyProfile.website.replace('https://', '')}</span>
                <ExternalLink className="w-3 h-3" />
              </a>
              <span className="hidden md:inline-flex items-center gap-1.5 text-[11px] text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full border border-emerald-500/20">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                90% Auto-Executed | 10% Telegram Gate
              </span>
            </div>
            <p className="text-xs text-slate-400">
              {companyProfile.name} &bull; GSTIN: {companyProfile.gstin} &bull; Tel: {companyProfile.phone} &bull; Mumbai Hub
            </p>
          </div>
        </div>

        {/* Status indicators and Settings / Telegram quick launcher */}
        <div className="flex items-center gap-2 sm:gap-3">
          <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-lg bg-slate-800/60 border border-slate-700/60 text-xs text-slate-300">
            <Activity className="w-3.5 h-3.5 text-blue-400" />
            <span>Event Bus: <strong className="text-white font-medium">184 msgs/min</strong></span>
          </div>

          <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-lg bg-slate-800/60 border border-slate-700/60 text-xs text-slate-300">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>Margin Guard: <strong className="text-emerald-400 font-medium">≥{companyProfile.defaultMarginThreshold}%</strong></span>
          </div>

          {/* Reset / Fresh Start Controller Button */}
          <button
            id="btn-open-reset-controller"
            onClick={onOpenReset}
            title="Reset system to clean production slate or load testing dataset"
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-semibold transition-colors ${
              environmentMode === 'PRODUCTION'
                ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-300 hover:bg-emerald-900/60'
                : 'bg-rose-950/60 border-rose-500/40 text-rose-300 hover:bg-rose-900/60'
            }`}
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">
              {environmentMode === 'PRODUCTION' ? 'Production Slate' : 'Reset / Start Fresh'}
            </span>
          </button>

          {/* Real Data & Settings Button */}
          <button
            id="btn-open-settings"
            onClick={onOpenSettings}
            title="Manage Company Profile & Real Data Backup/Import"
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition-colors"
          >
            <Settings className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden md:inline">Settings & Real Data</span>
          </button>

          {/* Hostinger MySQL Quick Launcher */}
          <button
            id="btn-open-hostinger-mysql"
            onClick={() => setActiveTab('system')}
            title="Hostinger Business Plan & MySQL Database Manager"
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-amber-950/50 hover:bg-amber-900/60 text-amber-300 border border-amber-500/40 text-xs font-semibold transition-colors"
          >
            <Database className="w-3.5 h-3.5 text-amber-400" />
            <span className="hidden xl:inline">Hostinger MySQL</span>
          </button>

          <button
            id="btn-telegram-quick-access"
            onClick={openTelegramDrawer}
            className={`relative flex items-center gap-2 px-3 py-1.5 rounded-lg font-medium text-xs transition-all shadow-sm ${
              isTelegramDrawerOpen || activeTab === 'telegram'
                ? 'bg-sky-500 text-white shadow-sky-500/25 ring-2 ring-sky-400/40'
                : 'bg-sky-600/20 text-sky-300 hover:bg-sky-600/30 border border-sky-500/30'
            }`}
          >
            <Send className="w-3.5 h-3.5 text-sky-400" />
            <span className="hidden sm:inline">Telegram Hub</span>
            {pendingApprovalsCount > 0 && (
              <span className="w-5 h-5 rounded-full bg-rose-500 text-white font-bold text-[10px] flex items-center justify-center animate-bounce">
                {pendingApprovalsCount}
              </span>
            )}
          </button>
        </div>
      </div>

      {/* Navigation tabs */}
      <div className="px-4 flex items-center gap-1 overflow-x-auto no-scrollbar py-1.5 bg-slate-950/40">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              id={`nav-tab-${tab.id}`}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap transition-colors relative ${
                isActive
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-white' : 'text-slate-400'}`} />
              <span>{tab.label}</span>
              {typeof tab.badge === 'number' && tab.badge > 0 && (
                <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded-full ${
                  isActive ? 'bg-rose-500 text-white' : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                }`}>
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </header>
  );
};
