import { authenticatedFetch } from '../services/authClient';
import React, { useState } from 'react';
import {
  Sparkles,
  Share2,
  Cpu,
  Activity,
  Send,
  CheckCircle2,
  RefreshCw,
  Layers,
  ArrowUpRight,
  TrendingUp,
  MessageSquare,
  Mail,
  ShieldCheck,
  Bot
} from 'lucide-react';
import { MarketingCampaign, AIAgent } from '../types';

interface MarketingAndAgentViewProps {
  campaigns: MarketingCampaign[];
  agents: AIAgent[];
  onTriggerCampaign: (campaign: MarketingCampaign) => void;
}

export const MarketingAndAgentView: React.FC<MarketingAndAgentViewProps> = ({
  campaigns,
  agents,
  onTriggerCampaign
}) => {
  const [activeTab, setActiveTab] = useState<'AGENTS' | 'CAMPAIGNS' | 'CONTENT_STUDIO'>('AGENTS');

  // AI Content Generator state (Section 41)
  const [targetSegment, setTargetSegment] = useState('B2B hardware accounts (verify needs and contact consent before outreach)');
  const [campaignObjective, setCampaignObjective] = useState('ProActive 1-Year Comprehensive AMC Upgrade');
  const [selectedChannel, setSelectedChannel] = useState<'WHATSAPP' | 'EMAIL'>('WHATSAPP');
  const [isGeneratingContent, setIsGeneratingContent] = useState(false);

  const [contentError,setContentError]=useState<string|null>(null);
  const [generatedContent, setGeneratedContent] = useState<{
    headline:string;whatsappMessage:string;emailSubject:string;emailBody:string;
    projectedConversion:string;estimatedPipelineValue:string;
  }|null>(null);

  const handleGenerateAIContent = async () => {
    setIsGeneratingContent(true);
    setContentError(null);
    try {
      const res = await authenticatedFetch('/api/ai/campaign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetSegment,
          objective: campaignObjective,
          channel: selectedChannel
        })
      });
      const data = await res.json();
      if(!res.ok)throw new Error(data.error || 'Campaign drafting unavailable');
      setGeneratedContent(data);
    } catch (err) {
      setGeneratedContent(null);
      setContentError(err instanceof Error ? err.message : 'Campaign drafting unavailable');
    } finally {
      setIsGeneratingContent(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-purple-400" />
            <span>AI Multi-Agent Orchestrator & Marketing Hub (Sections 39–47)</span>
          </h2>
          <p className="text-xs text-slate-400">
            Real-time status of 8 specialized autonomous agents and data-driven B2B campaign engine
          </p>
        </div>

        <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
          <button
            onClick={() => setActiveTab('AGENTS')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'AGENTS' ? 'bg-purple-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            Multi-Agent Fleet (8)
          </button>
          <button
            onClick={() => setActiveTab('CONTENT_STUDIO')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'CONTENT_STUDIO' ? 'bg-purple-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            AI Campaign Studio
          </button>
          <button
            onClick={() => setActiveTab('CAMPAIGNS')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeTab === 'CAMPAIGNS' ? 'bg-purple-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            Attribution & ROAS
          </button>
        </div>
      </div>

      {/* TAB 1: MULTI-AGENT ARCHITECTURE (Section 46 & 47) */}
      {activeTab === 'AGENTS' && (
        <div className="space-y-6">
          {/* Orchestrator Master Node */}
          <div className="bg-gradient-to-r from-slate-950 via-purple-950/40 to-slate-950 border border-purple-800/40 rounded-2xl p-5 shadow-lg space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-purple-900/40 pb-3">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-purple-600/30 text-purple-300 border border-purple-500/40 flex items-center justify-center">
                  <Bot className="w-5 h-5 text-purple-400" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white tracking-tight">
                    Central AI Orchestrator Node (Section 46)
                  </h3>
                  <span className="text-xs text-slate-400">
                    Directs 8 specialized domain agents & enforces Section 51 Guardrails
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-xs bg-emerald-500/20 text-emerald-300 px-3 py-1 rounded-full font-bold border border-emerald-500/30 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  All 8 Agents Healthy
                </span>
              </div>
            </div>

            {/* Section 51 Guardrails Notice */}
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-2 text-[11px] text-slate-300">
              <div className="p-2 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Zero Hallucinated Fact Rule</span>
              </div>
              <div className="p-2 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Cannot Bypass 15% Margin</span>
              </div>
              <div className="p-2 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Cannot Self-Approve Exception</span>
              </div>
              <div className="p-2 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>Strict Tenant Data Isolation</span>
              </div>
            </div>
          </div>

          {/* 8 Autonomous Domain Agents Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {agents.map((agent) => (
              <div
                key={agent.id}
                className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-2xl p-4 shadow-sm space-y-3 transition-all flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <span className="text-[10px] font-mono font-bold bg-purple-500/20 text-purple-300 px-2 py-0.5 rounded border border-purple-500/30">
                      {agent.code} AGENT
                    </span>
                    <span className={`text-[10px] font-bold px-2 py-0.2 rounded-full uppercase ${
                      agent.status === 'PROCESSING'
                        ? 'bg-blue-500/20 text-blue-300 animate-pulse'
                        : agent.status === 'WAITING_APPROVAL'
                        ? 'bg-amber-500/20 text-amber-300'
                        : 'bg-emerald-500/20 text-emerald-400'
                    }`}>
                      {agent.status}
                    </span>
                  </div>

                  <h4 className="text-xs font-bold text-white">{agent.name}</h4>
                  <p className="text-[11px] text-slate-400 mt-1 leading-relaxed line-clamp-2">
                    {agent.description}
                  </p>
                </div>

                <div className="space-y-2 pt-2 border-t border-slate-800/80 text-[11px]">
                  <div className="p-2 rounded-lg bg-slate-950 text-slate-300">
                    <strong className="text-[10px] text-purple-300 uppercase block mb-0.5">Current Task:</strong>
                    <span className="line-clamp-2 text-[11px]">{agent.currentTask}</span>
                  </div>

                  <div className="flex items-center justify-between text-slate-400 text-[10px] pt-0.5">
                    <span>Today: <strong className="text-white font-semibold">{agent.tasksCompletedToday}</strong> done</span>
                    <span>Confidence: <strong className="text-emerald-400 font-bold">{agent.confidenceScore}%</strong></span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 2: AI CAMPAIGN STUDIO (Section 41) */}
      {activeTab === 'CONTENT_STUDIO' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4 text-xs">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-purple-400" />
              <span>AI Content Engine (Section 41)</span>
            </h3>

            <div className="space-y-3">
              <div>
                <label className="text-slate-400 block mb-1">Select Target Audience Segment:</label>
                <select
                  value={targetSegment}
                  onChange={(e) => setTargetSegment(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                >
                  <option value="73 Accounts with Laptop/Server Warranty expiring < 60 days">
                    73 Accounts with Warranty Expiring &lt; 60 Days (AMC Upsell)
                  </option>
                  <option value="120 SMB & Educational Institutes seeking Gigabit Switches at 40% Discount">
                    120 SMBs & Schools (Dead Stock Cisco 2960 Liquidation)
                  </option>
                  <option value="50 High-Growth Tech Startups in BKC & Bengaluru">
                    50 High-Growth Tech Startups (ThinkPad & Server Lease Bundles)
                  </option>
                </select>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Campaign Objective:</label>
                <input
                  type="text"
                  value={campaignObjective}
                  onChange={(e) => setCampaignObjective(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Primary Channel:</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setSelectedChannel('WHATSAPP')}
                    className={`py-2 rounded-lg font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                      selectedChannel === 'WHATSAPP'
                        ? 'bg-emerald-600 text-white'
                        : 'bg-slate-950 text-slate-400 border border-slate-700'
                    }`}
                  >
                    <MessageSquare className="w-3.5 h-3.5" />
                    WhatsApp Direct
                  </button>
                  <button
                    type="button"
                    onClick={() => setSelectedChannel('EMAIL')}
                    className={`py-2 rounded-lg font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                      selectedChannel === 'EMAIL'
                        ? 'bg-blue-600 text-white'
                        : 'bg-slate-950 text-slate-400 border border-slate-700'
                    }`}
                  >
                    <Mail className="w-3.5 h-3.5" />
                    B2B Email Pitch
                  </button>
                </div>
              </div>

              <button
                onClick={handleGenerateAIContent}
                disabled={isGeneratingContent}
                className="w-full py-2.5 rounded-xl bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-bold text-xs flex items-center justify-center gap-2 shadow-md shadow-purple-600/25 transition-all"
              >
                {isGeneratingContent ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
                <span>Generate High-Converting Copy</span>
              </button>
            </div>
          </div>

          {/* Generated Previews */}
          <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white">Campaign Output Preview</h3>
              {generatedContent && (
                <div className="flex items-center gap-3 text-xs">
                  <span className="text-slate-400">Measured conversion: <strong className="text-emerald-400">{generatedContent.projectedConversion}</strong></span>
                  <span className="text-slate-400">Measured pipeline: <strong className="text-purple-300">{generatedContent.estimatedPipelineValue}</strong></span>
                </div>
              )}
            </div>

            {contentError && <p role="alert" className="text-xs text-amber-300">{contentError}</p>}
            {generatedContent && (
              <div className="space-y-4 text-xs">
                {/* WhatsApp Format */}
                <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-800/40 space-y-2">
                  <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1">
                    <MessageSquare className="w-3.5 h-3.5" /> WhatsApp Formatted Message
                  </span>
                  <div className="p-3 rounded-lg bg-slate-950 text-slate-200 font-sans whitespace-pre-line leading-relaxed border border-slate-800">
                    {generatedContent.whatsappMessage}
                  </div>
                </div>

                {/* Email Format */}
                <div className="p-4 rounded-xl bg-blue-950/20 border border-blue-800/40 space-y-2">
                  <span className="text-[10px] font-bold text-blue-400 uppercase tracking-wider flex items-center gap-1">
                    <Mail className="w-3.5 h-3.5" /> B2B Email Subject & Copy
                  </span>
                  <div className="p-2 rounded bg-slate-950 text-white font-semibold">
                    Subject: {generatedContent.emailSubject}
                  </div>
                  <div className="p-3 rounded-lg bg-slate-950 text-slate-300 font-sans whitespace-pre-line leading-relaxed border border-slate-800">
                    {generatedContent.emailBody}
                  </div>
                </div>

                <button disabled title="No verified audience consent or dispatch connector" className="w-full py-2.5 rounded-xl bg-slate-700 opacity-60 cursor-not-allowed text-slate-300 font-bold text-xs flex items-center justify-center gap-2">
                  <Send className="w-4 h-4" />
                  <span>Dispatch disabled — approval and consent required</span>
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: CAMPAIGNS & ROAS ATTRIBUTION (Section 42) */}
      {activeTab === 'CAMPAIGNS' && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-emerald-400" />
                <span>End-to-End Marketing Attribution & ROAS (Section 42)</span>
              </h3>
              <p className="text-xs text-slate-400">
                Track Campaign &rarr; Inbound Leads &rarr; Quotations &rarr; Orders &rarr; Gross Profit
              </p>
            </div>
          </div>

          <div className="space-y-3">
            {campaigns.map((camp) => (
              <div
                key={camp.id}
                className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3 text-xs"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <h4 className="font-bold text-white text-sm">{camp.name}</h4>
                    <span className="text-[11px] text-slate-400">Target: {camp.targetSegment}</span>
                  </div>
                  <span className="text-xs font-bold text-emerald-400 bg-emerald-500/20 px-2.5 py-1 rounded-full border border-emerald-500/30">
                    ROAS: {camp.roas}x
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3 rounded-lg bg-slate-900 text-center">
                  <div>
                    <span className="text-slate-500 text-[10px] block">Audience Reach</span>
                    <strong className="text-white text-sm font-mono">{camp.reach} Accts</strong>
                  </div>
                  <div>
                    <span className="text-slate-500 text-[10px] block">Qualified Leads</span>
                    <strong className="text-cyan-400 text-sm font-mono">{camp.qualifiedLeads}</strong>
                  </div>
                  <div>
                    <span className="text-slate-500 text-[10px] block">Deals Won</span>
                    <strong className="text-emerald-400 text-sm font-mono">{camp.ordersWon} Orders</strong>
                  </div>
                  <div>
                    <span className="text-slate-500 text-[10px] block">Attributed Revenue</span>
                    <strong className="text-white text-sm font-mono">₹{(camp.revenueGenerated / 100000).toFixed(2)}L</strong>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
