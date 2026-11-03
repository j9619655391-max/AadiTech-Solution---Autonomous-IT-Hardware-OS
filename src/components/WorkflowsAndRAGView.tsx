import React, { useState } from 'react';
import {
  GitBranch,
  Activity,
  BookOpen,
  Search,
  Sparkles,
  Play,
  CheckCircle2,
  AlertTriangle,
  Send,
  Plus,
  ArrowRight,
  Cpu,
  Layers,
  FileText,
  Clock,
  ShieldCheck,
  RotateCw
} from 'lucide-react';
import {
  WorkflowRule,
  EventBusMessage,
  KnowledgeDocument,
  CompanyProfile
} from '../types';

interface WorkflowsAndRAGViewProps {
  workflowRules: WorkflowRule[];
  eventBusMessages: EventBusMessage[];
  knowledgeDocs: KnowledgeDocument[];
  companyProfile: CompanyProfile;
  onToggleWorkflowRule: (ruleId: string) => void;
  onExecuteWorkflowRule: (ruleId: string) => void;
  onCreateWorkflowRule: (rule: WorkflowRule) => void;
}

export const WorkflowsAndRAGView: React.FC<WorkflowsAndRAGViewProps> = ({
  workflowRules,
  eventBusMessages,
  knowledgeDocs,
  companyProfile,
  onToggleWorkflowRule,
  onExecuteWorkflowRule,
  onCreateWorkflowRule
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'workflows' | 'event_bus' | 'rag_knowledge'>('workflows');

  // RAG sandbox state
  const [ragQuery, setRagQuery] = useState('');
  const [ragResult, setRagResult] = useState<{ answer: string; matchedDoc: string } | null>(null);
  const [isSearchingRag, setIsSearchingRag] = useState(false);

  // New workflow modal state
  const [isNewRuleModalOpen, setIsNewRuleModalOpen] = useState(false);
  const [newRuleForm, setNewRuleForm] = useState({
    name: 'Overdue Payment Escalation & WhatsApp Notice',
    triggerEvent: 'InvoiceOverdueDays >= 7',
    condition: 'OutstandingBalance > 50000 && RiskScore != LOW',
    aiDecision: 'Draft cordial yet firm reminder with payment UPI QR & bank RTGS details; dispatch to CFO via WhatsApp.',
    action: 'Dispatch WhatsApp Overdue Alert & Flag Credit Hold',
    channel: 'WHATSAPP' as WorkflowRule['channel']
  });

  const handleRunRagQuery = (e: React.FormEvent) => {
    e.preventDefault();
    if (!ragQuery.trim()) return;

    setIsSearchingRag(true);
    setTimeout(() => {
      const q = ragQuery.toLowerCase();
      let matchedDoc = knowledgeDocs[0]?.title || 'Datasheet';
      let answer = '';

      if (q.includes('temp') || q.includes('operating') || q.includes('miltary') || q.includes('mil') || q.includes('500w') || q.includes('dc-dc')) {
        matchedDoc = 'AadiTech Hi-REL Military Grade DC-DC Converter Technical Datasheet';
        answer = `According to the official AadiTech technical datasheet, the Hi-REL 500W DC-DC Rugged Converter operates within an extreme temperature range of -40°C to +85°C. It is MIL-STD-810G & 461E compliant with conduction cooling, reverse polarity protection, and an MTBF of 450,000 operational hours.`;
      } else if (q.includes('sla') || q.includes('response') || q.includes('server') || q.includes('mumbai') || q.includes('hours') || q.includes('uptime')) {
        matchedDoc = 'Enterprise Server & SAN Storage SLA & AMC Response Matrix';
        answer = `Under the AadiTech Enterprise Server SLA, critical Severity 1 hardware outages mandate a 4-hour on-site engineer response across Mumbai MMR, Delhi NCR, and Bengaluru. Hardware uptime guarantee is 99.95% backed by cold-spare buffer units maintained in Bhiwandi Hub.`;
      } else if (q.includes('rma') || q.includes('return') || q.includes('doa') || q.includes('warranty') || q.includes('replace')) {
        matchedDoc = 'AadiTech Reverse Logistics & DOA / RMA Hardware Replacement Policy';
        answer = `Under AadiTech DOA Policy, any hardware unit exhibiting defects within 14 calendar days of delivery qualifies for instant advance replacement dispatch prior to vendor warranty reconciliation. Mandatory serial barcode scans must accompany the reverse pickup logistics.`;
      } else {
        matchedDoc = 'AadiTech General IT Infrastructure Knowledge Base';
        answer = `Retrieved matching technical records: All enterprise hardware procured and integrated through AadiTech Solution comes with verified GST e-invoicing, pre-configured firmware hardening, and direct vendor-backed back-to-back warranty support.`;
      }

      setRagResult({ answer, matchedDoc });
      setIsSearchingRag(false);
    }, 400);
  };

  const handleCreateRuleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const rule: WorkflowRule = {
      id: `WF-${Date.now()}`,
      ruleCode: `RULE_${Date.now().toString().slice(-4)}`,
      name: newRuleForm.name,
      triggerEvent: newRuleForm.triggerEvent,
      condition: newRuleForm.condition,
      aiDecision: newRuleForm.aiDecision,
      action: newRuleForm.action,
      channel: newRuleForm.channel,
      status: 'ACTIVE',
      executionsCount: 0,
      lastTriggered: 'Just created'
    };
    onCreateWorkflowRule(rule);
    setIsNewRuleModalOpen(false);
  };

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <GitBranch className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-white tracking-tight">
                  Autonomous Workflows, Event Bus & Knowledge RAG
                </h2>
                <p className="text-xs text-slate-400">
                  Sections 48, 49 & 50 &bull; Automated Business Rules &bull; Real-time Event Streaming &bull; Hardware Technical Intelligence
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsNewRuleModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition-all"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Create Workflow Rule</span>
            </button>
          </div>
        </div>

        {/* Global telemetry snapshot */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Active Automation Rules</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-lg font-bold text-cyan-400">
                {workflowRules.filter((r) => r.status === 'ACTIVE').length} / {workflowRules.length}
              </span>
              <span className="text-[10px] text-emerald-400 font-medium">Auto-Triggering</span>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Event Bus Throughput</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-lg font-bold text-white">184 msgs/min</span>
              <span className="text-[10px] text-cyan-400 font-medium">&lt; 45ms Latency</span>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Knowledge Base Documents</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-lg font-bold text-purple-400">{knowledgeDocs.length}</span>
              <span className="text-[10px] text-slate-400 font-medium">Vector Indexed</span>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Dead Letter Failures</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-lg font-bold text-emerald-400">0</span>
              <span className="text-[10px] text-emerald-400 font-medium">100% Reliable</span>
            </div>
          </div>
        </div>

        {/* Sub-tab navigation */}
        <div className="flex items-center gap-2 mt-4 pt-3 border-t border-slate-800 overflow-x-auto no-scrollbar">
          <button
            onClick={() => setActiveSubTab('workflows')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
              activeSubTab === 'workflows'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <GitBranch className="w-3.5 h-3.5" />
            <span>Workflow Automation Rules (Section 48)</span>
            <span className="px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px] text-slate-300">
              {workflowRules.length}
            </span>
          </button>

          <button
            onClick={() => setActiveSubTab('event_bus')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
              activeSubTab === 'event_bus'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Live Event Bus Stream (Section 49)</span>
            <span className="px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px] text-slate-300">
              {eventBusMessages.length}
            </span>
          </button>

          <button
            onClick={() => setActiveSubTab('rag_knowledge')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
              activeSubTab === 'rag_knowledge'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span>Technical Knowledge Base & RAG (Section 50)</span>
            <span className="px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px] text-slate-300">
              {knowledgeDocs.length}
            </span>
          </button>
        </div>
      </div>

      {/* Subtab 1: Workflow Automation Rules (Section 48) */}
      {activeSubTab === 'workflows' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span>Autonomous Trigger &rarr; Condition &rarr; AI Decision &rarr; Action Engine</span>
            </h3>
            <span className="text-xs text-slate-400">Total Executions: {workflowRules.reduce((s, r) => s + r.executionsCount, 0)}</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {workflowRules.map((rule) => {
              const channelColors = {
                WHATSAPP: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
                TELEGRAM: 'bg-sky-500/10 text-sky-300 border-sky-500/30',
                SYSTEM_EVENT: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30',
                EMAIL: 'bg-purple-500/10 text-purple-300 border-purple-500/30'
              };

              return (
                <div key={rule.id} className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-3.5 text-xs shadow-sm">
                  <div className="flex items-start justify-between border-b border-slate-800 pb-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-white text-xs">{rule.name}</span>
                        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${channelColors[rule.channel]}`}>
                          {rule.channel}
                        </span>
                      </div>
                      <span className="text-[10px] text-slate-500 font-mono mt-0.5 block">{rule.ruleCode}</span>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => onToggleWorkflowRule(rule.id)}
                        className={`text-[10px] font-bold px-2.5 py-1 rounded-lg border transition-all ${
                          rule.status === 'ACTIVE'
                            ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 hover:bg-emerald-500/30'
                            : 'bg-slate-800 text-slate-400 border-slate-700 hover:bg-slate-700'
                        }`}
                      >
                        {rule.status}
                      </button>
                    </div>
                  </div>

                  {/* Visual Flow diagram: Trigger -> Condition -> AI Decision -> Action */}
                  <div className="space-y-2 p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="flex items-center gap-2">
                      <span className="w-16 text-[10px] text-slate-400 font-mono">TRIGGER:</span>
                      <span className="font-mono text-cyan-300 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 text-[11px]">
                        {rule.triggerEvent}
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="w-16 text-[10px] text-slate-400 font-mono">CONDITION:</span>
                      <span className="font-mono text-amber-300 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 text-[11px]">
                        {rule.condition}
                      </span>
                    </div>

                    <div className="flex items-start gap-2 pt-1 border-t border-slate-800/80">
                      <span className="w-16 text-[10px] text-purple-400 font-mono flex items-center gap-1">
                        <Sparkles className="w-3 h-3" />
                        <span>AI:</span>
                      </span>
                      <span className="text-slate-300 text-[11px] leading-relaxed">{rule.aiDecision}</span>
                    </div>

                    <div className="flex items-start gap-2 pt-1 border-t border-slate-800/80">
                      <span className="w-16 text-[10px] text-emerald-400 font-mono">ACTION:</span>
                      <span className="font-semibold text-white text-[11px]">{rule.action}</span>
                    </div>
                  </div>

                  {/* Execution footer */}
                  <div className="flex items-center justify-between text-[11px] pt-1 text-slate-400">
                    <span>
                      Executions: <strong className="text-white font-mono">{rule.executionsCount}</strong> &bull; Last: {rule.lastTriggered}
                    </span>

                    <button
                      onClick={() => onExecuteWorkflowRule(rule.id)}
                      className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs transition-colors"
                    >
                      <Play className="w-3 h-3 text-emerald-400" />
                      <span>Test Trigger Now</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Subtab 2: Live Event Bus Stream (Section 49) */}
      {activeSubTab === 'event_bus' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  <span>Real-Time Business Event Bus & Message Dispatch Stream</span>
                </h3>
                <p className="text-xs text-slate-400">
                  Asynchronous pub/sub event layer connecting AI Agents, CRM, Inventory, Telegram and Fulfilment.
                </p>
              </div>
              <span className="text-xs text-emerald-400 font-mono flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span>Live Event Ingestion</span>
              </span>
            </div>

            <div className="space-y-2 font-mono text-xs">
              {eventBusMessages.map((evt) => (
                <div
                  key={evt.id}
                  className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-white font-bold">{evt.eventId}</span>
                      <span className="px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 text-[10px] font-semibold border border-cyan-500/30">
                        {evt.eventType}
                      </span>
                      <span className="text-[10px] text-slate-500">{evt.timestamp}</span>
                    </div>

                    <div className="flex items-center gap-2 text-[11px] text-slate-400">
                      <span>Source: <strong className="text-slate-200">{evt.sourceAgent}</strong></span>
                      <span>&rarr;</span>
                      <span>Target: <strong className="text-slate-200">{evt.targetModule}</strong></span>
                    </div>

                    <p className="text-[11px] text-slate-300 font-sans mt-0.5">{evt.payloadSnippet}</p>
                  </div>

                  <div className="text-right space-y-1">
                    <span className="text-[10px] text-emerald-400 font-bold bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                      {evt.status}
                    </span>
                    <span className="text-[10px] text-slate-400 block mt-0.5">Latency: {evt.latencyMs}ms</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Subtab 3: Technical Knowledge Base & RAG (Section 50) */}
      {activeSubTab === 'rag_knowledge' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Interactive RAG Search Sandbox */}
          <div className="lg:col-span-6 space-y-4">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-purple-400" />
                  <span>Interactive AI Knowledge Retrieval (RAG) Sandbox</span>
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Ask technical specs, SLA response standards, or RMA replacement rules grounded in official AadiTech documentation.
                </p>
              </div>

              <form onSubmit={handleRunRagQuery} className="space-y-3">
                <div className="relative">
                  <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
                  <input
                    type="text"
                    value={ragQuery}
                    onChange={(e) => setRagQuery(e.target.value)}
                    placeholder="e.g., What is the operating temp of AadiTech 500W DC-DC converter?"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-3 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div className="flex flex-wrap gap-2 text-[11px]">
                  <span className="text-slate-400">Quick Prompt Chips:</span>
                  <button
                    type="button"
                    onClick={() => setRagQuery('What is the operating temp and MTBF of AadiTech 500W DC-DC?')}
                    className="px-2 py-0.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"
                  >
                    500W DC-DC Specs
                  </button>
                  <button
                    type="button"
                    onClick={() => setRagQuery('What is the SLA response time for server outage in Mumbai?')}
                    className="px-2 py-0.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"
                  >
                    Server Outage SLA
                  </button>
                  <button
                    type="button"
                    onClick={() => setRagQuery('What is the DOA hardware return policy?')}
                    className="px-2 py-0.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"
                  >
                    DOA Return Policy
                  </button>
                </div>

                <div className="flex justify-end">
                  <button
                    type="submit"
                    disabled={isSearchingRag}
                    className="px-4 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-semibold text-xs shadow-sm flex items-center gap-1.5 transition-all"
                  >
                    {isSearchingRag ? (
                      <RotateCw className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Sparkles className="w-3.5 h-3.5" />
                    )}
                    <span>Query RAG Vector Store</span>
                  </button>
                </div>
              </form>

              {/* RAG Answer Display */}
              {ragResult && (
                <div className="p-4 rounded-xl bg-purple-500/10 border border-purple-500/30 space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold text-purple-300 uppercase tracking-wider flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5 text-purple-400" />
                      <span>RAG Grounded Response</span>
                    </span>
                    <span className="text-[10px] font-mono text-slate-400">100% Fact Checked</span>
                  </div>
                  <p className="text-slate-200 leading-relaxed">{ragResult.answer}</p>
                  <div className="pt-2 border-t border-purple-500/20 text-[11px] text-purple-300">
                    Source: <strong className="text-white">{ragResult.matchedDoc}</strong>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Right Column: Catalog of indexed technical documents */}
          <div className="lg:col-span-6 space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <BookOpen className="w-4 h-4 text-cyan-400" />
              <span>Indexed Master Knowledge Base Documents</span>
            </h3>

            <div className="space-y-3">
              {knowledgeDocs.map((doc) => (
                <div key={doc.id} className="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-2 text-xs shadow-sm">
                  <div className="flex items-start justify-between">
                    <div>
                      <span className="text-[10px] font-semibold text-cyan-400 font-mono uppercase tracking-wider">
                        {doc.category.replace(/_/g, ' ')}
                      </span>
                      <h4 className="font-bold text-white text-sm mt-0.5">{doc.title}</h4>
                      <span className="text-[11px] text-slate-400 block mt-0.5">Applies to: {doc.productLine}</span>
                    </div>
                    <span className="text-[10px] text-slate-500 font-mono">{doc.docSize}</span>
                  </div>

                  <p className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-[11px] text-slate-300 leading-relaxed">
                    {doc.snippet}
                  </p>

                  <div className="flex items-center justify-between pt-1 text-[10px] text-slate-500">
                    <span>Last Updated: {doc.lastUpdated}</span>
                    <span className="text-emerald-400 font-medium">Vector Embedded</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* New Workflow Rule Modal */}
      {isNewRuleModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-lg w-full shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-bold text-white">Create Autonomous Workflow Rule</h3>
                <p className="text-xs text-slate-400">Configure Event-Trigger-Decision-Action automation</p>
              </div>
              <button
                onClick={() => setIsNewRuleModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 text-lg leading-none"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleCreateRuleSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 mb-1">Rule Name</label>
                <input
                  type="text"
                  value={newRuleForm.name}
                  onChange={(e) => setNewRuleForm({ ...newRuleForm, name: e.target.value })}
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1">Trigger Event</label>
                  <input
                    type="text"
                    value={newRuleForm.triggerEvent}
                    onChange={(e) => setNewRuleForm({ ...newRuleForm, triggerEvent: e.target.value })}
                    required
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">Execution Channel</label>
                  <select
                    value={newRuleForm.channel}
                    onChange={(e) => setNewRuleForm({ ...newRuleForm, channel: e.target.value as any })}
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white"
                  >
                    <option value="TELEGRAM">Telegram Bot (Owner Gate)</option>
                    <option value="WHATSAPP">WhatsApp Business API</option>
                    <option value="SYSTEM_EVENT">System Event Bus</option>
                    <option value="EMAIL">SMTP Email Notice</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Logical Condition (Expression)</label>
                <input
                  type="text"
                  value={newRuleForm.condition}
                  onChange={(e) => setNewRuleForm({ ...newRuleForm, condition: e.target.value })}
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-amber-300 font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1">AI Agent Decision Reasoning</label>
                <textarea
                  value={newRuleForm.aiDecision}
                  onChange={(e) => setNewRuleForm({ ...newRuleForm, aiDecision: e.target.value })}
                  required
                  rows={2}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white resize-none"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Automated Action to Dispatch</label>
                <input
                  type="text"
                  value={newRuleForm.action}
                  onChange={(e) => setNewRuleForm({ ...newRuleForm, action: e.target.value })}
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-emerald-400"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsNewRuleModalOpen(false)}
                  className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs shadow-sm"
                >
                  Deploy Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
