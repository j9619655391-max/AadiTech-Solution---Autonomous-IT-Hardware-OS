import React, { useState, useRef, useEffect } from 'react';
import {
  Send,
  CheckCircle2,
  XCircle,
  Clock,
  Sparkles,
  Bot,
  User,
  ShieldAlert,
  HelpCircle,
  ExternalLink,
  ChevronRight,
  RefreshCw,
  Terminal,
  Zap
} from 'lucide-react';
import { TelegramMessage, TelegramApprovalCard } from '../types';

interface TelegramCommandHubProps {
  messages: TelegramMessage[];
  onSendMessage: (text: string) => Promise<void>;
  onApproveCard: (cardId: string, reason?: string) => void;
  onRejectCard: (cardId: string, reason?: string) => void;
  onNavigateToQuote?: (quoteId: string) => void;
  isDrawer?: boolean;
  onCloseDrawer?: () => void;
}

export const TelegramCommandHub: React.FC<TelegramCommandHubProps> = ({
  messages,
  onSendMessage,
  onApproveCard,
  onRejectCard,
  onNavigateToQuote,
  isDrawer = false,
  onCloseDrawer
}) => {
  const [inputText, setInputText] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [quickReason, setQuickReason] = useState<{ [cardId: string]: string }>({});
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isSending]);

  const handleSend = async (textToSend?: string) => {
    const text = textToSend || inputText;
    if (!text.trim() || isSending) return;

    setInputText('');
    setIsSending(true);
    try {
      await onSendMessage(text);
    } finally {
      setIsSending(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleSend();
    }
  };

  const quickPrompts = [
    { label: '📊 Aaj ka profit?', text: 'Aaj kitna profit hua?' },
    { label: '⚠️ Pending approvals', text: 'Pending approvals dikhao' },
    { label: '📦 Low stock check', text: 'Low stock dikhao' },
    { label: '💰 Orders > ₹5L', text: '₹5 lakh se upar ke pending orders batao' },
  ];

  const quickCommands = [
    '/dashboard',
    '/leads',
    '/quotes',
    '/pending',
    '/stock',
    '/profit'
  ];

  return (
    <div className={`flex flex-col h-full bg-slate-950 text-slate-100 rounded-xl overflow-hidden border border-slate-800 shadow-2xl ${
      isDrawer ? 'max-w-md w-full' : 'w-full'
    }`}>
      {/* Telegram Chat Header */}
      <div className="px-4 py-3 bg-gradient-to-r from-sky-900/90 via-slate-900 to-sky-950 border-b border-sky-800/40 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="w-10 h-10 rounded-full bg-sky-500 flex items-center justify-center text-white shadow-md shadow-sky-500/20">
              <Bot className="w-5 h-5" />
            </div>
            <span className="absolute bottom-0 right-0 w-3 h-3 rounded-full bg-emerald-400 border-2 border-slate-900" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <h2 className="text-sm font-bold text-white tracking-tight">AutoHardware Owner Bot</h2>
              <span className="text-[10px] bg-sky-500/20 text-sky-300 px-1.5 py-0.2 rounded font-mono font-semibold">BOT</span>
            </div>
            <p className="text-[11px] text-sky-200/80 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              Telegram Command Center &bull; Section 24 &bull; 2-way sync
            </p>
          </div>
        </div>

        {isDrawer && onCloseDrawer && (
          <button
            onClick={onCloseDrawer}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
          >
            ✕
          </button>
        )}
      </div>

      {/* Telegram Quick Command Bar */}
      <div className="px-3 py-2 bg-slate-900/90 border-b border-slate-800/80 flex items-center gap-1.5 overflow-x-auto no-scrollbar">
        <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1 pl-1">
          <Terminal className="w-3 h-3 text-sky-400" /> Commands:
        </span>
        {quickCommands.map((cmd) => (
          <button
            key={cmd}
            onClick={() => handleSend(cmd)}
            disabled={isSending}
            className="px-2.5 py-1 text-xs font-mono font-medium rounded-md bg-slate-800 hover:bg-sky-600/30 hover:text-sky-300 text-slate-300 border border-slate-700/60 transition-colors whitespace-nowrap"
          >
            {cmd}
          </button>
        ))}
      </div>

      {/* Message Stream */}
      <div className="flex-1 p-4 overflow-y-auto space-y-4 bg-gradient-to-b from-slate-950 via-slate-900/50 to-slate-950">
        {messages.map((msg) => {
          const isUser = msg.sender === 'user';
          return (
            <div
              key={msg.id}
              className={`flex flex-col ${isUser ? 'items-end' : 'items-start'}`}
            >
              <div
                className={`max-w-[90%] md:max-w-[80%] rounded-2xl p-3.5 shadow-md ${
                  isUser
                    ? 'bg-sky-600 text-white rounded-tr-none'
                    : 'bg-slate-800/90 border border-slate-700/70 text-slate-100 rounded-tl-none'
                }`}
              >
                {/* Header info */}
                <div className="flex items-center justify-between text-[11px] mb-1.5 opacity-75 gap-3">
                  <span className="font-semibold flex items-center gap-1">
                    {isUser ? <User className="w-3 h-3" /> : <Bot className="w-3 h-3 text-sky-400" />}
                    {isUser ? 'Business Owner (You)' : 'AutoHardware AI Bot'}
                  </span>
                  <span>{msg.timestamp}</span>
                </div>

                {/* Body message text */}
                <div className="text-xs leading-relaxed whitespace-pre-line">
                  {msg.text}
                </div>

                {/* Interactive Approval Card if attached */}
                {msg.approvalCard && (
                  <div className="mt-3 pt-3 border-t border-slate-700/80 bg-slate-900/90 rounded-xl p-3 border border-slate-700/50">
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div className="flex items-center gap-2">
                        <div className="w-6 h-6 rounded-md bg-amber-500/20 text-amber-400 flex items-center justify-center">
                          <ShieldAlert className="w-4 h-4" />
                        </div>
                        <div>
                          <span className="text-xs font-bold text-white block">
                            {msg.approvalCard.title}
                          </span>
                          <span className="text-[10px] text-slate-400">
                            Ref: {msg.approvalCard.referenceId} &bull; {msg.approvalCard.customerName}
                          </span>
                        </div>
                      </div>

                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${
                        msg.approvalCard.status === 'APPROVED'
                          ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          : msg.approvalCard.status === 'REJECTED'
                          ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                          : 'bg-amber-500/20 text-amber-300 border border-amber-500/30 animate-pulse'
                      }`}>
                        {msg.approvalCard.status}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-2 my-2.5 p-2 rounded-lg bg-slate-950/60 border border-slate-800 text-[11px]">
                      <div>
                        <span className="text-slate-400 block text-[10px]">Deal Value:</span>
                        <strong className="text-white font-semibold">₹{msg.approvalCard.amount.toLocaleString('en-IN')}</strong>
                      </div>
                      <div>
                        <span className="text-slate-400 block text-[10px]">Deal Margin:</span>
                        <strong className={`font-semibold ${
                          (msg.approvalCard.marginPct || 0) < 15 ? 'text-amber-400' : 'text-emerald-400'
                        }`}>
                          {msg.approvalCard.marginPct}% (Threshold: 15.0%)
                        </strong>
                      </div>
                    </div>

                    <div className="text-[11px] text-slate-300 bg-slate-950/40 p-2 rounded border border-slate-800/80 mb-3">
                      <strong className="text-amber-300 text-[10px] uppercase block mb-0.5">Context & AI Reason:</strong>
                      {msg.approvalCard.reason}
                    </div>

                    {/* Countdown and Escalation Timer */}
                    {msg.approvalCard.status === 'PENDING' && (
                      <div className="flex items-center justify-between text-[10px] text-slate-400 mb-3 px-1">
                        <span className="flex items-center gap-1 text-amber-400">
                          <Clock className="w-3 h-3 animate-spin" />
                          Escalation timer: {msg.approvalCard.timeoutMinutes} mins to auto-reminder
                        </span>
                        <span>Level: Owner Tier</span>
                      </div>
                    )}

                    {/* Action buttons */}
                    {msg.approvalCard.status === 'PENDING' ? (
                      <div className="space-y-2">
                        <div className="grid grid-cols-2 gap-2">
                          <button
                            id={`btn-tg-approve-${msg.approvalCard.id}`}
                            onClick={() => onApproveCard(msg.approvalCard!.id)}
                            className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs transition-colors shadow-sm shadow-emerald-600/20"
                          >
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            [APPROVE]
                          </button>

                          <button
                            id={`btn-tg-reject-${msg.approvalCard.id}`}
                            onClick={() => onRejectCard(msg.approvalCard!.id)}
                            className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-rose-600/80 hover:bg-rose-600 text-white font-semibold text-xs transition-colors"
                          >
                            <XCircle className="w-3.5 h-3.5" />
                            [REJECT]
                          </button>
                        </div>

                        <div className="grid grid-cols-2 gap-2">
                          {onNavigateToQuote && (
                            <button
                              onClick={() => onNavigateToQuote(msg.approvalCard!.referenceId)}
                              className="flex items-center justify-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] border border-slate-700"
                            >
                              <ExternalLink className="w-3 h-3" />
                              [MODIFY QUOTE]
                            </button>
                          )}

                          <button
                            onClick={() => handleSend(`AI Analysis on ${msg.approvalCard?.referenceId}: Is this margin acceptable against current inventory landed cost?`)}
                            className="flex items-center justify-center gap-1 px-2.5 py-1.5 rounded-lg bg-indigo-600/30 hover:bg-indigo-600/50 text-indigo-300 text-[11px] border border-indigo-500/30"
                          >
                            <Sparkles className="w-3 h-3 text-indigo-400" />
                            [ASK AI ANALYSIS]
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div className="text-center py-1 text-xs font-semibold text-emerald-400 bg-emerald-950/40 rounded border border-emerald-800/40">
                        ✓ Action Recorded & Dispatched to Audit Engine
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {isSending && (
          <div className="flex items-center gap-2 text-xs text-sky-400 bg-slate-900/60 p-2.5 rounded-xl border border-slate-800 w-fit">
            <RefreshCw className="w-3.5 h-3.5 animate-spin text-sky-400" />
            <span>AI Orchestrator reasoning & querying business ledger...</span>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Suggested Natural Language Prompts */}
      <div className="px-3 py-2 bg-slate-900/80 border-t border-slate-800/80">
        <div className="text-[10px] text-slate-400 uppercase font-semibold mb-1 flex items-center gap-1">
          <Zap className="w-3 h-3 text-amber-400" /> Quick Owner Prompts:
        </div>
        <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar py-0.5">
          {quickPrompts.map((p, idx) => (
            <button
              key={idx}
              onClick={() => handleSend(p.text)}
              disabled={isSending}
              className="text-[11px] px-2.5 py-1 rounded-full bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/60 whitespace-nowrap transition-colors"
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Input Form */}
      <div className="p-3 bg-slate-900 border-t border-slate-800">
        <div className="flex items-center gap-2">
          <input
            id="input-telegram-command"
            type="text"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type Telegram command (/orders, /profit) or ask in natural language..."
            className="flex-1 bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-sky-500 focus:border-sky-500"
          />
          <button
            id="btn-telegram-send"
            onClick={() => handleSend()}
            disabled={!inputText.trim() || isSending}
            className="p-2 rounded-xl bg-sky-500 hover:bg-sky-400 disabled:opacity-40 text-white transition-all shadow-md shadow-sky-500/20"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
        <div className="mt-1.5 flex items-center justify-between text-[10px] text-slate-500">
          <span>Commands: /dashboard, /leads, /quotes, /orders, /pending, /stock, /profit</span>
          <span>Encrypted Owner Session &bull; Port 3000 API</span>
        </div>
      </div>
    </div>
  );
};
