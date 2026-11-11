import { authenticatedFetch } from '../services/authClient';
import React, { useState, useEffect } from 'react';
import {
  FileText,
  Printer,
  Download,
  Send,
  Sparkles,
  ShieldAlert,
  CheckCircle2,
  DollarSign,
  Building,
  RefreshCw,
  Clock,
  ArrowRight,
  Sliders,
  Scale,
  Share2
} from 'lucide-react';
import { Quotation, TelegramApprovalCard, CompanyProfile } from '../types';

interface QuotationAndNegotiationProps {
  quotations: Quotation[];
  activeQuote: Quotation;
  onSendToTelegram: (card: TelegramApprovalCard) => void;
  onUpdateQuoteStatus: (quoteId: string, status: any) => void;
  companyProfile: CompanyProfile;
}

export const QuotationAndNegotiation: React.FC<QuotationAndNegotiationProps> = ({
  quotations,
  activeQuote,
  onSendToTelegram,
  onUpdateQuoteStatus,
  companyProfile
}) => {
  const [selectedQuoteId, setSelectedQuoteId] = useState(activeQuote ? activeQuote.id : '');
  const currentQuote = quotations.find(q => q.id === selectedQuoteId) || activeQuote || null;

  // AI Negotiation State (Section 22) - dynamically sync with selected quote's first item
  const firstItem = currentQuote?.items?.[0];
  const [customerOfferInput, setCustomerOfferInput] = useState<number>(firstItem ? Math.round(firstItem.unitSell * 0.92) : 49000);
  const [negotiatingProduct, setNegotiatingProduct] = useState(firstItem ? firstItem.name : 'Lenovo ThinkPad T14 Gen 4');
  const [negotiationCostPrice, setNegotiationCostPrice] = useState(firstItem ? firstItem.unitCost : 44000);
  const [negotiationMinPrice, setNegotiationMinPrice] = useState(firstItem ? Math.round(firstItem.unitCost * 1.1) : 51000);
  const [negotiationNormalPrice, setNegotiationNormalPrice] = useState(firstItem ? firstItem.unitSell : 54000);

  // Update negotiation items when currentQuote changes
  useEffect(() => {
    if (currentQuote && currentQuote.items && currentQuote.items.length > 0) {
      const item = currentQuote.items[0];
      setNegotiatingProduct(item.name);
      setNegotiationCostPrice(item.unitCost);
      setNegotiationMinPrice(Math.round(item.unitCost * 1.1));
      setNegotiationNormalPrice(item.unitSell);
      setCustomerOfferInput(Math.round(item.unitSell * 0.92));
    }
  }, [selectedQuoteId, currentQuote]);

  const [negotiationResult, setNegotiationResult] = useState<{
    action: string;
    allowed: boolean;
    reason: string;
    suggestedPitch: string;
    telegramDispatched?: boolean;
  } | null>(null);
  const [isNegotiating, setIsNegotiating] = useState(false);

  const handleSelectNegotiationItem = (itemIndex: number) => {
    const item = currentQuote.items[itemIndex];
    if (item) {
      setNegotiatingProduct(item.name);
      setNegotiationCostPrice(item.unitCost);
      setNegotiationMinPrice(Math.round(item.unitCost * 1.1));
      setNegotiationNormalPrice(item.unitSell);
      setCustomerOfferInput(Math.round(item.unitSell * 0.92));
    }
  };

  // Client-supplied margin numbers are not pricing authorization.
  // No Telegram card or customer acceptance is emitted by this preview.
  const handleTestNegotiation=async()=>{
    setIsNegotiating(true);
    try{
      const res=await authenticatedFetch('/api/ai/negotiate',{
        method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({currentPrice:negotiationNormalPrice,
          customerOffer:customerOfferInput,costPrice:negotiationCostPrice,
          minPrice:negotiationMinPrice,productName:negotiatingProduct})
      });
      const result=await res.json();
      if(!res.ok||result.allowed!==false)
        throw new Error(typeof result.error==='string'?result.error:
          'Negotiation automation unavailable — no action executed');
      setNegotiationResult({action:'UNAVAILABLE',allowed:false,
        reason:String(result.error||'Server-side approval required'),
        suggestedPitch:''});
    }catch(err){
      setNegotiationResult({action:'UNAVAILABLE',allowed:false,
        reason:err instanceof Error?err.message:'Negotiation unavailable',
        suggestedPitch:''});
    }finally{setIsNegotiating(false);}
  };

  const handlePrint = () => {
    window.print();
  };

  const handleShareWhatsApp = () => {
    const text = encodeURIComponent(
      `Dear ${currentQuote.customerName},\n\nPlease find Commercial Quotation ${currentQuote.quoteNumber} from ${companyProfile.name} (https://aaditechs.in) for ₹${currentQuote.totalAmount.toLocaleString('en-IN')} (incl. GST).\n\nValidity: ${currentQuote.validityDays} Days.\nFor questions or acceptance, contact: ${companyProfile.phone} / ${companyProfile.email}`
    );
    window.open(`https://api.whatsapp.com/send?text=${text}`, '_blank');
  };

  if (!currentQuote) {
    return (
      <div className="space-y-6">
        <div className="bg-slate-900 border border-slate-800 p-10 rounded-2xl text-center space-y-4 shadow-xl">
          <div className="w-14 h-14 rounded-2xl bg-indigo-500/20 text-indigo-400 flex items-center justify-center mx-auto">
            <FileText className="w-7 h-7" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white">No Active Quotations in System</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto mt-1 leading-relaxed">
              The quotation repository is currently empty and clean. Generate your first official GST quotation using the AI Solution &amp; BOM Builder or capture an inbound lead.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with Quote Selector */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <FileText className="w-5 h-5 text-indigo-400" />
            <span>Quotation Engine & AI Negotiation (Sections 20, 21 & 22)</span>
          </h2>
          <p className="text-xs text-slate-400">
            Professional India GST Compliant Quotation & Autonomous Negotiation Boundary Gate &bull; {companyProfile.name}
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <select
            value={selectedQuoteId}
            onChange={(e) => setSelectedQuoteId(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-xs text-white rounded-lg p-2 focus:outline-none"
          >
            {quotations.map(q => (
              <option key={q.id} value={q.id}>
                {q.quoteNumber} - {q.customerName} (₹{q.totalAmount.toLocaleString('en-IN')})
              </option>
            ))}
          </select>

          <button
            onClick={handleShareWhatsApp}
            title="Share quotation summary on WhatsApp"
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 text-xs border border-emerald-500/30 font-medium transition-colors"
          >
            <Share2 className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">WhatsApp</span>
          </button>

          <button
            onClick={handlePrint}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700 font-medium transition-colors"
          >
            <Printer className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Print / PDF</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left 7 cols: Official GST Quotation Document */}
        <div className="lg:col-span-7 bg-white text-slate-900 rounded-2xl p-6 sm:p-8 shadow-xl border border-slate-200 space-y-6 print:m-0 print:p-0 print:border-none">
          {/* Header with Letterhead */}
          <div className="flex items-start justify-between border-b border-slate-200 pb-5">
            <div>
              <div className="flex items-center gap-2">
                <div className="w-9 h-9 rounded-lg bg-blue-600 flex items-center justify-center text-white font-black text-sm shadow-md">
                  ATS
                </div>
                <div>
                  <h3 className="text-base font-extrabold tracking-tight text-slate-900 uppercase">
                    {companyProfile.name}
                  </h3>
                  <span className="text-[10px] text-slate-500 font-medium block">
                    {companyProfile.tagline}
                  </span>
                </div>
              </div>
              <p className="text-[11px] text-slate-600 mt-2 leading-relaxed">
                {companyProfile.address}<br />
                <strong>GSTIN:</strong> {companyProfile.gstin} &bull; <strong>PAN:</strong> {companyProfile.pan}<br />
                <strong>Website:</strong> {companyProfile.website} &bull; <strong>Email:</strong> {companyProfile.email} &bull; <strong>Tel:</strong> {companyProfile.phone}
              </p>
            </div>

            <div className="text-right">
              <span className="text-xs uppercase font-bold tracking-widest text-blue-600 block">
                COMMERCIAL QUOTATION
              </span>
              <span className="text-base font-bold font-mono text-slate-900">
                {currentQuote.quoteNumber}
              </span>
              <span className="text-xs text-slate-500 block mt-1">
                Date: {currentQuote.createdDate}
              </span>
              <span className={`inline-block mt-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                currentQuote.status === 'APPROVED'
                  ? 'bg-emerald-100 text-emerald-800'
                  : 'bg-amber-100 text-amber-800'
              }`}>
                {currentQuote.status}
              </span>
            </div>
          </div>

          {/* Billed To / Shipped To */}
          <div className="grid grid-cols-2 gap-4 p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs">
            <div>
              <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">
                Customer & Billing Address:
              </span>
              <strong className="text-slate-900 block font-bold">{currentQuote.customerName}</strong>
              <p className="text-slate-600 mt-0.5 text-[11px] leading-relaxed">
                {currentQuote.billingAddress}
              </p>
              <span className="text-[11px] text-slate-700 font-mono block mt-1">
                <strong>GSTIN:</strong> {currentQuote.customerGstin}
              </span>
            </div>

            <div className="border-l border-slate-200 pl-4">
              <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">
                Commercial Terms & Validity:
              </span>
              <p className="text-slate-700 text-[11px]">
                <strong>Validity:</strong> {currentQuote.validityDays} Days from issue<br />
                <strong>Delivery SLA:</strong> {currentQuote.deliveryWeeks} Week ex-Central Logistics Depot<br />
                <strong>Payment:</strong> {currentQuote.paymentTerms}<br />
                <strong>Warranty:</strong> 3-Year Direct OEM / AadiTech Onsite Warranty
              </p>
            </div>
          </div>

          {/* Itemized Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b-2 border-slate-300 text-slate-600 font-bold">
                  <th className="py-2">Item & Description</th>
                  <th className="py-2 text-center">HSN</th>
                  <th className="py-2 text-center">Qty</th>
                  <th className="py-2 text-right">Unit Rate (₹)</th>
                  <th className="py-2 text-right">Amount (₹)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 text-slate-800">
                {currentQuote.items.map((item, idx) => (
                  <tr key={idx} className="hover:bg-slate-50">
                    <td className="py-2.5">
                      <strong className="block font-semibold text-slate-900">{item.name}</strong>
                      <span className="text-[10px] text-slate-500 font-mono">{item.sku || item.category}</span>
                    </td>
                    <td className="py-2.5 text-center font-mono text-slate-600">{item.hsn}</td>
                    <td className="py-2.5 text-center font-bold">{item.qty}</td>
                    <td className="py-2.5 text-right font-mono">₹{item.unitSell.toLocaleString('en-IN')}</td>
                    <td className="py-2.5 text-right font-mono font-bold">
                      ₹{(item.unitSell * item.qty).toLocaleString('en-IN')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Totals & Tax Breakdown */}
          <div className="pt-3 border-t-2 border-slate-300 flex justify-end">
            <div className="w-64 space-y-1.5 text-xs">
              <div className="flex justify-between text-slate-600">
                <span>Subtotal (Excl. Tax):</span>
                <span className="font-mono">₹{currentQuote.subtotal.toLocaleString('en-IN')}</span>
              </div>
              <div className="flex justify-between text-slate-600">
                <span>Freight & Insurance:</span>
                <span className="font-mono">₹{currentQuote.freight.toLocaleString('en-IN')}</span>
              </div>
              <div className="flex justify-between text-slate-600">
                <span>CGST (9.0%):</span>
                <span className="font-mono">₹{currentQuote.cgst.toLocaleString('en-IN')}</span>
              </div>
              <div className="flex justify-between text-slate-600">
                <span>SGST (9.0%):</span>
                <span className="font-mono">₹{currentQuote.sgst.toLocaleString('en-IN')}</span>
              </div>
              {currentQuote.igst > 0 && (
                <div className="flex justify-between text-slate-600">
                  <span>IGST (18.0%):</span>
                  <span className="font-mono">₹{currentQuote.igst.toLocaleString('en-IN')}</span>
                </div>
              )}
              <div className="pt-2 border-t border-slate-300 flex justify-between text-sm font-black text-slate-900">
                <span>Total Payable:</span>
                <span className="text-blue-700 font-mono">
                  ₹{currentQuote.totalAmount.toLocaleString('en-IN')}
                </span>
              </div>
            </div>
          </div>

          {/* Banking & T&C */}
          <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 text-[10px] text-slate-600 space-y-1">
            <div className="font-bold uppercase text-slate-800">RTGS / NEFT Bank Transfer Details:</div>
            <div>
              <strong>Bank:</strong> {companyProfile.bankName} &bull; <strong>A/c Name:</strong> {companyProfile.accountName} &bull; 
              <strong>A/c No:</strong> {companyProfile.accountNumber} &bull; <strong>IFSC:</strong> {companyProfile.ifscCode} &bull; <strong>Branch:</strong> {companyProfile.branch} &bull; <strong>UPI:</strong> {companyProfile.upiId}
            </div>
            <div className="text-slate-500 pt-1">
              Goods once sold carry direct manufacturer / AadiTech warranties. Disputes subject to Mumbai Jurisdiction.
            </div>
          </div>
        </div>

        {/* Right 5 cols: AI Negotiation Engine Simulator (Section 22) */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-5">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-amber-400" />
                <span>AI Negotiation Engine (Section 22)</span>
              </h3>
              <p className="text-xs text-slate-400">
                Autonomous boundary check: Accept, Counter, or Escalate via Telegram
              </p>
            </div>
            <span className="text-[10px] font-mono bg-amber-500/20 text-amber-300 px-2 py-0.5 rounded border border-amber-500/30">
              Rule #22
            </span>
          </div>

          {/* Item Selector for Negotiation */}
          {currentQuote.items.length > 1 && (
            <div>
              <label className="text-slate-400 text-xs block mb-1">Select Item to Negotiate:</label>
              <select
                onChange={(e) => handleSelectNegotiationItem(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-700 text-xs text-white rounded-lg p-2"
              >
                {currentQuote.items.map((it, idx) => (
                  <option key={idx} value={idx}>
                    {it.name} (Sell: ₹{it.unitSell.toLocaleString('en-IN')})
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Live Parameter Box */}
          <div className="grid grid-cols-3 gap-2 text-center text-xs">
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-400 block">Unit Cost (Floor)</span>
              <strong className="text-rose-400 font-mono">₹{negotiationCostPrice.toLocaleString('en-IN')}</strong>
            </div>
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-400 block">Min Price (10% Margin)</span>
              <strong className="text-amber-400 font-mono">₹{negotiationMinPrice.toLocaleString('en-IN')}</strong>
            </div>
            <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-400 block">Target Sell Price</span>
              <strong className="text-emerald-400 font-mono">₹{negotiationNormalPrice.toLocaleString('en-IN')}</strong>
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-xs text-slate-300 font-medium block">
              Simulate Customer Counter-Offer (Per Unit):
            </label>
            <div className="relative">
              <span className="absolute left-3 top-2.5 text-slate-400 font-mono text-xs">₹</span>
              <input
                type="number"
                value={customerOfferInput}
                onChange={(e) => setCustomerOfferInput(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg py-2 pl-7 pr-3 text-white text-sm font-mono focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setCustomerOfferInput(negotiationMinPrice - 1500)}
                className="text-[10px] px-2 py-1 rounded bg-slate-800 text-rose-300 border border-slate-700 hover:bg-slate-700"
              >
                Below Min (₹{(negotiationMinPrice - 1500).toLocaleString('en-IN')})
              </button>
              <button
                type="button"
                onClick={() => setCustomerOfferInput(negotiationMinPrice + 500)}
                className="text-[10px] px-2 py-1 rounded bg-slate-800 text-amber-300 border border-slate-700 hover:bg-slate-700"
              >
                Acceptable (₹{(negotiationMinPrice + 500).toLocaleString('en-IN')})
              </button>
              <button
                type="button"
                onClick={() => setCustomerOfferInput(negotiationNormalPrice)}
                className="text-[10px] px-2 py-1 rounded bg-slate-800 text-emerald-300 border border-slate-700 hover:bg-slate-700"
              >
                Full Price (₹{negotiationNormalPrice.toLocaleString('en-IN')})
              </button>
            </div>
          </div>

          <button
            onClick={handleTestNegotiation}
            disabled={isNegotiating}
            className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-amber-600 to-indigo-600 hover:from-amber-500 hover:to-indigo-500 text-white font-semibold text-xs transition-all shadow-md flex items-center justify-center gap-2"
          >
            {isNegotiating ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Analyzing Boundary & Calculating Margin...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4" />
                <span>Evaluate Deal Boundary with AI</span>
              </>
            )}
          </button>

          {/* AI Decision Output */}
          {negotiationResult && (
            <div className={`p-4 rounded-xl border text-xs space-y-2.5 transition-all ${
              negotiationResult.action === 'ACCEPT_OFFER'
                ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-200'
                : negotiationResult.action === 'TELEGRAM_APPROVAL_REQUIRED'
                ? 'bg-amber-950/40 border-amber-800/60 text-amber-200'
                : 'bg-rose-950/40 border-rose-800/60 text-rose-200'
            }`}>
              <div className="flex items-center justify-between">
                <span className="font-bold uppercase tracking-wider text-[10px]">
                  Server-side decision required:
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold ${
                  negotiationResult.action === 'ACCEPT_OFFER'
                    ? 'bg-emerald-500 text-white'
                    : negotiationResult.action === 'TELEGRAM_APPROVAL_REQUIRED'
                    ? 'bg-amber-500 text-slate-900'
                    : 'bg-rose-500 text-white'
                }`}>
                  {negotiationResult.action.replace(/_/g, ' ')}
                </span>
              </div>

              <p className="text-slate-300 leading-relaxed">
                {negotiationResult.reason}
              </p>

              {negotiationResult.suggestedPitch && (
                <div className="mt-2 pt-2 border-t border-slate-700/60">
                  <span className="text-[10px] text-slate-400 font-semibold block mb-1">
                    AI Suggested Inbound WhatsApp/Email Pitch:
                  </span>
                  <div className="p-2.5 rounded bg-slate-950/80 text-slate-200 text-[11px] italic font-mono border border-slate-800">
                    "{negotiationResult.suggestedPitch}"
                  </div>
                </div>
              )}

              {negotiationResult.action === 'TELEGRAM_APPROVAL_REQUIRED' && (
                <div className="mt-2 p-2 rounded bg-amber-500/20 border border-amber-500/40 text-amber-300 text-[11px] flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 shrink-0" />
                  <span>
                    Dispatched Telegram notification to Business Owner with 10-minute auto-expiry countdown.
                  </span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

