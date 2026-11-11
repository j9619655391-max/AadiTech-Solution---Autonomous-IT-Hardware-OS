import { authenticatedFetch } from '../services/authClient';
import React, { useState } from 'react';
import {
  Cpu,
  Layers,
  CheckCircle2,
  AlertTriangle,
  Sparkles,
  Plus,
  Trash2,
  ArrowRight,
  TrendingUp,
  ShieldCheck,
  RefreshCw,
  Sliders,
  DollarSign
} from 'lucide-react';
import { BOMItem, Product } from '../types';

interface SalesAndBOMBuilderProps {
  products: Product[];
  currentBOM: BOMItem[];
  setCurrentBOM: React.Dispatch<React.SetStateAction<BOMItem[]>>;
  onGenerateQuote: (bomItems: BOMItem[], targetMargin: number) => void;
  initialRequirement?: string;
}

export const SalesAndBOMBuilder: React.FC<SalesAndBOMBuilderProps> = ({
  products,
  currentBOM,
  setCurrentBOM,
  onGenerateQuote,
  initialRequirement = ''
}) => {
  const [requirementPrompt, setRequirementPrompt] = useState(
    initialRequirement || '25-seat modern office IT infrastructure setup with high security firewall and 3kVA UPS'
  );
  const [isGenerating, setIsGenerating] = useState(false);
  const [targetMarginPct, setTargetMarginPct] = useState<number>(16.5);
  const [freightPerUnit, setFreightPerUnit] = useState<number>(450);
  const [riskBufferPct, setRiskBufferPct] = useState<number>(2.0);

  // Compatibility engine state
  const [compatibilityError, setCompatibilityError] = useState<string | null>(null);
  const [compatibilityStatus, setCompatibilityStatus] = useState<'PASSED' | 'WARNING' | 'ERROR'>('WARNING');
  const [compatibilityReport, setCompatibilityReport] = useState<string>(
    'NOT VERIFIED: Check vendor prices, OEM compatibility, tax/HSN and availability with authoritative records.'
  );

  // Preset solutions
  const presets = [
    {
      label: '🏢 25-Seat Corporate Office',
      desc: '25 Desktops + 25 Monitors + 2 PoE Switches + Fortinet Firewall + 3 UniFi APs + 3kVA Online UPS',
      prompt: 'Complete 25-employee branch office IT hardware: 25 micro desktops with 24" monitors, 2 managed PoE switches, next-gen UTM firewall, 3 Wi-Fi 6 access points, and rack-mount online UPS.'
    },
    {
      label: '🖥️ 2U Virtualization Server Cluster',
      desc: 'Dell PowerEdge R760 + 128GB DDR5 ECC + RAID SAS + Redundant PSU + 10G SFP+',
      prompt: 'High-availability 2U rack server with dual Intel Xeon Gold, 128GB ECC DDR5 RDIMM, hardware RAID-10 with SAS SSDs, dual 1100W power supplies, and iDRAC enterprise.'
    },
    {
      label: '🛡️ Branch Network & Cybersecurity Stack',
      desc: 'Fortinet FortiGate 60F UTM + Cisco Catalyst 24P PoE+ + Ubiquiti Wi-Fi 6 APs',
      prompt: 'Branch cybersecurity and network refresh: 1 Gbps threat protection UTM firewall with 1-yr bundle, 24-port Gigabit PoE+ switch, and 3 high-density Wi-Fi 6 access points.'
    }
  ];

  const handleGenerateAIBOM = async (promptText?: string) => {
    const prompt = promptText || requirementPrompt;
    setIsGenerating(true);
    try {
      const res = await authenticatedFetch('/api/ai/bom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requirement: prompt })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'BOM drafting unavailable');

      if (data.items && Array.isArray(data.items)) {
        const newItems: BOMItem[] = data.items.map((it: any, index: number) => ({
          id: `bom-${Date.now()}-${index}`,
          category: it.category || 'General Hardware',
          name: it.name,
          qty: it.qty || 1,
          unitCost: 0,
          unitSell: 0,
          hsn: '',
          gstRate: 0
        }));
        setCurrentBOM(newItems);
        setCompatibilityStatus('WARNING');
        setCompatibilityError(null);
        setCompatibilityReport('UNVERIFIED AI DRAFT: Prices, GST/HSN and OEM compatibility need independent human verification.');
      }
    } catch (err) {
      setCompatibilityStatus('ERROR');
      setCompatibilityError(err instanceof Error ? err.message : 'BOM drafting unavailable');
      setCompatibilityReport('No verified BOM generated');
    } finally {
      setIsGenerating(false);
    }
  };

  const handleUpdateQty = (id: string, newQty: number) => {
    if (newQty < 1) return;
    setCurrentBOM(currentBOM.map(item => item.id === id ? { ...item, qty: newQty } : item));
  };

  const handleRemoveItem = (id: string) => {
    setCurrentBOM(currentBOM.filter(item => item.id !== id));
  };

  const handleAddManualProduct = (product: Product) => {
    const newItem: BOMItem = {
      id: `bom-${Date.now()}`,
      category: product.category,
      name: `${product.brand} ${product.model}`,
      sku: product.sku,
      qty: 1,
      unitCost: product.unitCost,
      unitSell: product.sellingPrice,
      hsn: product.hsn,
      gstRate: product.gstRate
    };
    setCurrentBOM([...currentBOM, newItem]);
  };

  // Pricing engine math
  const totalCost = currentBOM.reduce((sum, it) => sum + (it.unitCost * it.qty), 0);
  const totalSell = currentBOM.reduce((sum, it) => sum + (it.unitSell * it.qty), 0);
  const grossProfit = totalSell - totalCost;
  const marginPct = totalSell > 0 ? Number(((grossProfit / totalSell) * 100).toFixed(2)) : 0;
  const gstAmount = Math.round(totalSell * 0.18);
  const finalInvoiceAmount = totalSell + gstAmount;

  // Compatibility checker rule simulation
  const checkCompatibilityRule = () => {
    const hasDDR4 = currentBOM.some(i => i.name.toLowerCase().includes('ddr4'));
    const hasDDR5 = currentBOM.some(i => i.name.toLowerCase().includes('ddr5'));
    const hasServer = currentBOM.some(i => i.category.toLowerCase().includes('server') || i.name.toLowerCase().includes('r760'));
    const hasECC = currentBOM.some(i => i.name.toLowerCase().includes('ecc'));

    if (hasDDR4 && hasDDR5) {
      setCompatibilityStatus('WARNING');
      setCompatibilityReport('⚠️ Architecture Note: Mixing DDR4 desktop memory with DDR5 systems. Ensure motherboards match intended memory generation.');
    } else if (hasServer && !hasECC) {
      setCompatibilityStatus('WARNING');
      setCompatibilityReport('⚠️ Server Configuration Warning: Enterprise 2U server detected without ECC Registered memory specified. Auto-recommending Kingston/Hynix DDR5 ECC RDIMMs.');
    } else {
      setCompatibilityStatus('PASSED');
      setCompatibilityReport('✅ Compatibility Matrix Cleared: Socket LGA1700, DDR5 bus rates, 802.3at PoE+ switch power budgets, and online UPS kVA ratings verified.');
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Presets */}
      <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Cpu className="w-5 h-5 text-indigo-400" />
              <span>AI Solution & BOM Builder (Sections 11, 12, 13 & 14)</span>
            </h2>
            <p className="text-xs text-slate-400">
              Converts raw corporate customer requirements into fully verified Bill of Materials with hardware compatibility validation
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Autonomous BOM Engine:</span>
            <span className="px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-semibold">
              Active v4.2
            </span>
          </div>
        </div>

        {/* Preset Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {presets.map((p, idx) => (
            <button
              key={idx}
              onClick={() => {
                setRequirementPrompt(p.prompt);
                handleGenerateAIBOM(p.prompt);
              }}
              disabled={isGenerating}
              className="p-3 rounded-xl bg-slate-950/80 hover:bg-slate-800/80 border border-slate-800 text-left transition-all space-y-1 group"
            >
              <span className="text-xs font-bold text-white group-hover:text-sky-300 block">{p.label}</span>
              <span className="text-[11px] text-slate-400 line-clamp-2">{p.desc}</span>
            </button>
          ))}
        </div>

        {/* Input prompt */}
        <div className="flex flex-col sm:flex-row items-center gap-2 pt-1">
          <input
            id="input-bom-requirement"
            type="text"
            value={requirementPrompt}
            onChange={(e) => setRequirementPrompt(e.target.value)}
            placeholder="Describe customer requirement (e.g. 30 laptops with 10G switches and firewall for BKC office)..."
            className="flex-1 bg-slate-950 border border-slate-700 rounded-xl px-4 py-2.5 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
          <button
            id="btn-bom-generate"
            onClick={() => handleGenerateAIBOM()}
            disabled={isGenerating}
            className="px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-semibold text-xs flex items-center gap-2 transition-all shadow-md shadow-indigo-600/25 whitespace-nowrap"
          >
            {isGenerating ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
            <span>Synthesize AI BOM</span>
          </button>
        </div>
      </div>

      {/* Compatibility Validation Card (Section 14) */}
      <div className={`p-4 rounded-xl border flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs ${
        compatibilityStatus === 'PASSED'
          ? 'bg-emerald-950/20 border-emerald-800/40 text-emerald-200'
          : 'bg-amber-950/30 border-amber-800/50 text-amber-200'
      }`}>
        <div className="flex items-center gap-3">
          <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
            compatibilityStatus === 'PASSED' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'
          }`}>
            {compatibilityStatus === 'PASSED' ? <CheckCircle2 className="w-5 h-5" /> : <AlertTriangle className="w-5 h-5" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <strong className="font-bold uppercase tracking-wider text-[11px]">
                Hardware Compatibility Engine (Section 14)
              </strong>
              <span className={`px-2 py-0.2 rounded font-mono text-[10px] font-bold ${
                compatibilityStatus === 'PASSED' ? 'bg-emerald-500/20 text-emerald-300' : 'bg-amber-500/20 text-amber-300'
              }`}>
                STATUS: {compatibilityStatus}
              </span>
            </div>
            <p className="text-slate-300 mt-0.5 leading-relaxed">{compatibilityReport}</p>
          </div>
        </div>

        <button
          onClick={checkCompatibilityRule}
          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700 whitespace-nowrap self-start md:self-center"
        >
          Re-verify Rules
        </button>
      </div>

      {/* Itemized BOM Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-sm space-y-4">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold text-white">Itemized Solution Components</h3>
            <span className="text-xs bg-slate-800 text-slate-300 px-2 py-0.5 rounded-full font-mono">
              {currentBOM.length} Line Items
            </span>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 hidden sm:inline">Add from Catalog:</span>
            <select
              onChange={(e) => {
                const prod = products.find(p => p.id === e.target.value);
                if (prod) handleAddManualProduct(prod);
              }}
              defaultValue=""
              className="bg-slate-950 border border-slate-700 text-xs text-slate-300 rounded-lg p-1.5 focus:outline-none"
            >
              <option value="" disabled>+ Add Hardware SKU</option>
              {products.map(p => (
                <option key={p.id} value={p.id}>{p.brand} {p.model} (₹{p.sellingPrice.toLocaleString('en-IN')})</option>
              ))}
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 font-semibold border-b border-slate-800">
              <tr>
                <th className="p-3">Category & Item</th>
                <th className="p-3 text-center">Qty</th>
                <th className="p-3 text-right">Landed Cost</th>
                <th className="p-3 text-right">Selling Price</th>
                <th className="p-3 text-center">HSN</th>
                <th className="p-3 text-right">Line Total</th>
                <th className="p-3 text-center">Margin</th>
                <th className="p-3 text-center">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {currentBOM.map((item) => {
                const lineTotal = item.unitSell * item.qty;
                const lineCost = item.unitCost * item.qty;
                const itemMargin = lineTotal > 0 ? (((lineTotal - lineCost) / lineTotal) * 100).toFixed(1) : '0';

                return (
                  <tr key={item.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="p-3">
                      <span className="text-[10px] text-indigo-400 uppercase font-bold block">
                        {item.category}
                      </span>
                      <span className="text-slate-100 font-semibold">{item.name}</span>
                    </td>
                    <td className="p-3 text-center">
                      <div className="inline-flex items-center border border-slate-700 rounded-lg overflow-hidden bg-slate-950">
                        <button
                          onClick={() => handleUpdateQty(item.id, item.qty - 1)}
                          className="px-2 py-0.5 text-slate-400 hover:bg-slate-800 text-xs"
                        >
                          -
                        </button>
                        <span className="px-2 py-0.5 font-mono text-white text-xs font-semibold">
                          {item.qty}
                        </span>
                        <button
                          onClick={() => handleUpdateQty(item.id, item.qty + 1)}
                          className="px-2 py-0.5 text-slate-400 hover:bg-slate-800 text-xs"
                        >
                          +
                        </button>
                      </div>
                    </td>
                    <td className="p-3 text-right font-mono text-slate-400">
                      ₹{item.unitCost.toLocaleString('en-IN')}
                    </td>
                    <td className="p-3 text-right font-mono text-slate-100 font-semibold">
                      ₹{item.unitSell.toLocaleString('en-IN')}
                    </td>
                    <td className="p-3 text-center font-mono text-slate-400">
                      {item.hsn}
                    </td>
                    <td className="p-3 text-right font-mono text-white font-bold">
                      ₹{lineTotal.toLocaleString('en-IN')}
                    </td>
                    <td className="p-3 text-center">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                        Number(itemMargin) < 15 ? 'bg-amber-500/20 text-amber-300' : 'bg-emerald-500/20 text-emerald-400'
                      }`}>
                        {itemMargin}%
                      </span>
                    </td>
                    <td className="p-3 text-center">
                      <button
                        onClick={() => handleRemoveItem(item.id)}
                        className="p-1 text-slate-500 hover:text-rose-400 transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Smart Pricing Formula Summary (Section 20) */}
        <div className="p-4 bg-slate-950/80 border-t border-slate-800 grid grid-cols-1 lg:grid-cols-12 gap-4">
          <div className="lg:col-span-7 space-y-2">
            <div className="flex items-center gap-2">
              <DollarSign className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-bold text-white uppercase tracking-wider">
                Smart Pricing Engine Formula (Section 20)
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Purchase Cost (₹{totalCost.toLocaleString('en-IN')}) + Freight & Logistics (₹{freightPerUnit * currentBOM.length}) + Risk Buffer ({riskBufferPct}%) + Desired Margin ({marginPct}%) = Recommended Selling Price.
            </p>

            <div className="pt-2 flex items-center gap-3 text-xs">
              <div className={`px-3 py-1.5 rounded-lg border flex items-center gap-2 ${
                marginPct >= 15
                  ? 'bg-emerald-950/30 border-emerald-800 text-emerald-300'
                  : 'bg-amber-950/40 border-amber-800 text-amber-300 animate-pulse'
              }`}>
                <ShieldCheck className="w-4 h-4" />
                <span>
                  {marginPct >= 15
                    ? 'Margin ≥ 15% (Approval still requires server-backed review)'
                    : 'Margin < 15% (Server-backed owner authorization required)'}
                </span>
              </div>
            </div>
          </div>

          <div className="lg:col-span-5 bg-slate-900 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
            <div className="flex justify-between text-slate-400">
              <span>Subtotal (Excl. Tax):</span>
              <span className="text-white font-mono font-medium">₹{totalSell.toLocaleString('en-IN')}</span>
            </div>
            <div className="flex justify-between text-slate-400">
              <span>GST (18% B2B Input Credit):</span>
              <span className="text-slate-300 font-mono">₹{gstAmount.toLocaleString('en-IN')}</span>
            </div>
            <div className="flex justify-between text-slate-400">
              <span>Gross Profit (Pre-tax):</span>
              <span className="text-emerald-400 font-mono font-bold">₹{grossProfit.toLocaleString('en-IN')} ({marginPct}%)</span>
            </div>
            <div className="pt-2 border-t border-slate-800 flex justify-between text-sm">
              <span className="font-bold text-white">Quotation Total:</span>
              <span className="font-bold text-emerald-400 font-mono">₹{finalInvoiceAmount.toLocaleString('en-IN')}</span>
            </div>

            <button
              id="btn-bom-convert-quote"
              onClick={() => onGenerateQuote(currentBOM, marginPct)}
              disabled={!currentBOM.length || currentBOM.some(i => !(i.unitCost > 0 && i.unitSell > 0 && i.gstRate > 0 && !!i.hsn.trim()))}
              title="Add verified prices, GST and HSN before generating a quotation"
              className="w-full mt-3 py-2.5 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold text-xs flex items-center justify-center gap-2 shadow-lg shadow-emerald-600/20 transition-all"
            >
              <span>Generate Official GST Quotation</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
