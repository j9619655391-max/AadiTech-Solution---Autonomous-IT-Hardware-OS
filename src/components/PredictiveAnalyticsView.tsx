import React, { useState } from 'react';
import {
  TrendingUp,
  AlertTriangle,
  PackageX,
  Target,
  Send,
  CheckCircle2,
  Calendar,
  Sparkles,
  Search,
  Filter,
  ArrowUpRight,
  ShieldCheck,
  Building2,
  Clock,
  Layers,
  ChevronRight
} from 'lucide-react';
import {
  DeadStockItem,
  DemandForecast,
  SalesForecastSummary,
  CashFlowForecastItem,
  NextBestAction,
  LostDealAnalysis,
  CustomerLTVAnalysis
} from '../types';

interface PredictiveAnalyticsViewProps {
  deadStock: DeadStockItem[];
  onUpdateDeadStock: (items: DeadStockItem[]) => void;
  demandForecasts: DemandForecast[];
  onUpdateDemandForecasts: (forecasts: DemandForecast[]) => void;
  salesForecast: SalesForecastSummary;
  cashFlowForecast: CashFlowForecastItem[];
  nextBestActions: NextBestAction[];
  onTriggerAction: (actionId: string) => void;
  lostDeals: LostDealAnalysis[];
  customerLTVs: CustomerLTVAnalysis[];
  formatINR: (amount: number) => string;
}

export const PredictiveAnalyticsView: React.FC<PredictiveAnalyticsViewProps> = ({
  deadStock,
  onUpdateDeadStock,
  demandForecasts,
  salesForecast,
  cashFlowForecast,
  nextBestActions,
  onTriggerAction,
  lostDeals,
  customerLTVs,
  formatINR
}) => {
  const [activeTab, setActiveTab] = useState<'FORECAST' | 'DEAD_STOCK' | 'ACTIONS' | 'WIN_LOSS' | 'LTV'>('FORECAST');
  const [selectedHorizon, setSelectedHorizon] = useState<string>('ALL');
  const [deadStockSearch, setDeadStockSearch] = useState('');
  const [actionSuccessMsg, setActionSuccessMsg] = useState<string | null>(null);

  const totalDeadStockValue = deadStock.reduce((acc, item) => acc + item.totalBookValue, 0);
  const totalHoldingCost = deadStock.reduce((acc, item) => acc + item.monthlyHoldingCost, 0);

  const handleLiquidate = (id: string, actionType: string) => {
    const updated = deadStock.map(item => {
      if (item.id === id) {
        return {
          ...item,
          status: 'LIQUIDATED' as const,
          recommendationNote: `${item.recommendationNote} [Executed: ${actionType} at ${new Date().toLocaleTimeString()}]`
        };
      }
      return item;
    });
    onUpdateDeadStock(updated);
    setActionSuccessMsg(`Liquidation order initiated for item ${id}. Channel discount dispatched.`);
    setTimeout(() => setActionSuccessMsg(null), 4000);
  };

  const handleActionClick = (id: string, title: string) => {
    onTriggerAction(id);
    setActionSuccessMsg(`Autonomous action executed: "${title}". Notification dispatched via suggested channel.`);
    setTimeout(() => setActionSuccessMsg(null), 4000);
  };

  const filteredDemandForecasts = selectedHorizon === 'ALL'
    ? demandForecasts
    : demandForecasts.filter(df => df.timeHorizon === selectedHorizon);

  const filteredDeadStock = deadStock.filter(item =>
    item.productName.toLowerCase().includes(deadStockSearch.toLowerCase()) ||
    item.sku.toLowerCase().includes(deadStockSearch.toLowerCase()) ||
    item.warehouse.toLowerCase().includes(deadStockSearch.toLowerCase())
  );

  return (
    <div id="predictive-analytics-container" className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 text-white shadow-sm">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-indigo-500/20 text-indigo-400 rounded-lg border border-indigo-500/30">
              <TrendingUp className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-slate-100">Predictive Intelligence & Forecasting</h1>
              <p className="text-xs text-slate-400">
                Hardware demand simulation, dead stock liquidation, cash runway modeling, and AI next-best actions.
              </p>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center flex-wrap gap-1.5 bg-slate-800/80 p-1.5 rounded-lg border border-slate-700/60">
          <button
            id="tab-btn-forecast"
            onClick={() => setActiveTab('FORECAST')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors ${
              activeTab === 'FORECAST'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-slate-300 hover:text-white hover:bg-slate-700/60'
            }`}
          >
            Demand & Cash Flow
          </button>
          <button
            id="tab-btn-deadstock"
            onClick={() => setActiveTab('DEAD_STOCK')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors flex items-center gap-1.5 ${
              activeTab === 'DEAD_STOCK'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-slate-300 hover:text-white hover:bg-slate-700/60'
            }`}
          >
            <span>Dead Stock Engine</span>
            {deadStock.filter(i => i.status === 'PENDING_ACTION').length > 0 && (
              <span className="w-2 h-2 rounded-full bg-rose-400 animate-pulse"></span>
            )}
          </button>
          <button
            id="tab-btn-actions"
            onClick={() => setActiveTab('ACTIONS')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors flex items-center gap-1.5 ${
              activeTab === 'ACTIONS'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-slate-300 hover:text-white hover:bg-slate-700/60'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span>Next-Best Actions</span>
          </button>
          <button
            id="tab-btn-winloss"
            onClick={() => setActiveTab('WIN_LOSS')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors ${
              activeTab === 'WIN_LOSS'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-slate-300 hover:text-white hover:bg-slate-700/60'
            }`}
          >
            Win/Loss Post-Mortem
          </button>
          <button
            id="tab-btn-ltv"
            onClick={() => setActiveTab('LTV')}
            className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors ${
              activeTab === 'LTV'
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'text-slate-300 hover:text-white hover:bg-slate-700/60'
            }`}
          >
            Customer LTV & Growth
          </button>
        </div>
      </div>

      {/* Action Success Toast */}
      {actionSuccessMsg && (
        <div className="flex items-center gap-2 p-3.5 bg-emerald-950/80 border border-emerald-700/60 text-emerald-200 rounded-lg text-xs animate-fadeIn">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{actionSuccessMsg}</span>
        </div>
      )}

      {/* TAB 1: DEMAND & CASH FLOW FORECASTING */}
      {activeTab === 'FORECAST' && (
        <div className="space-y-6">
          {/* Top 4 KPI Metrics */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
              <div className="flex items-center justify-between text-slate-500 mb-1">
                <span className="text-xs font-medium uppercase tracking-wider">Gross Pipeline Value</span>
                <TrendingUp className="w-4 h-4 text-indigo-600" />
              </div>
              <div className="text-xl font-bold text-slate-900">{formatINR(salesForecast.grossPipelineValue)}</div>
              <div className="text-xs text-slate-500 mt-1">
                {salesForecast.pipelineDealsCount} qualified hardware deals in pipeline
              </div>
            </div>

            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
              <div className="flex items-center justify-between text-slate-500 mb-1">
                <span className="text-xs font-medium uppercase tracking-wider">Projected 30D Revenue</span>
                <Target className="w-4 h-4 text-emerald-600" />
              </div>
              <div className="text-xl font-bold text-emerald-700">{formatINR(salesForecast.weightedProjectedRevenue)}</div>
              <div className="text-xs text-slate-500 mt-1">
                Weighted by win probability ({salesForecast.historicalWinRatePct}% win rate)
              </div>
            </div>

            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
              <div className="flex items-center justify-between text-slate-500 mb-1">
                <span className="text-xs font-medium uppercase tracking-wider">Projected Gross Profit</span>
                <ShieldCheck className="w-4 h-4 text-blue-600" />
              </div>
              <div className="text-xl font-bold text-blue-700">{formatINR(salesForecast.projectedGrossProfit)}</div>
              <div className="text-xs text-slate-500 mt-1">
                Blended margin: <span className="font-semibold text-slate-700">{salesForecast.projectedMarginPct}%</span> (Above 15% threshold)
              </div>
            </div>

            <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
              <div className="flex items-center justify-between text-slate-500 mb-1">
                <span className="text-xs font-medium uppercase tracking-wider">Dead Stock Capital Locked</span>
                <PackageX className="w-4 h-4 text-amber-600" />
              </div>
              <div className="text-xl font-bold text-amber-700">{formatINR(totalDeadStockValue)}</div>
              <div className="text-xs text-slate-500 mt-1">
                Monthly carrying cost: {formatINR(totalHoldingCost)}
              </div>
            </div>
          </div>

          {/* Demand Forecasting Engine Section */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-4 border-b border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-50/70">
              <div>
                <h2 className="text-sm font-bold text-slate-800 flex items-center gap-2">
                  <Layers className="w-4 h-4 text-indigo-600" />
                  Hardware Category Demand Prediction & Reorder Advisor
                </h2>
                <p className="text-xs text-slate-500">
                  Calculated against seasonal enterprise refresh cycles, pipeline quotes, and distributor lead times.
                </p>
              </div>

              {/* Horizon Filter */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-500 font-medium">Time Horizon:</span>
                <select
                  value={selectedHorizon}
                  onChange={(e) => setSelectedHorizon(e.target.value)}
                  className="text-xs bg-white border border-slate-300 rounded-lg px-2.5 py-1.5 text-slate-700 font-medium focus:outline-none focus:ring-1 focus:ring-indigo-500"
                >
                  <option value="ALL">All Horizons (7D - 60D)</option>
                  <option value="7_DAYS">Next 7 Days</option>
                  <option value="14_DAYS">Next 14 Days</option>
                  <option value="30_DAYS">Next 30 Days</option>
                  <option value="60_DAYS">Next 60 Days</option>
                </select>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 text-slate-600 font-semibold border-b border-slate-200">
                  <tr>
                    <th className="py-3 px-4">Hardware Category</th>
                    <th className="py-3 px-4">Horizon</th>
                    <th className="py-3 px-4 text-center">Available Stock</th>
                    <th className="py-3 px-4 text-center">Pipeline Demand</th>
                    <th className="py-3 px-4 text-center">AI Projected Run-rate</th>
                    <th className="py-3 px-4 text-center">Recommended PO</th>
                    <th className="py-3 px-4">Stockout Risk</th>
                    <th className="py-3 px-4">Key Driver / Demand Trigger</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredDemandForecasts.map((df) => (
                    <tr key={df.id} className="hover:bg-slate-50/80 transition-colors">
                      <td className="py-3.5 px-4 font-semibold text-slate-800">
                        {df.category.replace(/_/g, ' ')}
                      </td>
                      <td className="py-3.5 px-4">
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-slate-100 text-slate-700">
                          {df.timeHorizon.replace(/_/g, ' ')}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-center font-medium text-slate-700">
                        {df.currentAvailableStock} units
                      </td>
                      <td className="py-3.5 px-4 text-center font-medium text-slate-700">
                        {df.pipelineDemand} units
                      </td>
                      <td className="py-3.5 px-4 text-center font-bold text-slate-900">
                        {df.predictedUnits} units
                      </td>
                      <td className="py-3.5 px-4 text-center">
                        <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-bold bg-indigo-50 text-indigo-700 border border-indigo-200">
                          +{df.recommendedOrderUnits} units
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        {df.urgency === 'HIGH_STOCKOUT_RISK' ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-rose-50 text-rose-700 border border-rose-200">
                            <AlertTriangle className="w-3 h-3 text-rose-500" />
                            Stockout Risk
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
                            <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                            Normal Buffer
                          </span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-slate-600 max-w-xs">
                        {df.keyDriver}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Cash Flow Forecast Table */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-4 border-b border-slate-100 bg-slate-50/70">
              <h2 className="text-sm font-bold text-slate-800 flex items-center gap-2">
                <Clock className="w-4 h-4 text-blue-600" />
                Autonomous Cash Flow & Working Capital Forecast (Next 4 Months)
              </h2>
              <p className="text-xs text-slate-500">
                Synchronized with customer payment terms (30D/60D PDC), distributor credit cycles (Savex/Ingram), and GST compliance liabilities.
              </p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 text-slate-600 font-semibold border-b border-slate-200">
                  <tr>
                    <th className="py-3 px-4">Month</th>
                    <th className="py-3 px-4 text-right">Debtor Collections</th>
                    <th className="py-3 px-4 text-right">Supplier Payables</th>
                    <th className="py-3 px-4 text-right">Operating Expenses</th>
                    <th className="py-3 px-4 text-right">Est. GST Liability</th>
                    <th className="py-3 px-4 text-right font-bold text-slate-900">Net Cash Flow</th>
                    <th className="py-3 px-4 text-right font-bold text-slate-900">Projected Closing Balance</th>
                    <th className="py-3 px-4 text-center">Runway Health</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {cashFlowForecast.map((cf, idx) => (
                    <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                      <td className="py-3 px-4 font-bold text-slate-800">
                        {cf.month}
                      </td>
                      <td className="py-3 px-4 text-right text-emerald-700 font-medium">
                        +{formatINR(cf.expectedCollections)}
                      </td>
                      <td className="py-3 px-4 text-right text-rose-600 font-medium">
                        -{formatINR(cf.supplierPayables)}
                      </td>
                      <td className="py-3 px-4 text-right text-slate-600">
                        -{formatINR(cf.operatingExpenses)}
                      </td>
                      <td className="py-3 px-4 text-right text-amber-700">
                        -{formatINR(cf.gstPayableEstimate)}
                      </td>
                      <td className="py-3 px-4 text-right font-bold text-indigo-700">
                        {formatINR(cf.netCashFlow)}
                      </td>
                      <td className="py-3 px-4 text-right font-bold text-slate-900">
                        {formatINR(cf.projectedClosingBalance)}
                      </td>
                      <td className="py-3 px-4 text-center">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold ${
                          cf.runwayStatus === 'OPTIMAL'
                            ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                            : 'bg-amber-50 text-amber-700 border border-amber-200'
                        }`}>
                          {cf.runwayStatus.replace(/_/g, ' ')}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: DEAD STOCK LIQUIDATION ENGINE */}
      {activeTab === 'DEAD_STOCK' && (
        <div className="space-y-5">
          {/* Summary Strip */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-amber-50/60 border border-amber-200 rounded-xl p-4">
              <div className="text-xs font-semibold text-amber-800 uppercase tracking-wider">Aged Inventory (&gt;90 Days)</div>
              <div className="text-xl font-bold text-amber-950 mt-1">{deadStock.length} SKUs Identified</div>
              <p className="text-xs text-amber-700 mt-1">Requires immediate liquidation or zero-markup bundling.</p>
            </div>

            <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
              <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Total Book Value Locked</div>
              <div className="text-xl font-bold text-slate-900 mt-1">{formatINR(totalDeadStockValue)}</div>
              <p className="text-xs text-slate-500 mt-1">Estimated recovery value: {formatINR(deadStock.reduce((a, b) => a + b.estimatedMarketValue, 0))}</p>
            </div>

            <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
              <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Monthly Capital Holding Drain</div>
              <div className="text-xl font-bold text-rose-600 mt-1">{formatINR(totalHoldingCost)} / mo</div>
              <p className="text-xs text-slate-500 mt-1">Warehouse footprint, insurance, and technological depreciation.</p>
            </div>
          </div>

          {/* Search Bar */}
          <div className="flex items-center gap-3 bg-white p-3 rounded-xl border border-slate-200 shadow-sm">
            <Search className="w-4 h-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search by product name, SKU, or warehouse location..."
              value={deadStockSearch}
              onChange={(e) => setDeadStockSearch(e.target.value)}
              className="w-full text-xs text-slate-800 placeholder-slate-400 focus:outline-none"
            />
          </div>

          {/* Dead Stock Cards */}
          <div className="grid grid-cols-1 gap-4">
            {filteredDeadStock.map((item) => (
              <div
                key={item.id}
                className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm hover:border-indigo-300 transition-colors"
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                  <div className="space-y-1.5 flex-1">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <span className="font-mono text-xs font-bold text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded border border-indigo-200">
                        {item.sku}
                      </span>
                      <h3 className="text-sm font-bold text-slate-900">{item.productName}</h3>
                      <span className="text-[11px] font-semibold text-rose-700 bg-rose-50 px-2 py-0.5 rounded border border-rose-200 flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {item.ageDays} Days in Warehouse
                      </span>
                      <span className="text-[11px] text-slate-500">
                        Location: <span className="font-semibold text-slate-700">{item.warehouse}</span>
                      </span>
                    </div>

                    <div className="flex items-center gap-4 text-xs text-slate-600 pt-1">
                      <div>Quantity: <span className="font-bold text-slate-900">{item.qty} units</span></div>
                      <div>Unit Book Cost: <span className="font-semibold text-slate-800">{formatINR(item.unitBookCost)}</span></div>
                      <div>Total Book Value: <span className="font-bold text-slate-900">{formatINR(item.totalBookValue)}</span></div>
                      <div>Monthly Drain: <span className="font-medium text-rose-600">-{formatINR(item.monthlyHoldingCost)}/mo</span></div>
                    </div>

                    {/* AI Recommendation Box */}
                    <div className="bg-amber-50/70 border border-amber-200 rounded-lg p-3 mt-2 text-xs">
                      <div className="flex items-center gap-1.5 font-bold text-amber-900 mb-0.5">
                        <Sparkles className="w-3.5 h-3.5 text-amber-600" />
                        AI Liquidation Strategy: {item.aiRecommendation.replace(/_/g, ' ')}
                      </div>
                      <p className="text-amber-800 leading-relaxed">{item.recommendationNote}</p>
                    </div>
                  </div>

                  {/* Actions Column */}
                  <div className="flex flex-row lg:flex-col items-center lg:items-end gap-2 shrink-0">
                    {item.status === 'LIQUIDATED' ? (
                      <span className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">
                        <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                        Offer Executed
                      </span>
                    ) : (
                      <>
                        <button
                          onClick={() => handleLiquidate(item.id, '25% Special Promo Liquidation')}
                          className="px-3.5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold shadow-sm transition-colors flex items-center gap-1.5"
                        >
                          <Send className="w-3.5 h-3.5" />
                          <span>Dispatch Liquidation Offer</span>
                        </button>
                        <button
                          onClick={() => handleLiquidate(item.id, 'Bundle at Zero Margin with Server Quotes')}
                          className="px-3.5 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg text-xs font-medium transition-colors"
                        >
                          Bundle with Server BOM
                        </button>
                      </>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 3: AI NEXT-BEST ACTIONS */}
      {activeTab === 'ACTIONS' && (
        <div className="space-y-4">
          <div className="p-4 bg-indigo-950 text-white rounded-xl border border-indigo-900 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-amber-400" />
                <h2 className="text-sm font-bold tracking-tight">Autonomous Revenue Next-Best Actions</h2>
              </div>
              <p className="text-xs text-indigo-200 mt-1">
                Real-time decision engine analyzing lead engagement, quote stalling, and expiring warranties to trigger revenue captures.
              </p>
            </div>
            <div className="text-xs bg-indigo-800/80 px-3 py-1.5 rounded-lg text-indigo-100 font-medium">
              4 high-impact triggers available
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {nextBestActions.map((nba) => (
              <div
                key={nba.id}
                className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm hover:shadow-md transition-shadow flex flex-col justify-between"
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase tracking-wider ${
                      nba.priority === 'URGENT'
                        ? 'bg-rose-100 text-rose-800 border border-rose-200'
                        : nba.priority === 'HIGH'
                        ? 'bg-amber-100 text-amber-800 border border-amber-200'
                        : 'bg-blue-100 text-blue-800 border border-blue-200'
                    }`}>
                      {nba.priority} Priority
                    </span>

                    <span className="text-xs font-bold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                      Impact: +{formatINR(nba.projectedRevenueImpact)}
                    </span>
                  </div>

                  <div>
                    <div className="text-[11px] font-medium text-slate-500 uppercase tracking-wider">
                      {nba.entityType}: <span className="font-semibold text-slate-800">{nba.entityName}</span>
                    </div>
                    <h3 className="text-sm font-bold text-slate-900 mt-0.5">{nba.actionTitle}</h3>
                  </div>

                  <p className="text-xs text-slate-600 leading-relaxed bg-slate-50 p-2.5 rounded-lg border border-slate-100">
                    {nba.rationale}
                  </p>
                </div>

                <div className="pt-4 border-t border-slate-100 flex items-center justify-between mt-3">
                  <div className="flex items-center gap-1.5 text-xs text-slate-500">
                    <span>Channel:</span>
                    <span className="font-semibold text-slate-800">{nba.suggestedChannel}</span>
                  </div>

                  {nba.status === 'TRIGGERED' ? (
                    <span className="inline-flex items-center gap-1 text-xs font-bold text-emerald-700 bg-emerald-50 px-2.5 py-1 rounded-md border border-emerald-200">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                      Triggered
                    </span>
                  ) : (
                    <button
                      onClick={() => handleActionClick(nba.id, nba.actionTitle)}
                      className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold shadow-sm transition-colors flex items-center gap-1.5"
                    >
                      <Send className="w-3 h-3" />
                      <span>Execute Action</span>
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 4: WIN/LOSS POST-MORTEM ANALYTICS */}
      {activeTab === 'WIN_LOSS' && (
        <div className="space-y-4">
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
            <h2 className="text-sm font-bold text-slate-900 mb-1">Commercial Win/Loss Post-Mortem & Intelligence</h2>
            <p className="text-xs text-slate-500">
              Analysis of lost enterprise opportunities, competitor displacement tactics, and systemic margin or lead-time corrective actions.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-4">
            {lostDeals.map((ld) => (
              <div key={ld.id} className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-3">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-100 pb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-slate-700 bg-slate-100 px-2 py-0.5 rounded">
                        {ld.dealNumber}
                      </span>
                      <h3 className="text-sm font-bold text-slate-900">{ld.customerName}</h3>
                    </div>
                    <div className="text-xs text-slate-500 mt-0.5">
                      Requested: <span className="font-medium text-slate-700">{ld.productRequested}</span>
                    </div>
                  </div>

                  <div className="text-right">
                    <div className="text-sm font-bold text-slate-900">{formatINR(ld.dealValue)}</div>
                    <div className="text-[11px] text-slate-400">Date: {ld.lossDate}</div>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div className="bg-rose-50/60 border border-rose-200 rounded-lg p-3">
                    <div className="font-bold text-rose-900 flex items-center gap-1.5 mb-1">
                      <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />
                      Primary Loss Cause: {ld.primaryLossReason.replace(/_/g, ' ')}
                    </div>
                    {ld.competitorWinner && (
                      <div className="text-slate-700 font-medium mb-1">
                        Displaced By: <span className="font-bold text-slate-900">{ld.competitorWinner}</span>
                      </div>
                    )}
                    <p className="text-slate-600 leading-relaxed">{ld.aiPostMortemInsight}</p>
                  </div>

                  <div className="bg-emerald-50/60 border border-emerald-200 rounded-lg p-3">
                    <div className="font-bold text-emerald-900 flex items-center gap-1.5 mb-1">
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
                      Systemic Corrective Strategy
                    </div>
                    <p className="text-slate-700 leading-relaxed font-medium">{ld.correctiveStrategy}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 5: CUSTOMER LTV & ACCOUNT EXPANSION */}
      {activeTab === 'LTV' && (
        <div className="space-y-4">
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm">
            <h2 className="text-sm font-bold text-slate-900 mb-1">Enterprise Customer Lifetime Value (LTV) Roadmap</h2>
            <p className="text-xs text-slate-500">
              Expansion pathways from initial box-drop procurement to multi-year AMC contracts, turnkey power storage, and hybrid cloud management.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-4">
            {customerLTVs.map((ltv) => (
              <div key={ltv.id} className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-3">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-100 pb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <Building2 className="w-4 h-4 text-indigo-600" />
                      <h3 className="text-sm font-bold text-slate-900">{ltv.customerName}</h3>
                      <span className="text-[11px] font-medium bg-slate-100 text-slate-600 px-2 py-0.5 rounded">
                        {ltv.industry}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 text-xs">
                    <div>
                      <span className="text-slate-500">Current Spend: </span>
                      <span className="font-bold text-slate-900">{formatINR(ltv.currentLifetimeSpend)}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Projected 3-Year LTV: </span>
                      <span className="font-bold text-indigo-700">{formatINR(ltv.projected3YearLTV)}</span>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      ltv.retentionRisk === 'LOW'
                        ? 'bg-emerald-100 text-emerald-800'
                        : 'bg-amber-100 text-amber-800'
                    }`}>
                      Risk: {ltv.retentionRisk}
                    </span>
                  </div>
                </div>

                <div>
                  <div className="text-xs font-bold text-slate-800 mb-2">Identified Expansion Pipelines:</div>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                    {ltv.expansionOpportunities.map((opp, i) => (
                      <div key={i} className="bg-slate-50 border border-slate-200 rounded-lg p-2.5 text-xs flex flex-col justify-between">
                        <div>
                          <div className="font-semibold text-slate-900">{opp.opportunityName}</div>
                          <div className="text-emerald-700 font-bold mt-1">+{formatINR(opp.potentialValue)}</div>
                        </div>
                        <div className="mt-2 pt-1 border-t border-slate-200 flex items-center justify-between text-[11px] text-slate-500">
                          <span>Readiness:</span>
                          <span className="font-medium text-slate-700">{opp.readiness.replace(/_/g, ' ')}</span>
                        </div>
                      </div>
                    ))}
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
