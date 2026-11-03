import React, { useState } from 'react';
import {
  Package,
  Layers,
  Building,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Truck,
  FileSpreadsheet,
  ArrowRight,
  ShieldCheck,
  TrendingUp,
  RefreshCw,
  Sparkles,
  Barcode,
  Plus,
  ShoppingBag,
  FileText,
  Clock,
  Send
} from 'lucide-react';
import { Product, Supplier, RFQ, SerialInventory, PurchaseOrder } from '../types';

interface ProcurementAndInventoryProps {
  products: Product[];
  suppliers: Supplier[];
  rfqs: RFQ[];
  inventory: SerialInventory[];
  purchaseOrders?: PurchaseOrder[];
  onRaisePO: (rfqId: string, supplierId: string) => void;
  onAddProduct?: (product: Product) => void;
  onAddInventoryItem?: (item: SerialInventory) => void;
  onAddRFQ?: (rfq: RFQ) => void;
}

export const ProcurementAndInventory: React.FC<ProcurementAndInventoryProps> = ({
  products,
  suppliers,
  rfqs,
  inventory,
  purchaseOrders = [],
  onRaisePO,
  onAddProduct,
  onAddInventoryItem,
  onAddRFQ
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'INVENTORY' | 'CATALOG' | 'RFQ' | 'PURCHASE_ORDERS' | 'DEAD_STOCK' | 'SUPPLIERS'>('INVENTORY');
  const [selectedWarehouse, setSelectedWarehouse] = useState<string>('ALL');
  
  // Modals state
  const [showAddProductModal, setShowAddProductModal] = useState(false);
  const [showAddSerialModal, setShowAddSerialModal] = useState(false);
  const [showCreateRFQModal, setShowCreateRFQModal] = useState(false);

  // Form states
  const [newProductForm, setNewProductForm] = useState({
    sku: '',
    name: '',
    brand: 'AadiTech',
    category: 'Turnkey Power Systems',
    model: '',
    specs: '',
    unitCost: 25000,
    unitSell: 32000,
    hsn: '8504',
    gstRate: 18,
    stockBhiwandi: 5,
    stockDelhi: 2,
    stockBangalore: 1
  });

  const [newSerialForm, setNewSerialForm] = useState({
    serialNumber: '',
    sku: products[0]?.sku || 'ADT-PSU-500W',
    productName: products[0]?.name || 'AadiTech Hi-REL 500W DC-DC Converter',
    warehouse: 'BHIWANDI_HUB' as 'BHIWANDI_HUB' | 'DELHI_OKHLA' | 'BANGALORE_ECITY',
    binLocation: 'A-01-01',
    cost: 25000,
    supplierName: 'Direct AadiTech Facility'
  });

  const [newRFQForm, setNewRFQForm] = useState({
    productName: '',
    category: 'Enterprise Hardware',
    qty: 10,
    targetPrice: 45000,
    requiredByDate: 'Within 7 Days'
  });

  const filteredInventory = inventory.filter((item) => {
    if (selectedWarehouse === 'ALL') return true;
    return item.warehouse === selectedWarehouse;
  });

  const deadStockItems = inventory.filter(item => item.isDeadStock || item.ageDays > 90);

  const handleCreateProduct = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newProductForm.name || !newProductForm.sku) return;

    const prod: Product = {
      id: `PROD-${Date.now()}`,
      sku: newProductForm.sku.toUpperCase(),
      brand: newProductForm.brand || 'AadiTech',
      category: 'POWER_STORAGE',
      model: newProductForm.model || newProductForm.name || newProductForm.sku,
      specs: newProductForm.specs || 'Enterprise Grade Hardware Solution',
      unitCost: Number(newProductForm.unitCost),
      freightCost: 800,
      riskBuffer: 1200,
      landedCost: Number(newProductForm.unitCost) + 2000,
      sellingPrice: Number(newProductForm.unitSell),
      minPrice: Math.round(Number(newProductForm.unitCost) * 1.1),
      targetMarginPct: Math.round(((Number(newProductForm.unitSell) - Number(newProductForm.unitCost)) / Number(newProductForm.unitSell)) * 100),
      gstRate: Number(newProductForm.gstRate) || 18,
      hsn: newProductForm.hsn || '8504',
      warrantyMonths: 36,
      stockBhiwandi: Number(newProductForm.stockBhiwandi) || 0,
      stockDelhi: Number(newProductForm.stockDelhi) || 0,
      stockBangalore: Number(newProductForm.stockBangalore) || 0,
      reservedStock: 0,
      leadTimeDays: 3
    };

    if (onAddProduct) {
      onAddProduct(prod);
    }
    setShowAddProductModal(false);
    setNewProductForm({
      sku: '',
      name: '',
      brand: 'AadiTech',
      category: 'Turnkey Power Systems',
      model: '',
      specs: '',
      unitCost: 25000,
      unitSell: 32000,
      hsn: '8504',
      gstRate: 18,
      stockBhiwandi: 5,
      stockDelhi: 2,
      stockBangalore: 1
    });
  };

  const handleCreateSerial = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSerialForm.serialNumber) return;

    const item: SerialInventory = {
      id: `SN-${Date.now()}`,
      serialNumber: newSerialForm.serialNumber.toUpperCase(),
      sku: newSerialForm.sku,
      productName: newSerialForm.productName,
      warehouse: newSerialForm.warehouse,
      binLocation: newSerialForm.binLocation,
      cost: Number(newSerialForm.cost),
      supplier: newSerialForm.supplierName,
      ageDays: 1,
      state: 'AVAILABLE',
      isDeadStock: false
    };

    if (onAddInventoryItem) {
      onAddInventoryItem(item);
    }
    setShowAddSerialModal(false);
    setNewSerialForm({
      serialNumber: '',
      sku: products[0]?.sku || 'ADT-PSU-500W',
      productName: products[0]?.model ? `${products[0].brand} ${products[0].model}` : 'AadiTech Hi-REL 500W DC-DC Converter',
      warehouse: 'BHIWANDI_HUB',
      binLocation: 'A-01-01',
      cost: 25000,
      supplierName: 'Direct AadiTech Facility'
    });
  };

  const handleCreateRFQ = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRFQForm.productName) return;

    const newRfq: RFQ = {
      id: `RFQ-${Date.now()}`,
      rfqNumber: `RFQ-2026-${Math.floor(100 + Math.random() * 900)}`,
      productName: newRFQForm.productName,
      qty: Number(newRFQForm.qty),
      targetPrice: Number(newRFQForm.targetPrice),
      requiredByDate: newRFQForm.requiredByDate,
      status: 'OPEN',
      quotes: suppliers.slice(0, 3).map((sup, idx) => ({
        supplierId: sup.id,
        supplierName: sup.name,
        pricePerUnit: Math.round(newRFQForm.targetPrice * (0.95 + idx * 0.04)),
        deliveryDays: 2 + idx * 2,
        warrantyYears: 3,
        availability: 'IN_STOCK' as const,
        reliabilityScore: Math.round(92 - idx * 5),
        aiRecommended: idx === 0
      }))
    };

    if (onAddRFQ) {
      onAddRFQ(newRfq);
    }
    setShowCreateRFQModal(false);
    setNewRFQForm({
      productName: '',
      category: 'Enterprise Hardware',
      qty: 10,
      targetPrice: 45000,
      requiredByDate: 'Within 7 Days'
    });
  };

  return (
    <div className="space-y-6">
      {/* Top action header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Package className="w-5 h-5 text-cyan-400" />
            <span>Procurement, RFQ & Multi-Warehouse Hub (Sections 15–19 & 54)</span>
          </h2>
          <p className="text-xs text-slate-400">
            Multi-hub serialized inventory, automated supplier RFQ comparisons, and dead stock liquidation
          </p>
        </div>

        {/* Sub-tab pills */}
        <div className="flex flex-wrap items-center gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs">
          <button
            onClick={() => setActiveSubTab('INVENTORY')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeSubTab === 'INVENTORY' ? 'bg-cyan-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            Multi-Hub Stock
          </button>
          <button
            onClick={() => setActiveSubTab('CATALOG')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeSubTab === 'CATALOG' ? 'bg-cyan-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            Catalog & Master SKUs
          </button>
          <button
            onClick={() => setActiveSubTab('RFQ')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeSubTab === 'RFQ' ? 'bg-cyan-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            Supplier RFQ Matrix
          </button>
          <button
            onClick={() => setActiveSubTab('PURCHASE_ORDERS')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors flex items-center gap-1 ${
              activeSubTab === 'PURCHASE_ORDERS' ? 'bg-cyan-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            <span>Active POs</span>
            {purchaseOrders.length > 0 && (
              <span className="w-4 h-4 rounded-full bg-cyan-500 text-slate-950 font-bold text-[10px] flex items-center justify-center">
                {purchaseOrders.length}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveSubTab('DEAD_STOCK')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors flex items-center gap-1 ${
              activeSubTab === 'DEAD_STOCK' ? 'bg-amber-600 text-white shadow-sm' : 'text-slate-400 hover:text-amber-300'
            }`}
          >
            <span>Dead Stock Engine</span>
            {deadStockItems.length > 0 && (
              <span className="w-4 h-4 rounded-full bg-amber-500 text-slate-950 font-bold text-[10px] flex items-center justify-center">
                {deadStockItems.length}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveSubTab('SUPPLIERS')}
            className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
              activeSubTab === 'SUPPLIERS' ? 'bg-cyan-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            Supplier Intelligence
          </button>
        </div>
      </div>

      {/* SUBTAB 1: MULTI-HUB SERIALIZED INVENTORY */}
      {activeSubTab === 'INVENTORY' && (
        <div className="space-y-4">
          {/* Warehouse distribution chips */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div
              onClick={() => setSelectedWarehouse('BHIWANDI_HUB')}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                selectedWarehouse === 'BHIWANDI_HUB'
                  ? 'bg-cyan-950/40 border-cyan-500/50 text-cyan-200'
                  : 'bg-slate-900 border-slate-800 hover:border-slate-700 text-slate-300'
              }`}
            >
              <div className="flex justify-between items-start mb-1">
                <span className="font-bold text-xs text-white">Bhiwandi Central Hub (MH)</span>
                <span className="text-[10px] bg-slate-800 text-slate-300 px-1.5 py-0.2 rounded">Primary Depot</span>
              </div>
              <p className="text-[11px] text-slate-400">Main Western Distribution Logistics Center</p>
              <div className="mt-2 pt-2 border-t border-slate-800/80 flex justify-between text-xs font-semibold">
                <span className="text-slate-400">Total Units:</span>
                <span className="text-cyan-400">114 Serials</span>
              </div>
            </div>

            <div
              onClick={() => setSelectedWarehouse('DELHI_OKHLA')}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                selectedWarehouse === 'DELHI_OKHLA'
                  ? 'bg-cyan-950/40 border-cyan-500/50 text-cyan-200'
                  : 'bg-slate-900 border-slate-800 hover:border-slate-700 text-slate-300'
              }`}
            >
              <div className="flex justify-between items-start mb-1">
                <span className="font-bold text-xs text-white">Delhi Okhla Tech Depot (NCR)</span>
                <span className="text-[10px] bg-slate-800 text-slate-300 px-1.5 py-0.2 rounded">North Hub</span>
              </div>
              <p className="text-[11px] text-slate-400">Northern Enterprise & Govt Accounts Buffer</p>
              <div className="mt-2 pt-2 border-t border-slate-800/80 flex justify-between text-xs font-semibold">
                <span className="text-slate-400">Total Units:</span>
                <span className="text-cyan-400">46 Serials</span>
              </div>
            </div>

            <div
              onClick={() => setSelectedWarehouse('BANGALORE_ECITY')}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                selectedWarehouse === 'BANGALORE_ECITY'
                  ? 'bg-cyan-950/40 border-cyan-500/50 text-cyan-200'
                  : 'bg-slate-900 border-slate-800 hover:border-slate-700 text-slate-300'
              }`}
            >
              <div className="flex justify-between items-start mb-1">
                <span className="font-bold text-xs text-white">Bengaluru E-City Depot (KA)</span>
                <span className="text-[10px] bg-slate-800 text-slate-300 px-1.5 py-0.2 rounded">South Hub</span>
              </div>
              <p className="text-[11px] text-slate-400">IT Corridors Fast Delivery Buffer</p>
              <div className="mt-2 pt-2 border-t border-slate-800/80 flex justify-between text-xs font-semibold">
                <span className="text-slate-400">Total Units:</span>
                <span className="text-cyan-400">24 Serials</span>
              </div>
            </div>
          </div>

          {/* Serial inventory table */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Barcode className="w-4 h-4 text-cyan-400" />
                  <span>Serialized Physical Inventory Tracking</span>
                </h3>
                <span className="text-xs text-slate-400">
                  Tracking {filteredInventory.length} Units with Bin Locations & Serial Scanning
                </span>
              </div>
              <button
                onClick={() => setShowAddSerialModal(true)}
                className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs flex items-center gap-1.5 transition-colors shadow-sm self-start sm:self-auto"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Serial Hardware</span>
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/60 text-slate-400 font-semibold border-b border-slate-800">
                  <tr>
                    <th className="p-3">Serial Number</th>
                    <th className="p-3">Product & SKU</th>
                    <th className="p-3">Warehouse Hub</th>
                    <th className="p-3">Bin Location</th>
                    <th className="p-3 text-right">Unit Cost</th>
                    <th className="p-3">Distributor</th>
                    <th className="p-3 text-center">Stock Age</th>
                    <th className="p-3 text-center">State</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {filteredInventory.map((item) => (
                    <tr key={item.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="p-3 font-mono font-bold text-white flex items-center gap-1.5">
                        <Barcode className="w-3.5 h-3.5 text-slate-500" />
                        <span>{item.serialNumber}</span>
                      </td>
                      <td className="p-3">
                        <strong className="block text-slate-200">{item.productName}</strong>
                        <span className="text-[10px] text-slate-400 font-mono">{item.sku}</span>
                      </td>
                      <td className="p-3 font-medium text-slate-300">
                        {item.warehouse.replace('_', ' ')}
                      </td>
                      <td className="p-3 font-mono text-cyan-300">
                        {item.binLocation}
                      </td>
                      <td className="p-3 text-right font-mono text-slate-300">
                        ₹{item.cost.toLocaleString('en-IN')}
                      </td>
                      <td className="p-3 text-slate-400">
                        {item.supplier}
                      </td>
                      <td className="p-3 text-center font-mono">
                        <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                          item.ageDays > 90 ? 'bg-rose-500/20 text-rose-300' : 'bg-slate-800 text-slate-300'
                        }`}>
                          {item.ageDays} Days
                        </span>
                      </td>
                      <td className="p-3 text-center">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          item.state === 'AVAILABLE'
                            ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                            : item.state === 'RESERVED'
                            ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30'
                            : item.state === 'QC_CHECK'
                            ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                            : 'bg-slate-800 text-slate-400'
                        }`}>
                          {item.state}
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

      {/* SUBTAB: CATALOG & MASTER SKUs */}
      {activeSubTab === 'CATALOG' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Layers className="w-4 h-4 text-cyan-400" />
                  <span>Hardware Catalog & Master SKU Registry</span>
                </h3>
                <p className="text-xs text-slate-400">
                  Total {products.length} Products registered with HSN codes, multi-hub inventory allocation and target margins
                </p>
              </div>
              <button
                onClick={() => setShowAddProductModal(true)}
                className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs flex items-center gap-1.5 transition-colors shadow-sm self-start sm:self-auto"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Hardware SKU</span>
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/60 text-slate-400 font-semibold border-b border-slate-800">
                  <tr>
                    <th className="p-3">SKU & Item Name</th>
                    <th className="p-3">Brand / Line</th>
                    <th className="p-3">HSN Code</th>
                    <th className="p-3 text-right">Standard Cost</th>
                    <th className="p-3 text-right">Selling Price</th>
                    <th className="p-3 text-center">Gross Margin</th>
                    <th className="p-3 text-center">Multi-Hub Stock</th>
                    <th className="p-3 text-center">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {products.map((p) => {
                    const marginPct = Math.round(((p.unitSell - p.unitCost) / p.unitSell) * 100);
                    const totalStock = p.stockBhiwandi + p.stockDelhi + p.stockBangalore;
                    return (
                      <tr key={p.id} className="hover:bg-slate-800/30 transition-colors">
                        <td className="p-3">
                          <strong className="block text-white font-mono">{p.sku}</strong>
                          <span className="text-slate-300 text-[11px]">{p.name}</span>
                          <span className="text-[10px] text-slate-500 block">{p.specs}</span>
                        </td>
                        <td className="p-3">
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[11px] font-medium">
                            {p.brand}
                          </span>
                          <span className="text-[10px] text-slate-500 block mt-0.5">{p.category}</span>
                        </td>
                        <td className="p-3 font-mono text-slate-400">{p.hsn} ({p.gstRate}%)</td>
                        <td className="p-3 text-right font-mono text-slate-300">
                          ₹{p.unitCost.toLocaleString('en-IN')}
                        </td>
                        <td className="p-3 text-right font-mono font-bold text-white">
                          ₹{p.unitSell.toLocaleString('en-IN')}
                        </td>
                        <td className="p-3 text-center">
                          <span className={`px-2 py-0.5 rounded font-mono font-bold text-[11px] ${
                            marginPct >= 15 ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-300'
                          }`}>
                            {marginPct}%
                          </span>
                        </td>
                        <td className="p-3 text-center">
                          <div className="font-mono font-bold text-white text-xs">{totalStock} Units</div>
                          <div className="text-[10px] text-slate-400">
                            MH: {p.stockBhiwandi} | DL: {p.stockDelhi} | BLR: {p.stockBangalore}
                          </div>
                        </td>
                        <td className="p-3 text-center">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            totalStock > p.reorderPoint
                              ? 'bg-emerald-500/20 text-emerald-400'
                              : 'bg-rose-500/20 text-rose-300'
                          }`}>
                            {totalStock > p.reorderPoint ? 'HEALTHY' : 'REORDER'}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 2: SUPPLIER RFQ & COMPARISON ENGINE (Section 18 & 19) */}
      {activeSubTab === 'RFQ' && (
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-900 border border-slate-800 p-4 rounded-xl">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <FileSpreadsheet className="w-4 h-4 text-cyan-400" />
                <span>Competitive Supplier RFQ Matrix & L1 Evaluation</span>
              </h3>
              <p className="text-xs text-slate-400">
                Compare authorized national distributors (Redington, Ingram Micro, Savex, Kaizen) with L1 algorithmic scoring
              </p>
            </div>
            <button
              onClick={() => setShowCreateRFQModal(true)}
              className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs flex items-center gap-1.5 transition-colors shadow-sm self-start sm:self-auto"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Create New RFQ</span>
            </button>
          </div>

          {rfqs.map((rfq) => (
            <div key={rfq.id} className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold text-white">{rfq.rfqNumber}</span>
                    <span className="text-xs bg-cyan-500/20 text-cyan-300 px-2 py-0.5 rounded-full font-mono font-semibold">
                      Qty: {rfq.qty} Units
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-white mt-1">{rfq.productName}</h3>
                  <span className="text-xs text-slate-400">
                    Required By: {rfq.requiredByDate} &bull; Target Cost Cap: ₹{rfq.targetPrice.toLocaleString('en-IN')}/unit
                  </span>
                </div>

                <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  Status: Quotes Evaluated
                </span>
              </div>

              {/* Multi-Supplier Comparison Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {rfq.quotes.map((quote) => (
                  <div
                    key={quote.supplierId}
                    className={`p-4 rounded-xl border relative transition-all ${
                      quote.aiRecommended
                        ? 'bg-gradient-to-b from-slate-950 via-slate-900 to-indigo-950/40 border-indigo-500/60 shadow-lg shadow-indigo-500/10'
                        : 'bg-slate-950/70 border-slate-800'
                    }`}
                  >
                    {quote.aiRecommended && (
                      <span className="absolute -top-2.5 right-3 bg-indigo-500 text-white text-[10px] font-bold px-2 py-0.5 rounded-full flex items-center gap-1 shadow-sm">
                        <Sparkles className="w-3 h-3" /> AI RECOMMENDED
                      </span>
                    )}

                    <div className="space-y-2">
                      <h4 className="text-xs font-bold text-white">{quote.supplierName}</h4>
                      
                      <div className="text-xl font-bold font-mono text-cyan-400">
                        ₹{quote.pricePerUnit.toLocaleString('en-IN')}
                        <span className="text-xs text-slate-400 font-normal"> / unit</span>
                      </div>

                      <div className="grid grid-cols-2 gap-2 text-[11px] pt-1 border-t border-slate-800/80">
                        <div>
                          <span className="text-slate-400 block">Lead Time:</span>
                          <span className="text-white font-medium">{quote.deliveryDays} Day(s)</span>
                        </div>
                        <div>
                          <span className="text-slate-400 block">Availability:</span>
                          <span className="text-emerald-400 font-semibold">{quote.availability}</span>
                        </div>
                        <div>
                          <span className="text-slate-400 block">Reliability:</span>
                          <span className="text-slate-200 font-medium">{quote.reliabilityScore}%</span>
                        </div>
                        <div>
                          <span className="text-slate-400 block">Total PO Cost:</span>
                          <span className="text-white font-mono font-bold">
                            ₹{(quote.pricePerUnit * rfq.qty).toLocaleString('en-IN')}
                          </span>
                        </div>
                      </div>

                      <button
                        onClick={() => onRaisePO(rfq.id, quote.supplierId)}
                        className={`w-full mt-3 py-2 rounded-lg font-semibold text-xs transition-colors flex items-center justify-center gap-1.5 ${
                          quote.aiRecommended
                            ? 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-md'
                            : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                        }`}
                      >
                        <span>Issue Purchase Order (PO)</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* SUBTAB: ENTERPRISE PURCHASE ORDERS */}
      {activeSubTab === 'PURCHASE_ORDERS' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-sm">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <ShoppingBag className="w-4 h-4 text-cyan-400" />
                  <span>Enterprise Purchase Orders (POs) & Distributor Fulfillment</span>
                </h3>
                <p className="text-xs text-slate-400">
                  Tracking active supplier purchase orders, dispatch status, inbound logistics, and GRN verification
                </p>
              </div>
              <span className="text-xs font-mono bg-cyan-500/20 text-cyan-300 px-2.5 py-1 rounded-full border border-cyan-500/30 font-bold">
                {purchaseOrders.length} Issued POs
              </span>
            </div>

            {purchaseOrders.length === 0 ? (
              <div className="p-8 text-center text-slate-400 text-xs">
                No active purchase orders currently open. Issue POs directly from the Supplier RFQ Matrix.
              </div>
            ) : (
              <div className="divide-y divide-slate-800/60">
                {purchaseOrders.map((po) => (
                  <div key={po.id} className="p-4 hover:bg-slate-800/20 transition-colors space-y-3">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-white text-sm">{po.poNumber}</span>
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                            po.status === 'ISSUED'
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                              : po.status === 'CONFIRMED'
                              ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30'
                              : po.status === 'DELIVERED'
                              ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                              : 'bg-slate-800 text-slate-300'
                          }`}>
                            {po.status}
                          </span>
                        </div>
                        <div className="text-xs text-slate-300 mt-1 flex items-center gap-2">
                          <Building className="w-3.5 h-3.5 text-slate-500" />
                          <span>Supplier: <strong>{po.supplierName}</strong></span>
                          <span className="text-slate-500">&bull;</span>
                          <span className="text-slate-400">Issue Date: {po.date}</span>
                        </div>
                      </div>

                      <div className="text-right">
                        <span className="text-xs text-slate-400 block">Total PO Value (INR)</span>
                        <div className="text-base font-bold font-mono text-emerald-400">
                          ₹{po.totalAmount.toLocaleString('en-IN')}
                        </div>
                      </div>
                    </div>

                    <div className="p-3 rounded-lg bg-slate-950/70 text-xs border border-slate-800/80">
                      <div className="text-[11px] font-semibold text-slate-400 mb-1">Fulfillment Line Items:</div>
                      {po.items.map((it, idx) => (
                        <div key={idx} className="flex justify-between items-center text-slate-300 py-0.5">
                          <span>{it.productName} ({it.qty} units)</span>
                          <span className="font-mono">₹{(it.unitPrice * it.qty).toLocaleString('en-IN')}</span>
                        </div>
                      ))}
                      <div className="mt-2 pt-2 border-t border-slate-800 flex justify-between text-[11px] text-slate-400">
                        <span>Destination Hub: <strong className="text-slate-200">{po.deliveryWarehouse.replace('_', ' ')}</strong></span>
                        <span>Payment Terms: <strong className="text-slate-200">{po.paymentTerms}</strong></span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* SUBTAB 3: DEAD STOCK ENGINE (Section 54) */}
      {activeSubTab === 'DEAD_STOCK' && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span>Dead Stock Engine & Capital Liquidation (Section 54)</span>
              </h3>
              <p className="text-xs text-slate-400">
                AI detection of stagnant hardware assets (&gt;90-120 days) with proactive liquidation recommendations
              </p>
            </div>
            <span className="text-xs font-mono font-bold text-amber-400 bg-amber-500/20 px-2.5 py-1 rounded-full border border-amber-500/30">
              Trapped Capital: ₹1,84,000
            </span>
          </div>

          <div className="space-y-3">
            {deadStockItems.map((item) => (
              <div
                key={item.id}
                className="p-4 rounded-xl bg-slate-950/90 border border-amber-800/40 space-y-3"
              >
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <h4 className="text-xs font-bold text-white">{item.productName}</h4>
                      <span className="text-[10px] bg-rose-500/20 text-rose-300 px-2 py-0.2 rounded font-mono font-bold">
                        Age: {item.ageDays} Days in Stock
                      </span>
                    </div>
                    <span className="text-[11px] text-slate-400 block mt-0.5">
                      Serial: <strong className="font-mono text-slate-300">{item.serialNumber}</strong> &bull; Bin: {item.binLocation} &bull; Warehouse: {item.warehouse}
                    </span>
                  </div>

                  <div className="text-right">
                    <span className="text-xs text-slate-400 block">Unit Cost Trapped:</span>
                    <span className="text-sm font-bold font-mono text-white">₹{item.cost.toLocaleString('en-IN')}</span>
                  </div>
                </div>

                {/* AI Liquidation Recommendation */}
                <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 space-y-1.5">
                  <div className="flex items-center gap-1.5 text-amber-400 font-bold text-[11px]">
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>AI Liquidation Recommendation:</span>
                  </div>
                  <p className="text-slate-300 leading-relaxed">
                    Legacy Cisco 2960-X market demand is shifting towards Catalyst 1200. Liquidate via WhatsApp campaign targeted at <strong>120 Educational & Training Institutes</strong> with a <strong>35% liquidation discount (₹29,900)</strong> bundled with a 1-year replacement guarantee to recover ₹1.84L capital.
                  </p>
                </div>

                <div className="flex items-center justify-end gap-2">
                  <button className="px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-semibold text-xs transition-colors shadow-sm">
                    Launch Flash Liquidation Campaign
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 4: SUPPLIER INTELLIGENCE (Section 18) */}
      {activeSubTab === 'SUPPLIERS' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {suppliers.map((sup) => (
            <div key={sup.id} className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm space-y-3">
              <div className="flex items-start justify-between">
                <div>
                  <h4 className="text-sm font-bold text-white">{sup.name}</h4>
                  <span className="text-xs text-slate-400 block mt-0.5">{sup.location}</span>
                  <span className="text-[10px] font-mono text-slate-500">GST: {sup.gstin}</span>
                </div>
                <div className="text-right">
                  <span className="text-xs text-emerald-400 font-bold block">Rating {sup.rating} ★</span>
                  <span className="text-[10px] text-slate-400 font-mono">{sup.paymentTerms}</span>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-2 p-2.5 rounded-lg bg-slate-950 text-[11px] text-center">
                <div>
                  <span className="text-slate-500 block text-[10px]">Delivery Score</span>
                  <strong className="text-white">{sup.deliveryScore}%</strong>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Defect Rate</span>
                  <strong className="text-emerald-400">{sup.defectRate}%</strong>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Warranty SLA</span>
                  <strong className="text-sky-300">{sup.warrantySupportScore}%</strong>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs">
                <span className="text-slate-400">Authorized OEM Lines:</span>
                <span className="text-slate-200 font-medium">{sup.primaryBrands.join(', ')}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* MODAL 1: ADD HARDWARE SKU TO CATALOG */}
      {showAddProductModal && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Layers className="w-5 h-5 text-cyan-400" />
                <span>Add New Hardware SKU</span>
              </h3>
              <button
                onClick={() => setShowAddProductModal(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateProduct} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">SKU Code *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. ADT-PWR-1000W"
                    value={newProductForm.sku}
                    onChange={(e) => setNewProductForm({ ...newProductForm, sku: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-mono uppercase"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Brand Name *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. AadiTech / Lenovo / Cisco"
                    value={newProductForm.brand}
                    onChange={(e) => setNewProductForm({ ...newProductForm, brand: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                  />
                </div>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Product Description / Title *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. AadiTech Modular Redundant Power Supply System"
                  value={newProductForm.name}
                  onChange={(e) => setNewProductForm({ ...newProductForm, name: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Category</label>
                  <input
                    type="text"
                    value={newProductForm.category}
                    onChange={(e) => setNewProductForm({ ...newProductForm, category: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Model Number</label>
                  <input
                    type="text"
                    placeholder="e.g. ADT-PWR-V2"
                    value={newProductForm.model}
                    onChange={(e) => setNewProductForm({ ...newProductForm, model: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Procurement Cost (INR) *</label>
                  <input
                    type="number"
                    required
                    value={newProductForm.unitCost}
                    onChange={(e) => setNewProductForm({ ...newProductForm, unitCost: Number(e.target.value) })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-mono"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Target Selling Price (INR) *</label>
                  <input
                    type="number"
                    required
                    value={newProductForm.unitSell}
                    onChange={(e) => setNewProductForm({ ...newProductForm, unitSell: Number(e.target.value) })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">HSN Code</label>
                  <input
                    type="text"
                    value={newProductForm.hsn}
                    onChange={(e) => setNewProductForm({ ...newProductForm, hsn: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-mono"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">GST Rate %</label>
                  <select
                    value={newProductForm.gstRate}
                    onChange={(e) => setNewProductForm({ ...newProductForm, gstRate: Number(e.target.value) })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                  >
                    <option value={18}>18% GST (Standard IT Hardware)</option>
                    <option value={28}>28% GST</option>
                    <option value={12}>12% GST</option>
                    <option value={5}>5% GST</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-2 pt-1 border-t border-slate-800">
                <div>
                  <label className="text-slate-400 block mb-1 text-[11px]">Bhiwandi Hub Stock</label>
                  <input
                    type="number"
                    value={newProductForm.stockBhiwandi}
                    onChange={(e) => setNewProductForm({ ...newProductForm, stockBhiwandi: Number(e.target.value) })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-1.5 text-white font-mono text-center"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1 text-[11px]">Delhi Okhla Stock</label>
                  <input
                    type="number"
                    value={newProductForm.stockDelhi}
                    onChange={(e) => setNewProductForm({ ...newProductForm, stockDelhi: Number(e.target.value) })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-1.5 text-white font-mono text-center"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1 text-[11px]">BLR E-City Stock</label>
                  <input
                    type="number"
                    value={newProductForm.stockBangalore}
                    onChange={(e) => setNewProductForm({ ...newProductForm, stockBangalore: Number(e.target.value) })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-1.5 text-white font-mono text-center"
                  />
                </div>
              </div>

              <div className="pt-3 flex justify-end gap-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddProductModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold shadow-md flex items-center gap-1.5"
                >
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Register SKU in Catalog</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 2: ADD SERIALIZED PHYSICAL UNIT */}
      {showAddSerialModal && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Barcode className="w-5 h-5 text-cyan-400" />
                <span>Add Serialized Hardware Unit</span>
              </h3>
              <button
                onClick={() => setShowAddSerialModal(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateSerial} className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">Serial Number (Scanned / Input) *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. SN-ADT-2026-9901"
                  value={newSerialForm.serialNumber}
                  onChange={(e) => setNewSerialForm({ ...newSerialForm, serialNumber: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-mono uppercase tracking-wider"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Select Hardware SKU *</label>
                <select
                  value={newSerialForm.sku}
                  onChange={(e) => {
                    const sel = products.find(p => p.sku === e.target.value);
                    setNewSerialForm({
                      ...newSerialForm,
                      sku: e.target.value,
                      productName: sel ? sel.name : newSerialForm.productName,
                      cost: sel ? sel.unitCost : newSerialForm.cost
                    });
                  }}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-mono"
                >
                  {products.map((p) => (
                    <option key={p.id} value={p.sku}>
                      {p.sku} - {p.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Warehouse Hub</label>
                  <select
                    value={newSerialForm.warehouse}
                    onChange={(e) => setNewSerialForm({ ...newSerialForm, warehouse: e.target.value as any })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                  >
                    <option value="BHIWANDI_HUB">Bhiwandi Central Hub (MH)</option>
                    <option value="DELHI_OKHLA">Delhi Okhla Tech Depot (NCR)</option>
                    <option value="BANGALORE_ECITY">Bengaluru E-City Depot (KA)</option>
                  </select>
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Physical Bin Location</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. A-02-14"
                    value={newSerialForm.binLocation}
                    onChange={(e) => setNewSerialForm({ ...newSerialForm, binLocation: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-mono uppercase"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Inward Unit Cost (INR)</label>
                  <input
                    type="number"
                    value={newSerialForm.cost}
                    onChange={(e) => setNewSerialForm({ ...newSerialForm, cost: Number(e.target.value) })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-mono"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Supplier / Inward Source</label>
                  <input
                    type="text"
                    value={newSerialForm.supplierName}
                    onChange={(e) => setNewSerialForm({ ...newSerialForm, supplierName: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                  />
                </div>
              </div>

              <div className="pt-3 flex justify-end gap-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowAddSerialModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold shadow-md flex items-center gap-1.5"
                >
                  <Barcode className="w-4 h-4" />
                  <span>Inward Serial to Warehouse</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 3: CREATE NEW RFQ */}
      {showCreateRFQModal && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <FileSpreadsheet className="w-5 h-5 text-cyan-400" />
                <span>Create Competitive Supplier RFQ</span>
              </h3>
              <button
                onClick={() => setShowCreateRFQModal(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateRFQ} className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 block mb-1">Equipment / Solution Required *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 50x Intel Xeon Silver Processors or 20x Fortinet 60F Firewalls"
                  value={newRFQForm.productName}
                  onChange={(e) => setNewRFQForm({ ...newRFQForm, productName: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 block mb-1">Quantity Required *</label>
                  <input
                    type="number"
                    required
                    min={1}
                    value={newRFQForm.qty}
                    onChange={(e) => setNewRFQForm({ ...newRFQForm, qty: Number(e.target.value) })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-mono"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1">Target Price per Unit (INR) *</label>
                  <input
                    type="number"
                    required
                    value={newRFQForm.targetPrice}
                    onChange={(e) => setNewRFQForm({ ...newRFQForm, targetPrice: Number(e.target.value) })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="text-slate-400 block mb-1">Required Delivery Timeline</label>
                <select
                  value={newRFQForm.requiredByDate}
                  onChange={(e) => setNewRFQForm({ ...newRFQForm, requiredByDate: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-white"
                >
                  <option value="Immediate (48 Hours)">Immediate (48 Hours)</option>
                  <option value="Within 7 Days">Within 7 Days</option>
                  <option value="Within 15 Days">Within 15 Days</option>
                  <option value="Within 30 Days (Project Schedule)">Within 30 Days (Project Schedule)</option>
                </select>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 text-slate-400 text-[11px] space-y-1 border border-slate-800">
                <div className="text-white font-semibold">Participating Distributors:</div>
                <div>RFQ will be broadcasted to: <strong>Redington India, Ingram Micro, Savex Technologies</strong></div>
                <div>Autonomous evaluation engine will score by L1 pricing, credit terms, and delivery SLA.</div>
              </div>

              <div className="pt-3 flex justify-end gap-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateRFQModal(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold shadow-md flex items-center gap-1.5"
                >
                  <Send className="w-4 h-4" />
                  <span>Broadcast RFQ & Solicit Bids</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
