import React, { useState } from 'react';
import {
  Truck,
  Package,
  CheckCircle2,
  Clock,
  MapPin,
  FileText,
  Barcode,
  Wrench,
  AlertTriangle,
  RotateCcw,
  Plus,
  Send,
  Printer,
  ChevronRight,
  ShieldCheck,
  Search,
  Building2,
  Phone
} from 'lucide-react';
import {
  SalesOrder,
  InstallationWorkOrder,
  RMARequest,
  CompanyProfile
} from '../types';

interface OrdersAndLogisticsViewProps {
  salesOrders: SalesOrder[];
  workOrders: InstallationWorkOrder[];
  rmas: RMARequest[];
  companyProfile: CompanyProfile;
  onUpdateOrderStatus: (orderId: string, status: SalesOrder['fulfillmentStatus']) => void;
  onDispatchOrder: (orderId: string, courier: SalesOrder['courierName'], awb: string, eWayBill: string) => void;
  onToggleWorkOrderChecklist: (woId: string, index: number) => void;
  onUpdateWorkOrderStatus: (woId: string, status: InstallationWorkOrder['status']) => void;
  onCreateWorkOrder: (wo: InstallationWorkOrder) => void;
  onAddRMA: (rma: RMARequest) => void;
}

export const OrdersAndLogisticsView: React.FC<OrdersAndLogisticsViewProps> = ({
  salesOrders,
  workOrders,
  rmas,
  companyProfile,
  onUpdateOrderStatus,
  onDispatchOrder,
  onToggleWorkOrderChecklist,
  onUpdateWorkOrderStatus,
  onCreateWorkOrder,
  onAddRMA
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'orders' | 'dispatch' | 'installations' | 'rma'>('orders');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedOrder, setSelectedOrder] = useState<SalesOrder | null>(salesOrders[0] || null);

  // Dispatch modal state
  const [isDispatchModalOpen, setIsDispatchModalOpen] = useState(false);
  const [dispatchOrderTarget, setDispatchOrderTarget] = useState<SalesOrder | null>(null);
  const [selectedCourier, setSelectedCourier] = useState<SalesOrder['courierName']>('BlueDart Express');
  const [awbInput, setAwbInput] = useState('');
  const [eWayBillInput, setEWayBillInput] = useState('');

  // Work Order creation modal
  const [isNewWOModalOpen, setIsNewWOModalOpen] = useState(false);
  const [newWOForm, setNewWOForm] = useState({
    orderId: salesOrders[0]?.orderNumber || '',
    customerName: salesOrders[0]?.customerName || '',
    siteAddress: salesOrders[0]?.deliveryAddress || '',
    hardwareSummary: 'Network Switch & Firewall Installation',
    assignedTechnician: 'Amit Verma (Senior Network Specialist)',
    technicianPhone: '+91 98112 33491',
    scheduledDate: new Date(Date.now() + 86400000 * 2).toISOString().split('T')[0]
  });

  // RMA modal state
  const [isNewRMAModalOpen, setIsNewRMAModalOpen] = useState(false);
  const [newRMAForm, setNewRMAForm] = useState({
    customerName: salesOrders[0]?.customerName || '',
    serialNumber: 'PF49X099',
    productModel: 'Enterprise Hardware Unit',
    issueReported: 'Boot failure after power surge',
    pickupAddress: salesOrders[0]?.deliveryAddress || ''
  });

  const filteredOrders = salesOrders.filter(
    (o) =>
      o.orderNumber.toLowerCase().includes(searchQuery.toLowerCase()) ||
      o.customerName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      o.destinationCity.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleOpenDispatch = (order: SalesOrder) => {
    setDispatchOrderTarget(order);
    setAwbInput(`BD-${Math.floor(10000000 + Math.random() * 90000000)}`);
    setEWayBillInput(`2718${Math.floor(10000000 + Math.random() * 90000000)}`);
    setIsDispatchModalOpen(true);
  };

  const handleConfirmDispatch = (e: React.FormEvent) => {
    e.preventDefault();
    if (dispatchOrderTarget) {
      onDispatchOrder(dispatchOrderTarget.id, selectedCourier, awbInput, eWayBillInput);
      setIsDispatchModalOpen(false);
      setDispatchOrderTarget(null);
    }
  };

  const handleCreateWO = (e: React.FormEvent) => {
    e.preventDefault();
    const wo: InstallationWorkOrder = {
      id: `WO-2026-${Math.floor(10 + Math.random() * 90)}`,
      workOrderNumber: `WO-2026-${Math.floor(10 + Math.random() * 90)}`,
      orderId: newWOForm.orderId,
      customerName: newWOForm.customerName,
      siteAddress: newWOForm.siteAddress,
      hardwareSummary: newWOForm.hardwareSummary,
      assignedTechnician: newWOForm.assignedTechnician,
      technicianPhone: newWOForm.technicianPhone,
      scheduledDate: newWOForm.scheduledDate,
      status: 'SCHEDULED',
      checklist: [
        { item: 'Site Power & Cooling Readiness Verification', done: true },
        { item: 'Hardware Unboxing & Serial QC Barcode Scan', done: false },
        { item: 'Rack Mounting & Patch Cable Dressing', done: false },
        { item: 'Firmware & Initial Configuration', done: false },
        { item: 'Customer Acceptance Signoff & Handover', done: false }
      ],
      customerSignoff: false
    };
    onCreateWorkOrder(wo);
    setIsNewWOModalOpen(false);
  };

  const handleCreateRMA = (e: React.FormEvent) => {
    e.preventDefault();
    const rma: RMARequest = {
      id: `RMA-2026-${Math.floor(10 + Math.random() * 90)}`,
      rmaNumber: `RMA-2026-${Math.floor(10 + Math.random() * 90)}`,
      customerName: newRMAForm.customerName,
      serialNumber: newRMAForm.serialNumber,
      productModel: newRMAForm.productModel,
      issueReported: newRMAForm.issueReported,
      status: 'RMA_INITIATED',
      pickupAddress: newRMAForm.pickupAddress,
      technicianAssigned: 'Suresh Patil (Field Diagnostics)',
      createdDate: new Date().toISOString().split('T')[0]
    };
    onAddRMA(rma);
    setIsNewRMAModalOpen(false);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Metric Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <Truck className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-white tracking-tight">
                  Orders, Logistics & Turnkey Fulfillment
                </h2>
                <p className="text-xs text-slate-400">
                  Sections 27, 31, 33, 34 & 35 &bull; {companyProfile.name} Hub Fulfilment & On-Site Installation Pipeline
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsNewWOModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-sm transition-all"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Schedule On-Site Engineer</span>
            </button>
            <button
              onClick={() => setIsNewRMAModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition-all"
            >
              <RotateCcw className="w-3.5 h-3.5 text-amber-400" />
              <span>Initiate RMA Ticket</span>
            </button>
          </div>
        </div>

        {/* Quick KPI stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Total Sales Orders</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-lg font-bold text-white">{salesOrders.length}</span>
              <span className="text-[10px] text-emerald-400 font-medium">100% Verified</span>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">In Transit / Dispatched</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-lg font-bold text-cyan-400">
                {salesOrders.filter((o) => o.fulfillmentStatus === 'DISPATCHED').length}
              </span>
              <span className="text-[10px] text-slate-400 font-medium">Live AWB Sync</span>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Installation Work Orders</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-lg font-bold text-blue-400">{workOrders.length}</span>
              <span className="text-[10px] text-slate-400 font-medium">
                {workOrders.filter((w) => w.status === 'COMPLETED').length} Handed Over
              </span>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Active RMA Replacements</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-lg font-bold text-amber-400">{rmas.length}</span>
              <span className="text-[10px] text-emerald-400 font-medium">DOA 14-Day Guard</span>
            </div>
          </div>
        </div>

        {/* Sub-tab navigation */}
        <div className="flex items-center gap-2 mt-4 pt-3 border-t border-slate-800 overflow-x-auto no-scrollbar">
          <button
            onClick={() => setActiveSubTab('orders')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
              activeSubTab === 'orders'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Package className="w-3.5 h-3.5" />
            <span>Sales Orders & GST Invoicing</span>
            <span className="px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px] text-slate-300">
              {salesOrders.length}
            </span>
          </button>

          <button
            onClick={() => setActiveSubTab('dispatch')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
              activeSubTab === 'dispatch'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Truck className="w-3.5 h-3.5" />
            <span>Dispatch & E-Way Bill Hub</span>
          </button>

          <button
            onClick={() => setActiveSubTab('installations')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
              activeSubTab === 'installations'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Wrench className="w-3.5 h-3.5" />
            <span>On-Site Work Orders & Sign-off</span>
            <span className="px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px] text-slate-300">
              {workOrders.length}
            </span>
          </button>

          <button
            onClick={() => setActiveSubTab('rma')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
              activeSubTab === 'rma'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>RMA & Reverse Logistics</span>
            <span className="px-1.5 py-0.2 rounded-full bg-slate-800 text-[10px] text-slate-300">
              {rmas.length}
            </span>
          </button>
        </div>
      </div>

      {/* Subtab 1: Orders & GST Invoicing */}
      {activeSubTab === 'orders' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Order list column */}
          <div className="lg:col-span-7 space-y-3">
            <div className="flex items-center justify-between gap-3">
              <div className="relative flex-1">
                <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search order number, customer, city..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl pl-9 pr-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div className="space-y-3">
              {filteredOrders.map((order) => {
                const isSelected = selectedOrder?.id === order.id;
                const statusColors = {
                  ORDER_CONFIRMED: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
                  PICKED_IN_QC: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
                  PACKED: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
                  DISPATCHED: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
                  DELIVERED: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                };

                return (
                  <div
                    key={order.id}
                    onClick={() => setSelectedOrder(order)}
                    className={`bg-slate-900 border rounded-2xl p-4 transition-all cursor-pointer ${
                      isSelected
                        ? 'border-cyan-500 ring-1 ring-cyan-500/20 shadow-md'
                        : 'border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-white">{order.orderNumber}</span>
                          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${statusColors[order.fulfillmentStatus]}`}>
                            {order.fulfillmentStatus.replace(/_/g, ' ')}
                          </span>
                          <span className="text-[10px] text-slate-400">{order.createdDate}</span>
                        </div>
                        <h4 className="text-sm font-semibold text-slate-200 mt-1">{order.customerName}</h4>
                        <p className="text-xs text-slate-400 flex items-center gap-1.5 mt-0.5">
                          <MapPin className="w-3 h-3 text-slate-500" />
                          <span>{order.destinationCity}</span>
                        </p>
                      </div>

                      <div className="text-right">
                        <span className="text-sm font-bold text-emerald-400 font-mono">
                          ₹{order.totalAmount.toLocaleString('en-IN')}
                        </span>
                        <span className="text-[10px] text-slate-400 block mt-0.5 font-mono">
                          GST: ₹{order.gstAmount.toLocaleString('en-IN')}
                        </span>
                        <span className="text-[10px] text-sky-300 font-mono block mt-0.5">
                          {order.paymentStatus.replace(/_/g, ' ')}
                        </span>
                      </div>
                    </div>

                    <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
                      <div className="text-slate-400 text-[11px] truncate max-w-[280px]">
                        {order.items.length} line item(s): {order.items[0]?.productName}
                      </div>

                      <div className="flex items-center gap-2">
                        {order.fulfillmentStatus !== 'DISPATCHED' && order.fulfillmentStatus !== 'DELIVERED' && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleOpenDispatch(order);
                            }}
                            className="px-2.5 py-1 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 text-[11px] font-medium transition-colors"
                          >
                            Dispatch Order &rarr;
                          </button>
                        )}
                        {order.fulfillmentStatus === 'DISPATCHED' && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onUpdateOrderStatus(order.id, 'DELIVERED');
                            }}
                            className="px-2.5 py-1 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 text-[11px] font-medium transition-colors flex items-center gap-1"
                          >
                            <CheckCircle2 className="w-3 h-3" />
                            <span>Mark Delivered</span>
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Selected Order Detailed Drawer */}
          <div className="lg:col-span-5">
            {selectedOrder ? (
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4 sticky top-24">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div>
                    <span className="text-[10px] text-slate-400 font-mono">SALES ORDER SPECIFICATION</span>
                    <h3 className="text-base font-bold text-white font-mono">{selectedOrder.orderNumber}</h3>
                  </div>
                  <button
                    onClick={() => window.print()}
                    className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs border border-slate-700"
                  >
                    <Printer className="w-3.5 h-3.5" />
                    <span>Print Invoice</span>
                  </button>
                </div>

                {/* Customer & Tax info */}
                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Customer:</span>
                    <span className="font-semibold text-white">{selectedOrder.customerName}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Customer GSTIN:</span>
                    <span className="font-mono text-cyan-300">{selectedOrder.customerGst}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Delivery Address:</span>
                    <span className="text-slate-300 text-right max-w-[200px]">{selectedOrder.deliveryAddress}</span>
                  </div>
                  <div className="flex justify-between pt-1 border-t border-slate-800">
                    <span className="text-slate-400">Govt e-Invoice IRN:</span>
                    <span className="font-mono text-[10px] text-slate-300 truncate max-w-[180px]">
                      {selectedOrder.irnNumber || 'Generated upon dispatch'}
                    </span>
                  </div>
                </div>

                {/* Line items with serial numbers */}
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-slate-300">Hardware Line Items & Serial Numbers</span>
                  <div className="space-y-2">
                    {selectedOrder.items.map((item, idx) => (
                      <div key={idx} className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs">
                        <div className="flex justify-between items-start">
                          <div>
                            <span className="font-semibold text-white">{item.productName}</span>
                            <span className="text-[10px] text-slate-400 block font-mono">SKU: {item.sku} &bull; Qty: {item.qty}</span>
                          </div>
                          <span className="font-mono text-emerald-400 font-semibold">
                            ₹{item.total.toLocaleString('en-IN')}
                          </span>
                        </div>
                        {item.serialNumbers && item.serialNumbers.length > 0 && (
                          <div className="mt-2 pt-2 border-t border-slate-800/80">
                            <span className="text-[10px] text-slate-400 block mb-1 flex items-center gap-1">
                              <Barcode className="w-3 h-3 text-cyan-400" />
                              <span>Allocated Serial Barcodes:</span>
                            </span>
                            <div className="flex flex-wrap gap-1">
                              {item.serialNumbers.map((sn, sIdx) => (
                                <span
                                  key={sIdx}
                                  className="text-[10px] font-mono bg-slate-900 px-2 py-0.5 rounded border border-slate-700 text-cyan-300"
                                >
                                  {sn}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Financial Total */}
                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5 text-xs font-mono">
                  <div className="flex justify-between text-slate-400">
                    <span>Taxable Subtotal:</span>
                    <span>₹{selectedOrder.subtotal.toLocaleString('en-IN')}</span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>GST (18% Output CGST/SGST/IGST):</span>
                    <span>₹{selectedOrder.gstAmount.toLocaleString('en-IN')}</span>
                  </div>
                  <div className="flex justify-between text-sm font-bold text-white pt-1.5 border-t border-slate-800">
                    <span>Gross Invoice Total:</span>
                    <span className="text-emerald-400">₹{selectedOrder.totalAmount.toLocaleString('en-IN')}</span>
                  </div>
                </div>

                {/* Status action buttons */}
                <div className="pt-2">
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      onClick={() => onUpdateOrderStatus(selectedOrder.id, 'PICKED_IN_QC')}
                      className={`py-2 rounded-xl text-xs font-semibold border transition-all ${
                        selectedOrder.fulfillmentStatus === 'PICKED_IN_QC'
                          ? 'bg-amber-500 text-slate-950 border-amber-400'
                          : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
                      }`}
                    >
                      QC Inward Pass
                    </button>
                    <button
                      onClick={() => handleOpenDispatch(selectedOrder)}
                      className="py-2 rounded-xl text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow-sm transition-all"
                    >
                      Dispatch & AWB
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 text-center text-slate-400 text-xs">
                Select a Sales Order to inspect details, serial barcode allocations, and GST e-invoices.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Subtab 2: Dispatch & E-Way Bill Hub */}
      {activeSubTab === 'dispatch' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Truck className="w-4 h-4 text-cyan-400" />
              <span>Logistics Integrations: BlueDart, Delhivery, Safexpress & DTDC Air</span>
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Real-time API tracking, National e-Way Bill portal compliance, and Proof of Delivery (POD) scanning.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
              {salesOrders.map((order) => (
                <div key={order.id} className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-white">{order.orderNumber}</span>
                    <span className="px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 text-[10px] font-mono border border-cyan-500/30">
                      {order.courierName || 'Pending Courier'}
                    </span>
                  </div>

                  <div className="space-y-1">
                    <span className="text-slate-400 block text-[11px]">Consignee:</span>
                    <span className="font-semibold text-slate-200 block">{order.customerName}</span>
                    <span className="text-slate-400 text-[11px] block">{order.destinationCity}</span>
                  </div>

                  <div className="p-2 rounded-lg bg-slate-900 border border-slate-800 space-y-1 font-mono text-[11px]">
                    <div className="flex justify-between">
                      <span className="text-slate-400">AWB Tracking:</span>
                      <span className="text-cyan-300 font-semibold">{order.awbNumber || 'Generating...'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">e-Way Bill No:</span>
                      <span className="text-slate-200">{order.eWayBillNumber || 'Exempt / Pending'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Est. Delivery:</span>
                      <span className="text-emerald-400">{order.expectedDelivery}</span>
                    </div>
                  </div>

                  <div className="flex justify-between items-center pt-2 border-t border-slate-800">
                    <span className="text-[10px] text-slate-400">Fulfillment Status</span>
                    <span className="text-[10px] font-semibold text-cyan-400">{order.fulfillmentStatus}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Subtab 3: On-Site Work Orders & Sign-off */}
      {activeSubTab === 'installations' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Wrench className="w-4 h-4 text-blue-400" />
                <span>On-Site Engineer Deployment & Technical Sign-off</span>
              </h3>
              <p className="text-xs text-slate-400">
                Turnkey installation, firmware staging, VLAN configuration, and digital handover signoff.
              </p>
            </div>
            <button
              onClick={() => setIsNewWOModalOpen(true)}
              className="flex items-center gap-1 px-3 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-sm transition-all"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Work Order</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {workOrders.map((wo) => {
              const statusColors = {
                SCHEDULED: 'bg-blue-500/10 text-blue-300 border-blue-500/30',
                TECHNICIAN_ON_SITE: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
                CONFIGURING: 'bg-purple-500/10 text-purple-300 border-purple-500/30',
                COMPLETED: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
              };

              const allDone = wo.checklist.every((c) => c.done);

              return (
                <div key={wo.id} className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4 shadow-sm">
                  <div className="flex items-start justify-between border-b border-slate-800 pb-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-white text-xs">{wo.workOrderNumber}</span>
                        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${statusColors[wo.status]}`}>
                          {wo.status.replace(/_/g, ' ')}
                        </span>
                      </div>
                      <h4 className="text-sm font-semibold text-slate-200 mt-1">{wo.customerName}</h4>
                      <p className="text-xs text-slate-400 flex items-center gap-1 mt-0.5">
                        <MapPin className="w-3 h-3 text-slate-500" />
                        <span>{wo.siteAddress}</span>
                      </p>
                    </div>

                    <div className="text-right">
                      <span className="text-[10px] text-slate-400 block">Scheduled Date</span>
                      <span className="text-xs font-semibold text-white font-mono">{wo.scheduledDate}</span>
                    </div>
                  </div>

                  {/* Technician & Scope */}
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5 text-xs">
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400">Assigned Engineer:</span>
                      <span className="font-semibold text-white flex items-center gap-1.5">
                        <Phone className="w-3 h-3 text-emerald-400" />
                        <span>{wo.assignedTechnician} ({wo.technicianPhone})</span>
                      </span>
                    </div>
                    <div className="flex justify-between items-start pt-1 border-t border-slate-800/80">
                      <span className="text-slate-400">Hardware Scope:</span>
                      <span className="text-slate-300 text-right max-w-[220px] font-medium">{wo.hardwareSummary}</span>
                    </div>
                  </div>

                  {/* Interactive Checklist */}
                  <div className="space-y-2">
                    <span className="text-xs font-semibold text-slate-300">Staging & Commissioning Checklist</span>
                    <div className="space-y-1.5">
                      {wo.checklist.map((item, cIdx) => (
                        <label
                          key={cIdx}
                          className="flex items-center gap-2.5 p-2 rounded-lg bg-slate-950 hover:bg-slate-800/50 border border-slate-800/80 cursor-pointer transition-colors text-xs"
                        >
                          <input
                            type="checkbox"
                            checked={item.done}
                            onChange={() => onToggleWorkOrderChecklist(wo.id, cIdx)}
                            className="w-4 h-4 rounded border-slate-700 bg-slate-900 text-blue-500 focus:ring-blue-500"
                          />
                          <span className={item.done ? 'text-slate-300 line-through' : 'text-white'}>
                            {item.item}
                          </span>
                        </label>
                      ))}
                    </div>
                  </div>

                  {/* Actions & Status Updater */}
                  <div className="pt-2 flex items-center justify-between">
                    <div className="flex items-center gap-1">
                      {wo.customerSignoff ? (
                        <span className="text-[11px] font-semibold text-emerald-400 flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Customer Signoff Verified</span>
                        </span>
                      ) : (
                        <span className="text-[11px] text-amber-400 flex items-center gap-1">
                          <Clock className="w-3.5 h-3.5" />
                          <span>Signoff Awaiting</span>
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      {wo.status !== 'COMPLETED' ? (
                        <button
                          onClick={() => onUpdateWorkOrderStatus(wo.id, 'COMPLETED')}
                          disabled={!allDone}
                          className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                            allDone
                              ? 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm'
                              : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                          }`}
                        >
                          Mark Complete & Handover
                        </button>
                      ) : (
                        <span className="text-xs font-semibold text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-lg border border-emerald-500/20">
                          Handed Over & Verified
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Subtab 4: RMA & Reverse Logistics */}
      {activeSubTab === 'rma' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <RotateCcw className="w-4 h-4 text-amber-400" />
                <span>RMA, Dead-On-Arrival (DOA) & Reverse Diagnostics</span>
              </h3>
              <p className="text-xs text-slate-400">
                Section 35 &bull; Instant replacement dispatch, vendor claim settlement, and serial track.
              </p>
            </div>
            <button
              onClick={() => setIsNewRMAModalOpen(true)}
              className="flex items-center gap-1 px-3 py-1.5 rounded-xl bg-amber-600 hover:bg-amber-500 text-slate-950 font-semibold text-xs transition-all"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Raise RMA Claim</span>
            </button>
          </div>

          <div className="space-y-3">
            {rmas.map((rma) => (
              <div key={rma.id} className="bg-slate-900 border border-slate-800 rounded-2xl p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 text-xs">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-amber-400">{rma.rmaNumber}</span>
                    <span className="font-mono text-cyan-300 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                      SN: {rma.serialNumber}
                    </span>
                    <span className="px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-300 text-[10px] font-semibold border border-amber-500/30">
                      {rma.status.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <h4 className="font-semibold text-white text-sm">{rma.customerName} &bull; {rma.productModel}</h4>
                  <p className="text-slate-400 text-xs">{rma.issueReported}</p>
                </div>

                <div className="text-right space-y-1">
                  <span className="text-slate-400 block text-[11px]">Field Tech: {rma.technicianAssigned}</span>
                  <span className="text-slate-500 block text-[10px]">Pickup: {rma.pickupAddress}</span>
                  <span className="text-emerald-400 font-medium block text-[11px]">
                    Advance Replacement Dispatched
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Dispatch Order Modal */}
      {isDispatchModalOpen && dispatchOrderTarget && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-md w-full shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-bold text-white">Generate Dispatch & Transmit AWB</h3>
                <p className="text-xs text-slate-400">Order: {dispatchOrderTarget.orderNumber}</p>
              </div>
              <button
                onClick={() => setIsDispatchModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 text-lg leading-none"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleConfirmDispatch} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 mb-1 font-medium">Select Approved Courier Partner</label>
                <select
                  value={selectedCourier}
                  onChange={(e) => setSelectedCourier(e.target.value as any)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="BlueDart Express">BlueDart Express (Air Priority)</option>
                  <option value="Delhivery Freight">Delhivery Freight (Surface Heavy)</option>
                  <option value="Safexpress Logistics">Safexpress Logistics (Enterprise Cold/Rack)</option>
                  <option value="DTDC Air">DTDC Air Prime</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 mb-1 font-medium">Generated Air Waybill (AWB) Barcode</label>
                <input
                  type="text"
                  value={awbInput}
                  onChange={(e) => setAwbInput(e.target.value)}
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-cyan-300 font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1 font-medium">GST e-Way Bill Number (NIC Portal)</label>
                <input
                  type="text"
                  value={eWayBillInput}
                  onChange={(e) => setEWayBillInput(e.target.value)}
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-[11px] text-slate-400 space-y-1">
                <span className="text-emerald-400 font-semibold block">Warehouse QC Checklist:</span>
                <span>&bull; Serial numbers captured & verified against physical barcodes</span>
                <span>&bull; Tamper-evident AadiTech security seals affixed</span>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsDispatchModalOpen(false)}
                  className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs shadow-sm"
                >
                  Confirm Dispatch & Transmit
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Schedule Engineer Modal */}
      {isNewWOModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-lg w-full shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-bold text-white">Schedule On-Site Engineer Deployment</h3>
                <p className="text-xs text-slate-400">Turnkey commissioning & configuration work order</p>
              </div>
              <button
                onClick={() => setIsNewWOModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 text-lg leading-none"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleCreateWO} className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1">Customer Account</label>
                  <input
                    type="text"
                    value={newWOForm.customerName}
                    onChange={(e) => setNewWOForm({ ...newWOForm, customerName: e.target.value })}
                    required
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">Scheduled Date</label>
                  <input
                    type="date"
                    value={newWOForm.scheduledDate}
                    onChange={(e) => setNewWOForm({ ...newWOForm, scheduledDate: e.target.value })}
                    required
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Customer Site Address</label>
                <input
                  type="text"
                  value={newWOForm.siteAddress}
                  onChange={(e) => setNewWOForm({ ...newWOForm, siteAddress: e.target.value })}
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Assigned Field Engineer & Contact</label>
                <div className="grid grid-cols-2 gap-3">
                  <input
                    type="text"
                    value={newWOForm.assignedTechnician}
                    onChange={(e) => setNewWOForm({ ...newWOForm, assignedTechnician: e.target.value })}
                    required
                    placeholder="Engineer Name"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white"
                  />
                  <input
                    type="text"
                    value={newWOForm.technicianPhone}
                    onChange={(e) => setNewWOForm({ ...newWOForm, technicianPhone: e.target.value })}
                    required
                    placeholder="Engineer Phone"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Hardware Scope of Work</label>
                <textarea
                  value={newWOForm.hardwareSummary}
                  onChange={(e) => setNewWOForm({ ...newWOForm, hardwareSummary: e.target.value })}
                  required
                  rows={2}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white resize-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsNewWOModalOpen(false)}
                  className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs shadow-sm"
                >
                  Generate Work Order
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* New RMA Modal */}
      {isNewRMAModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-md w-full shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-bold text-white">Raise Reverse RMA / DOA Claim</h3>
                <p className="text-xs text-slate-400">Initiate immediate advance replacement workflow</p>
              </div>
              <button
                onClick={() => setIsNewRMAModalOpen(false)}
                className="text-slate-400 hover:text-slate-200 text-lg leading-none"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleCreateRMA} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 mb-1">Customer Name</label>
                <input
                  type="text"
                  value={newRMAForm.customerName}
                  onChange={(e) => setNewRMAForm({ ...newRMAForm, customerName: e.target.value })}
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1">Unit Serial Number</label>
                  <input
                    type="text"
                    value={newRMAForm.serialNumber}
                    onChange={(e) => setNewRMAForm({ ...newRMAForm, serialNumber: e.target.value })}
                    required
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">Product Model</label>
                  <input
                    type="text"
                    value={newRMAForm.productModel}
                    onChange={(e) => setNewRMAForm({ ...newRMAForm, productModel: e.target.value })}
                    required
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Issue Reported / Defect Diagnostics</label>
                <textarea
                  value={newRMAForm.issueReported}
                  onChange={(e) => setNewRMAForm({ ...newRMAForm, issueReported: e.target.value })}
                  required
                  rows={2}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white resize-none"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Pickup Address</label>
                <input
                  type="text"
                  value={newRMAForm.pickupAddress}
                  onChange={(e) => setNewRMAForm({ ...newRMAForm, pickupAddress: e.target.value })}
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-white"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsNewRMAModalOpen(false)}
                  className="px-4 py-2 rounded-xl bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-amber-600 hover:bg-amber-500 text-slate-950 font-semibold text-xs shadow-sm"
                >
                  Initiate RMA & Pickup
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
