import {
  Lead,
  Customer360,
  Product,
  Quotation,
  TelegramMessage,
  Supplier,
  RFQ,
  SerialInventory,
  WarrantyAsset,
  AMCContract,
  ServiceTicket,
  MarketingCampaign,
  AIAgent,
  AuditEvent,
  SalesOrder,
  InstallationWorkOrder,
  RMARequest,
  PartnerAccount,
  DealRegistration,
  CommissionRecord,
  WorkflowRule,
  EventBusMessage,
  KnowledgeDocument,
  DeadStockItem,
  DemandForecast,
  SalesForecastSummary,
  CashFlowForecastItem,
  NextBestAction,
  LostDealAnalysis,
  CustomerLTVAnalysis,
  TenantAccount,
  UserRoleDefinition,
  SystemHealthMetric,
  DeadLetterJob,
  IntegrationConnector,
  ApiEndpointDoc,
  GeMTenderBid,
  OutboundProspectAccount,
  HardwareRefreshAsset
} from '../types';

export const INITIAL_LEADS: Lead[] = [
  {
    id: 'LD-1092',
    name: 'Rohan Deshmukh (VP Infrastructure)',
    company: 'FinStack Technologies Ltd',
    email: 'rohan.d@finstack.in',
    phone: '+91 98201 44520',
    source: 'WHATSAPP',
    status: 'QUALIFIED',
    score: 'HOT',
    scoreReason: 'Immediate 45x laptop requirement + 3x 10G switches for Mumbai branch expansion; budget approved ₹32L.',
    intentScore: 94,
    requirement: '45x Lenovo ThinkPad T14 Gen 4, 3x Cisco Catalyst 1200 24-Port PoE, 1x Fortinet 60F Firewall.',
    estimatedBudget: 3200000,
    location: 'Mumbai (BKC)',
    gstin: '27AABCF1290K1ZP',
    createdAt: '2026-09-04 09:15 AM',
    lastInteraction: '10 mins ago via WhatsApp Bot'
  },
  {
    id: 'LD-1091',
    name: 'Priya Sundaram (Head of IT)',
    company: 'Apex Logistics Parks Pvt Ltd',
    email: 'priya.s@apexlogistics.com',
    phone: '+91 97110 88231',
    source: 'INDIAMART',
    status: 'BOM_GENERATED',
    score: 'HOT',
    scoreReason: 'Warehouse automation hardware with 3-year on-site AMC mandate; GST verified.',
    intentScore: 88,
    requirement: '2x Dell PowerEdge R760 2U Servers + APC 6kVA Online UPS + 18x Industrial Barcode Handhelds.',
    estimatedBudget: 1850000,
    location: 'Bhiwandi Logistics Hub',
    gstin: '27AABCA7712M1Z3',
    createdAt: '2026-09-04 08:30 AM',
    lastInteraction: '35 mins ago via AI Solution Builder'
  },
  {
    id: 'LD-1090',
    name: 'Arunav Sengupta (Director)',
    company: 'Kolkata BioMed Diagnostics',
    email: 'arunav@kolkatabiomed.org',
    phone: '+91 98300 23419',
    source: 'WEBSITE',
    status: 'CONTACTED',
    score: 'WARM',
    scoreReason: 'Evaluating replacement of 30x legacy i3 desktops; comparison stage with Dell vs HP.',
    intentScore: 72,
    requirement: '30x Core i5 13th Gen Desktops with 24-inch IPS monitors.',
    estimatedBudget: 1400000,
    location: 'Kolkata (Salt Lake)',
    createdAt: '2026-09-04 07:10 AM',
    lastInteraction: '1 hr ago via Web Portal'
  },
  {
    id: 'LD-1089',
    name: 'Vikas Sharma (Admin Lead)',
    company: 'EduLearn Digital Academy',
    email: 'vikas@edulearn.edu.in',
    phone: '+91 98101 99238',
    source: 'EMAIL',
    status: 'NEW',
    score: 'NURTURE',
    scoreReason: 'Price inquiry for computer lab refit; funding awaiting Q3 state grant clearance.',
    intentScore: 45,
    requirement: '50x All-in-One PCs + Central NAS Storage.',
    estimatedBudget: 2200000,
    location: 'Jaipur, Rajasthan',
    createdAt: '2026-09-03 04:45 PM',
    lastInteraction: 'Yesterday via Email'
  },
  {
    id: 'LD-1093',
    name: 'Executive Engineer (Signalling & Telecom)',
    company: 'Western Railway Divisional HQ (GeM)',
    email: 'snt.wr@indianrailways.gov.in',
    phone: '+91 22 2201 5490',
    source: 'GEM_TENDER',
    status: 'QUALIFIED',
    score: 'HOT',
    scoreReason: 'GeM Bid #GEM/2026/B/8912 matched with AadiTech Solution ATS Rugged DC-DC Converter units; EMD exempt; Margin 28%.',
    intentScore: 96,
    requirement: '40x ATS 48V-1000W Rugged DC-DC Converters + 2x Dell PowerEdge 2U R760 Rackmount Servers.',
    estimatedBudget: 4200000,
    location: 'Mumbai Central / Churchgate',
    gstin: '27AAAGM0289H1Z4',
    createdAt: '2026-09-05 10:20 AM',
    lastInteraction: 'Bid auto-parsed & mapped to ATS Master Catalog',
    tenderNumber: 'GEM/2026/B/8912',
    bidClosingDate: '2026-09-18'
  },
  {
    id: 'LD-1094',
    name: 'Sunil Grover (VP Infrastructure & SecOps)',
    company: 'NexaPay Cloud Payments Pvt Ltd',
    email: 'sunil.grover@nexapay.in',
    phone: '+91 98210 44912',
    source: 'OUTBOUND_HUNTER',
    status: 'QUALIFIED',
    score: 'HOT',
    scoreReason: 'AI Hunter detected 35,000 sq.ft BKC tech center expansion; direct outreach responded with approved Q3 laptop budget.',
    intentScore: 93,
    requirement: '70x Lenovo ThinkPad T14 Gen 4, 4x Cisco Catalyst 1200 48-Port PoE+, 2x Fortinet FG-60F High Availability cluster.',
    estimatedBudget: 5400000,
    location: 'Mumbai (BKC G-Block)',
    gstin: '27AABCN8812K1Z9',
    createdAt: '2026-09-05 02:40 PM',
    lastInteraction: 'Direct response to AI Expansion Outreach sequence'
  },
  {
    id: 'LD-1095',
    name: 'Rajesh Patil (Sr Manager IT Infrastructure)',
    company: 'Tata Motors Supply Hub (Pimpri)',
    email: 'rajesh.patil@tatamotors.com',
    phone: '+91 98220 99401',
    source: 'HARDWARE_REFRESH',
    status: 'QUALIFIED',
    score: 'HOT',
    scoreReason: 'Installed base warranty scanner flagged 35x ThinkPads deployed in 2023 reaching 36 months; buyback refresh requested.',
    intentScore: 91,
    requirement: '35x ThinkPad T14 Gen 5 Refresh + Trade-in credit for 2023 fleet + 3-Year Premier Support on-site.',
    estimatedBudget: 2850000,
    location: 'Pune / Pimpri Industrial Belt',
    gstin: '27AAACT2727Q1ZW',
    createdAt: '2026-09-06 09:00 AM',
    lastInteraction: 'Proactive Refresh Alert generated by Customer 360 scanner',
    refreshAssetDetails: '35x ThinkPad L14 Gen 2 (Age: 36 Months)'
  }
];

export const INITIAL_CUSTOMERS: Customer360[] = [
  {
    id: 'CUST-001',
    name: 'TechCorp India Solutions Ltd',
    gstin: '27AABCT9981K1ZO',
    contactPerson: 'Sandeep Nair (VP Procurement)',
    email: 'sandeep@techcorp.in',
    phone: '+91 98200 11990',
    city: 'Mumbai',
    state: 'Maharashtra',
    creditLimit: 2500000,
    currentOutstanding: 420000,
    paymentRiskScore: 'LOW',
    lifetimeValue: 8450000,
    totalOrders: 14,
    activeWarrantiesCount: 88,
    activeAMCCount: 3,
    lastPurchaseDate: '2026-08-18',
    preferredBrands: ['Lenovo', 'Cisco', 'APC']
  },
  {
    id: 'CUST-002',
    name: 'Zomato Regional Kitchen Operations',
    gstin: '06AAACZ9988P1Z4',
    contactPerson: 'Karan Mehra (IT Ops Lead)',
    email: 'karan.m@zomatokitchens.in',
    phone: '+91 99100 44211',
    city: 'Gurugram',
    state: 'Haryana',
    creditLimit: 1500000,
    currentOutstanding: 180000,
    paymentRiskScore: 'LOW',
    lifetimeValue: 4620000,
    totalOrders: 9,
    activeWarrantiesCount: 42,
    activeAMCCount: 2,
    lastPurchaseDate: '2026-08-28',
    preferredBrands: ['Dell', 'Fortinet', 'Ubiquiti']
  },
  {
    id: 'CUST-003',
    name: 'Alpha Infotech Subcontracting',
    gstin: '29AABCA4431B1ZT',
    contactPerson: 'Manish Hegde (Managing Partner)',
    email: 'manish@alphainfotech.co.in',
    phone: '+91 98450 77122',
    city: 'Bengaluru',
    state: 'Karnataka',
    creditLimit: 1000000,
    currentOutstanding: 920000,
    paymentRiskScore: 'HIGH',
    lifetimeValue: 3100000,
    totalOrders: 6,
    activeWarrantiesCount: 24,
    activeAMCCount: 0,
    lastPurchaseDate: '2026-07-12',
    preferredBrands: ['HP', 'D-Link']
  }
];

export const INITIAL_PRODUCTS: Product[] = [
  {
    id: 'PROD-001',
    sku: 'LEN-TP-T14-G4',
    brand: 'Lenovo',
    model: 'ThinkPad T14 Gen 4',
    category: 'LAPTOP',
    specs: 'Intel Core i5-1335U, 16GB DDR5, 512GB NVMe SSD, 14" WUXGA IPS, Win 11 Pro, 3Y Onsite NBD',
    unitCost: 59500,
    freightCost: 650,
    riskBuffer: 850,
    landedCost: 61000,
    sellingPrice: 72500,
    minPrice: 68000,
    targetMarginPct: 15.86,
    gstRate: 18,
    hsn: '8471',
    warrantyMonths: 36,
    stockBhiwandi: 38,
    stockDelhi: 14,
    stockBangalore: 22,
    reservedStock: 12,
    leadTimeDays: 2
  },
  {
    id: 'PROD-002',
    sku: 'DELL-OPT-7010M',
    brand: 'Dell',
    model: 'OptiPlex 7010 Micro',
    category: 'DESKTOP',
    specs: 'Intel Core i5-13500T, 16GB DDR4, 512GB Gen4 SSD, Intel UHD 770, Win 11 Pro, 3Y ProSupport',
    unitCost: 41200,
    freightCost: 500,
    riskBuffer: 600,
    landedCost: 42300,
    sellingPrice: 49800,
    minPrice: 46500,
    targetMarginPct: 15.06,
    gstRate: 18,
    hsn: '8471',
    warrantyMonths: 36,
    stockBhiwandi: 45,
    stockDelhi: 20,
    stockBangalore: 15,
    reservedStock: 25,
    leadTimeDays: 1
  },
  {
    id: 'PROD-003',
    sku: 'DELL-PE-R760',
    brand: 'Dell',
    model: 'PowerEdge R760 2U Rack Server',
    category: 'SERVER',
    specs: '2x Intel Xeon Silver 4410Y (24C), 128GB DDR5 ECC RDIMM, 4x 960GB SAS SSD Mixed-Use, PERC H755 RAID, Dual 1100W Redundant PSU, iDRAC9 Enterprise',
    unitCost: 385000,
    freightCost: 4500,
    riskBuffer: 6500,
    landedCost: 396000,
    sellingPrice: 485000,
    minPrice: 455000,
    targetMarginPct: 18.35,
    gstRate: 18,
    hsn: '8471',
    warrantyMonths: 36,
    stockBhiwandi: 4,
    stockDelhi: 2,
    stockBangalore: 1,
    reservedStock: 2,
    leadTimeDays: 5
  },
  {
    id: 'PROD-004',
    sku: 'CISCO-CAT-1200-24P',
    brand: 'Cisco',
    model: 'Catalyst 1200 24-Port Gigabit PoE+',
    category: 'NETWORKING',
    specs: '24x 10/100/1000 RJ45 PoE+ Ports (195W Power Budget), 4x 1G SFP Uplinks, Layer 2 Smart Managed, Lifetime Ltd Warranty',
    unitCost: 23800,
    freightCost: 350,
    riskBuffer: 450,
    landedCost: 24600,
    sellingPrice: 29800,
    minPrice: 27500,
    targetMarginPct: 17.44,
    gstRate: 18,
    hsn: '8517',
    warrantyMonths: 60,
    stockBhiwandi: 16,
    stockDelhi: 8,
    stockBangalore: 10,
    reservedStock: 4,
    leadTimeDays: 2
  },
  {
    id: 'PROD-005',
    sku: 'FORTI-FG-60F',
    brand: 'Fortinet',
    model: 'FortiGate 60F UTM Firewall',
    category: 'NETWORKING',
    specs: '10x GE RJ45 ports (including 2x WAN, 1x DMZ, 7x Internal), 1 Gbps Threat Protection, 1-Year Unified Threat Protection (UTP) License Bundle',
    unitCost: 56500,
    freightCost: 400,
    riskBuffer: 800,
    landedCost: 57700,
    sellingPrice: 69900,
    minPrice: 65000,
    targetMarginPct: 17.45,
    gstRate: 18,
    hsn: '8517',
    warrantyMonths: 12,
    stockBhiwandi: 2, // Low stock!
    stockDelhi: 1,
    stockBangalore: 0,
    reservedStock: 2,
    leadTimeDays: 4
  },
  {
    id: 'PROD-006',
    sku: 'APC-SMT-3000RM2U',
    brand: 'APC by Schneider Electric',
    model: 'Smart-UPS 3000VA LCD RM 2U',
    category: 'POWER_STORAGE',
    specs: '2700 Watts / 3000 VA, 230V, Rack Height 2U, SmartConnect Cloud-enabled, Sine Wave output, 3-year warranty on electronics, 2-year on battery',
    unitCost: 98000,
    freightCost: 2200,
    riskBuffer: 1800,
    landedCost: 102000,
    sellingPrice: 124000,
    minPrice: 115000,
    targetMarginPct: 17.74,
    gstRate: 18,
    hsn: '8504',
    warrantyMonths: 36,
    stockBhiwandi: 6,
    stockDelhi: 3,
    stockBangalore: 2,
    reservedStock: 1,
    leadTimeDays: 3
  }
];

export const INITIAL_QUOTATIONS: Quotation[] = [
  {
    id: 'QT-2026-089',
    quoteNumber: 'QT-2026-089',
    customerName: 'TechCorp India Solutions Ltd',
    customerGstin: '27AABCT9981K1ZO',
    billingAddress: '402 Platina Building, Bandra Kurla Complex, Mumbai, MH - 400051',
    items: [
      { id: 'b1', category: 'Laptops', name: 'Lenovo ThinkPad T14 Gen 4 (i5/16GB/512GB)', sku: 'LEN-TP-T14-G4', qty: 15, unitCost: 59500, unitSell: 68500, hsn: '8471', gstRate: 18 },
      { id: 'b2', category: 'Networking', name: 'Cisco Catalyst 1200 24-Port Gigabit PoE+', sku: 'CISCO-CAT-1200-24P', qty: 2, unitCost: 23800, unitSell: 27500, hsn: '8517', gstRate: 18 },
      { id: 'b3', category: 'Power', name: 'APC Smart-UPS 3000VA LCD RM 2U', sku: 'APC-SMT-3000RM2U', qty: 1, unitCost: 98000, unitSell: 112500, hsn: '8504', gstRate: 18 }
    ],
    subtotal: 1195000,
    freight: 5000,
    cgst: 108000,
    sgst: 108000,
    igst: 0,
    totalAmount: 1416000,
    totalCost: 1038100,
    marginPct: 14.1, // Requires Telegram approval because < 15%!
    status: 'PENDING_APPROVAL',
    approvalTierRequired: 'OWNER_TELEGRAM',
    validityDays: 15,
    deliveryWeeks: 1,
    paymentTerms: '30% Advance with PO, Balance against Delivery',
    createdDate: '2026-09-04'
  },
  {
    id: 'QT-2026-088',
    quoteNumber: 'QT-2026-088',
    customerName: 'Zomato Regional Kitchen Operations',
    customerGstin: '06AAACZ9988P1Z4',
    billingAddress: 'Tower B, Signature Towers, South City 1, Gurugram, HR - 122001',
    items: [
      { id: 'b4', category: 'Firewalls', name: 'Fortinet FortiGate 60F UTM Firewall Bundle', sku: 'FORTI-FG-60F', qty: 2, unitCost: 56500, unitSell: 69900, hsn: '8517', gstRate: 18 },
      { id: 'b5', category: 'Desktops', name: 'Dell OptiPlex 7010 Micro', sku: 'DELL-OPT-7010M', qty: 8, unitCost: 41200, unitSell: 49800, hsn: '8471', gstRate: 18 }
    ],
    subtotal: 538200,
    freight: 3500,
    cgst: 0,
    sgst: 0,
    igst: 97506,
    totalAmount: 639206,
    totalCost: 442600,
    marginPct: 17.76,
    status: 'APPROVED',
    approvalTierRequired: 'NONE',
    validityDays: 30,
    deliveryWeeks: 1,
    paymentTerms: '100% Payment within 30 Days of Invoice',
    createdDate: '2026-09-03'
  }
];

export const INITIAL_TELEGRAM_MESSAGES: TelegramMessage[] = [
  {
    id: 'tg-1',
    sender: 'bot',
    text: `⚡ **AutoHardware OS Telegram Command Hub v4.2 Active**\nWelcome Boss! Autonomous engines are live.\n\nType natural questions like:\n• "Aaj kitna profit hua?"\n• "Pending approvals dikhao"\n• "₹5 lakh se upar ke orders batao"\n\nOr tap commands below:`,
    timestamp: '08:00 AM',
    quickActions: ['/dashboard', '/leads', '/quotes', '/pending', '/stock', '/profit']
  },
  {
    id: 'tg-2',
    sender: 'user',
    text: '/pending',
    timestamp: '08:45 AM'
  },
  {
    id: 'tg-3',
    sender: 'bot',
    text: `🔔 **ATTENTION REQUIRED: HIGH-VALUE QUOTATION MARGIN EXCEPTION**\n\nAI Sales Agent has generated Quotation **QT-2026-089** for **TechCorp India Solutions Ltd**.\nCalculated deal margin is **14.1%**, which is below your standard autonomous 15.0% threshold.`,
    timestamp: '08:46 AM',
    approvalCard: {
      id: 'appr-089',
      type: 'QUOTATION_MARGIN',
      title: 'Quotation QT-2026-089 Margin Authorization',
      referenceId: 'QT-2026-089',
      amount: 1195000,
      marginPct: 14.1,
      customerName: 'TechCorp India Solutions Ltd',
      requestedBy: 'AI Sales Agent (via WhatsApp Bot)',
      reason: 'Customer negotiated volume pricing on 15x ThinkPads + 2x Cisco Switches. Competitor Savex offered ₹69,000/laptop. Offering ₹68,500 locks a ₹12L account with guaranteed 3-year AMC upsell potential.',
      status: 'PENDING',
      timeoutMinutes: 9,
      createdAt: '2026-09-04 08:45 AM',
      escalationLevel: 'OWNER_ESCALATED'
    }
  }
];

export const INITIAL_SUPPLIERS: Supplier[] = [
  {
    id: 'SUP-01',
    name: 'Redington India Ltd',
    location: 'Bhiwandi National Warehouse',
    gstin: '27AABCR2451H1ZB',
    rating: 4.8,
    deliveryScore: 96,
    defectRate: 0.4,
    warrantySupportScore: 98,
    paymentTerms: 'Net 30 Days with Credit Line',
    primaryBrands: ['Lenovo', 'Dell', 'Cisco', 'APC']
  },
  {
    id: 'SUP-02',
    name: 'Ingram Micro India Pvt Ltd',
    location: 'Navi Mumbai Hub',
    gstin: '27AABCI1102P1ZT',
    rating: 4.7,
    deliveryScore: 94,
    defectRate: 0.6,
    warrantySupportScore: 95,
    paymentTerms: 'Net 21 Days',
    primaryBrands: ['HP', 'Fortinet', 'Dell', 'Ubiquiti']
  },
  {
    id: 'SUP-03',
    name: 'Supertron Infotech Pvt Ltd',
    location: 'Andheri East, Mumbai',
    gstin: '27AABCS3389J1ZR',
    rating: 4.4,
    deliveryScore: 91,
    defectRate: 1.1,
    warrantySupportScore: 90,
    paymentTerms: 'Advance / 7 Days',
    primaryBrands: ['Seagate', 'Kingston', 'D-Link']
  },
  {
    id: 'SUP-04',
    name: 'Savex Technologies Pvt Ltd',
    location: 'Lower Parel, Mumbai',
    gstin: '27AABCS8891N1ZM',
    rating: 4.6,
    deliveryScore: 93,
    defectRate: 0.8,
    warrantySupportScore: 92,
    paymentTerms: 'Net 15 Days',
    primaryBrands: ['Lenovo', 'Apple', 'Samsung']
  }
];

export const INITIAL_RFQS: RFQ[] = [
  {
    id: 'RFQ-2026-44',
    rfqNumber: 'RFQ-2026-44',
    productName: 'Fortinet FortiGate 60F UTM Firewall Bundle',
    qty: 5,
    requiredByDate: '2026-09-08',
    targetPrice: 56000,
    status: 'QUOTES_RECEIVED',
    selectedSupplier: 'Ingram Micro India Pvt Ltd',
    quotes: [
      {
        supplierId: 'SUP-02',
        supplierName: 'Ingram Micro India',
        pricePerUnit: 56200,
        deliveryDays: 1,
        warrantyYears: 1,
        availability: 'IN_STOCK',
        reliabilityScore: 97,
        aiRecommended: true
      },
      {
        supplierId: 'SUP-01',
        supplierName: 'Redington India',
        pricePerUnit: 57100,
        deliveryDays: 3,
        warrantyYears: 1,
        availability: '3_DAYS',
        reliabilityScore: 95,
        aiRecommended: false
      },
      {
        supplierId: 'SUP-04',
        supplierName: 'Savex Technologies',
        pricePerUnit: 56800,
        deliveryDays: 2,
        warrantyYears: 1,
        availability: 'IN_STOCK',
        reliabilityScore: 91,
        aiRecommended: false
      }
    ]
  }
];

export const INITIAL_INVENTORY: SerialInventory[] = [
  {
    id: 'SN-901',
    serialNumber: 'LNV-PF4X981A',
    sku: 'LEN-TP-T14-G4',
    productName: 'Lenovo ThinkPad T14 Gen 4',
    warehouse: 'BHIWANDI_HUB',
    binLocation: 'A3-R2-B4',
    state: 'AVAILABLE',
    cost: 59500,
    supplier: 'Redington India Ltd',
    ageDays: 14
  },
  {
    id: 'SN-902',
    serialNumber: 'LNV-PF4X982B',
    sku: 'LEN-TP-T14-G4',
    productName: 'Lenovo ThinkPad T14 Gen 4',
    warehouse: 'BHIWANDI_HUB',
    binLocation: 'A3-R2-B4',
    state: 'RESERVED',
    cost: 59500,
    supplier: 'Redington India Ltd',
    ageDays: 14
  },
  {
    id: 'SN-903',
    serialNumber: 'DEL-PE760-991',
    sku: 'DELL-PE-R760',
    productName: 'Dell PowerEdge R760 2U Rack Server',
    warehouse: 'BHIWANDI_HUB',
    binLocation: 'SRV-RACK-01',
    state: 'QC_CHECK',
    cost: 385000,
    supplier: 'Redington India Ltd',
    ageDays: 4
  },
  {
    id: 'SN-904',
    serialNumber: 'CSC-CAT-88120',
    sku: 'CISCO-CAT-1200-24P',
    productName: 'Cisco Catalyst 1200 24-Port PoE+',
    warehouse: 'DELHI_OKHLA',
    binLocation: 'D-NET-11',
    state: 'AVAILABLE',
    cost: 23800,
    supplier: 'Redington India Ltd',
    ageDays: 28
  },
  {
    id: 'SN-905',
    serialNumber: 'CSC-OLD-2960X-01',
    sku: 'CISCO-2960X-24TD',
    productName: 'Cisco Catalyst 2960-X (Legacy Model)',
    warehouse: 'BHIWANDI_HUB',
    binLocation: 'DEAD-SEC-03',
    state: 'AVAILABLE',
    cost: 46000,
    supplier: 'Supertron Infotech',
    ageDays: 135,
    isDeadStock: true
  }
];

export const INITIAL_WARRANTIES: WarrantyAsset[] = [
  {
    id: 'WAR-01',
    serialNumber: 'LNV-PF2901AA',
    customerName: 'TechCorp India Solutions Ltd',
    productName: 'Lenovo ThinkPad L14 Gen 2 (Fleet of 18)',
    purchaseDate: '2023-10-15',
    warrantyExpiryDate: '2026-10-15',
    daysRemaining: 41,
    alertStatus: 'EXPIRING_60',
    hasActiveAMC: false
  },
  {
    id: 'WAR-02',
    serialNumber: 'DEL-OPT-5090-09',
    customerName: 'Zomato Regional Kitchen Operations',
    productName: 'Dell OptiPlex 5090 SFF (Fleet of 12)',
    purchaseDate: '2023-09-20',
    warrantyExpiryDate: '2026-09-20',
    daysRemaining: 16,
    alertStatus: 'EXPIRING_15',
    hasActiveAMC: true
  },
  {
    id: 'WAR-03',
    serialNumber: 'APC-SMT-7711',
    customerName: 'Alpha Infotech Subcontracting',
    productName: 'APC Smart-UPS 2200VA RM 2U',
    purchaseDate: '2023-09-10',
    warrantyExpiryDate: '2026-09-10',
    daysRemaining: 6,
    alertStatus: 'EXPIRING_15',
    hasActiveAMC: false
  }
];

export const INITIAL_AMCS: AMCContract[] = [
  {
    id: 'AMC-2025-11',
    contractNumber: 'AMC-2025-11',
    customerName: 'TechCorp India Solutions Ltd',
    assetCount: 45,
    annualFee: 185000,
    startDate: '2025-10-01',
    endDate: '2026-09-30',
    slaHours: 4,
    scheduledVisitsPerYear: 4,
    completedVisits: 3,
    status: 'UP_FOR_RENEWAL'
  },
  {
    id: 'AMC-2026-02',
    contractNumber: 'AMC-2026-02',
    customerName: 'Zomato Regional Kitchen Operations',
    assetCount: 28,
    annualFee: 120000,
    startDate: '2026-03-01',
    endDate: '2027-02-28',
    slaHours: 4,
    scheduledVisitsPerYear: 4,
    completedVisits: 2,
    status: 'ACTIVE'
  }
];

export const INITIAL_TICKETS: ServiceTicket[] = [
  {
    id: 'TCK-401',
    ticketNumber: 'TCK-401',
    customerName: 'TechCorp India Solutions Ltd',
    serialNumber: 'LNV-PF2901AA',
    issueDescription: 'Laptop displays intermittent BSOD (Memory_Management); user reports failure during video conferences.',
    priority: 'HIGH',
    status: 'TECHNICIAN_ASSIGNED',
    technician: 'Sachin Kamble (Senior Hardware Tech)',
    slaTimeRemainingHours: 2.5,
    createdAt: '2026-09-04 07:30 AM'
  },
  {
    id: 'TCK-402',
    ticketNumber: 'TCK-402',
    customerName: 'Zomato Regional Kitchen Operations',
    serialNumber: 'FORTI-FG-60F',
    issueDescription: 'WAN-2 failover IPSEC tunnel dropped connection to cloud database.',
    priority: 'CRITICAL',
    status: 'OPEN',
    technician: 'Unassigned (Auto-matching Network Engineer)',
    slaTimeRemainingHours: 1.2,
    createdAt: '2026-09-04 08:50 AM'
  }
];

export const INITIAL_CAMPAIGNS: MarketingCampaign[] = [
  {
    id: 'CMP-01',
    name: 'Hardware Warranty Sunset -> ProActive AMC Upsell',
    targetSegment: '73 Accounts with Laptop/Server Warranty expiring < 60 days without AMC',
    channel: 'OMNICHANNEL',
    status: 'ACTIVE',
    reach: 73,
    qualifiedLeads: 24,
    ordersWon: 8,
    revenueGenerated: 1480000,
    roas: 18.5,
    messagePreview: 'Hi {Name}, your OEM warranty for {Assets} expires in 30 days. Prevent costly motherboard/drive downtime with our 4-Hr SLA AMC...'
  },
  {
    id: 'CMP-02',
    name: 'Dead Stock Clearance: Cisco 2960-X Enterprise Bundle',
    targetSegment: '120 SMB & Educational Institutes seeking Gigabit Switches at 40% Discount',
    channel: 'WHATSAPP',
    status: 'ACTIVE',
    reach: 120,
    qualifiedLeads: 18,
    ordersWon: 6,
    revenueGenerated: 320000,
    roas: 12.0,
    messagePreview: 'Flash Liquidation: Genuine Cisco 2960-X with 1-Year Comprehensive Replacement Guarantee at ₹28,500 (Normally ₹46,000)...'
  }
];

export const INITIAL_AI_AGENTS: AIAgent[] = [
  {
    id: 'agent-1',
    name: 'AI Lead & Ingestion Agent',
    code: 'LEAD',
    description: 'Captures and enriches leads from WhatsApp, IndiaMART, Web & Telegram; evaluates intent score.',
    status: 'PROCESSING',
    currentTask: 'Ingesting 3 WhatsApp RFQ inquiries from BKC & Okhla hubs',
    tasksCompletedToday: 54,
    confidenceScore: 98,
    recentActivity: 'Scored Rohan Deshmukh (FinStack) as HOT (94/100)'
  },
  {
    id: 'agent-2',
    name: 'AI Sales & Conversation Agent',
    code: 'SALES',
    description: 'Engages in multi-channel natural dialogue, captures exact technical specs and delivery dates.',
    status: 'PROCESSING',
    currentTask: 'Conducting spec dialogue with Priya Sundaram for 2U Server deployment',
    tasksCompletedToday: 41,
    confidenceScore: 96,
    recentActivity: 'Clarified RAID-10 requirement for Apex Logistics'
  },
  {
    id: 'agent-3',
    name: 'AI Solution & BOM Engine',
    code: 'BOM',
    description: 'Generates comprehensive IT infrastructure BOM with automated hardware compatibility validation.',
    status: 'IDLE',
    currentTask: 'Ready for solution synthesis',
    tasksCompletedToday: 29,
    confidenceScore: 99,
    recentActivity: 'Validated 25-node PoE+ power budget and 3kVA UPS load'
  },
  {
    id: 'agent-4',
    name: 'AI Smart Pricing & Margin Agent',
    code: 'PRICING',
    description: 'Calculates landed cost, risk buffers, and guards 15% margin thresholds against competitor quotes.',
    status: 'WAITING_APPROVAL',
    currentTask: 'Queued Quotation QT-2026-089 for Telegram Owner Authorization (14.1% margin)',
    tasksCompletedToday: 38,
    confidenceScore: 95,
    recentActivity: 'Prevented below-cost quote attempt on 30x Lenovo Laptops'
  },
  {
    id: 'agent-5',
    name: 'AI Procurement & RFQ Agent',
    code: 'PROCUREMENT',
    description: 'Sends automated RFQs to Redington, Ingram Micro, Savex, and analyzes landed prices & defect scores.',
    status: 'PROCESSING',
    currentTask: 'Comparing 3 distributor quotes for FortiGate 60F restock',
    tasksCompletedToday: 22,
    confidenceScore: 97,
    recentActivity: 'Recommended Ingram Micro (saving ₹900/unit @ 1-day delivery)'
  },
  {
    id: 'agent-6',
    name: 'AI Inventory & Warehouse Agent',
    code: 'INVENTORY',
    description: 'Monitors bin allocations, serial number scanning, dead-stock flags, and inter-hub transfers.',
    status: 'PROCESSING',
    currentTask: 'Monitoring Bhiwandi buffer vs Delhi Okhla stock reserves',
    tasksCompletedToday: 68,
    confidenceScore: 99,
    recentActivity: 'Flagged 8x legacy Cisco 2960-X switches as Dead Stock (>120 days)'
  },
  {
    id: 'agent-7',
    name: 'AI Finance, GST & Credit Risk Agent',
    code: 'FINANCE',
    description: 'Validates GSTINs, checks customer credit exposure before SO release, reconciles bank payments.',
    status: 'IDLE',
    currentTask: 'Listening to bank webhooks for NEFT/RTGS releases',
    tasksCompletedToday: 33,
    confidenceScore: 99,
    recentActivity: 'Approved SO-4402 after verifying ₹2.10L RTGS credit'
  },
  {
    id: 'agent-8',
    name: 'AI Warranty, AMC & Service Agent',
    code: 'SERVICE',
    description: 'Tracks serial-level warranty countdowns (90/60/30 days) and dispatches field technicians for SLAs.',
    status: 'PROCESSING',
    currentTask: 'Dispatching Sachin Kamble to TechCorp BKC for motherboard diagnostics',
    tasksCompletedToday: 19,
    confidenceScore: 94,
    recentActivity: 'Generated automated AMC renewal quote for 45 ThinkPads'
  }
];

export const INITIAL_AUDIT_LOGS: AuditEvent[] = [
  {
    id: 'AUD-991',
    timestamp: '2026-09-04 08:46:12',
    agent: 'AI Pricing Agent',
    action: 'APPROVAL_REQUESTED',
    entityType: 'QUOTATION',
    entityId: 'QT-2026-089',
    details: 'Quotation QT-2026-089 calculated margin of 14.1% violates Auto-Approve rule (≥15.0%). Dispatched to Telegram Command Hub for Owner override.',
    rulesChecked: 'Rule #23: Margin < 15% requires Telegram Owner Authorization',
    approvalRequired: true,
    status: 'ESCALATED'
  },
  {
    id: 'AUD-990',
    timestamp: '2026-09-04 08:32:05',
    agent: 'AI Solution & BOM Engine',
    action: 'BOM_VALIDATION_SUCCESS',
    entityType: 'BOM',
    entityId: 'BOM-1091',
    details: 'Hardware compatibility verified: Dual Xeon Silver 4410Y with 128GB DDR5 ECC RDIMM & Dual Redundant 1100W PSU verified. Zero compatibility conflicts.',
    rulesChecked: 'Rule #14: Server Socket, ECC DDR5 & Redundant PSU Rule',
    approvalRequired: false,
    status: 'AUTO_EXECUTED'
  },
  {
    id: 'AUD-989',
    timestamp: '2026-09-04 08:14:40',
    agent: 'AI Procurement Agent',
    action: 'RFQ_AUTO_DISPATCH',
    entityType: 'RFQ',
    entityId: 'RFQ-2026-44',
    details: 'Critical stock threshold triggered for Fortinet FG-60F (2 units remaining). Auto-dispatched RFQ to Redington, Ingram Micro & Savex.',
    rulesChecked: 'Rule #17: Low Stock Reorder Threshold (< 3 units)',
    approvalRequired: false,
    status: 'AUTO_EXECUTED'
  },
  {
    id: 'AUD-988',
    timestamp: '2026-09-04 07:55:19',
    agent: 'AI Lead Agent',
    action: 'LEAD_ENRICHED_HOT',
    entityType: 'LEAD',
    entityId: 'LD-1092',
    details: 'Customer GSTIN 27AABCF1290K1ZP verified active. Intent score calculated as 94/100 based on immediate delivery mandate and confirmed budget.',
    rulesChecked: 'Rule #7: AI Lead Scoring & GSTIN Verification',
    approvalRequired: false,
    status: 'AUTO_EXECUTED'
  }
];

export const INITIAL_SALES_ORDERS: SalesOrder[] = [
  {
    id: 'SO-2026-081',
    orderNumber: 'SO-2026-081',
    quoteId: 'QT-2026-042',
    customerId: 'CUST-101',
    customerName: 'FinStack Technologies Ltd',
    customerGst: '27AABCF1290K1ZP',
    items: [
      {
        sku: 'LNV-T14-G4',
        productName: 'Lenovo ThinkPad T14 Gen 4 i7 32GB 1TB SSD',
        qty: 10,
        unitPrice: 108000,
        total: 1080000,
        serialNumbers: ['PF49X001', 'PF49X002', 'PF49X003', 'PF49X004', 'PF49X005']
      },
      {
        sku: 'CSC-C1200-24P',
        productName: 'Cisco Catalyst 1200 24-Port Gigabit PoE Managed Switch',
        qty: 2,
        unitPrice: 52000,
        total: 104000,
        serialNumbers: ['FOC2401A091', 'FOC2401A092']
      }
    ],
    subtotal: 1184000,
    gstAmount: 213120,
    totalAmount: 1397120,
    paymentStatus: 'ADVANCE_RECEIVED',
    fulfillmentStatus: 'DISPATCHED',
    courierName: 'BlueDart Express',
    awbNumber: 'BLUEDART-88291044',
    eWayBillNumber: '271890341129',
    irnNumber: '7a98b1c4e9f02381290bb3410a8e990c741289df',
    destinationCity: 'Mumbai, Maharashtra',
    deliveryAddress: 'Unit 402, Nesco IT Park, Goregaon East, Mumbai 400063',
    createdDate: '2026-09-02',
    expectedDelivery: '2026-09-05'
  },
  {
    id: 'SO-2026-082',
    orderNumber: 'SO-2026-082',
    quoteId: 'QT-2026-043',
    customerId: 'CUST-102',
    customerName: 'Apex Health Logistics',
    customerGst: '29AABCA4412L1Z9',
    items: [
      {
        sku: 'DEL-R760-2U',
        productName: 'Dell PowerEdge R760 2U Rack Server (Dual Xeon Silver, 128GB)',
        qty: 2,
        unitPrice: 425000,
        total: 850000,
        serialNumbers: ['DEL-R760-9901', 'DEL-R760-9902']
      }
    ],
    subtotal: 850000,
    gstAmount: 153000,
    totalAmount: 1003000,
    paymentStatus: 'PAID',
    fulfillmentStatus: 'PICKED_IN_QC',
    courierName: 'Delhivery Freight',
    destinationCity: 'Bengaluru, Karnataka',
    deliveryAddress: 'Plot 18, Electronic City Phase 1, Hosur Road, Bengaluru 560100',
    createdDate: '2026-09-03',
    expectedDelivery: '2026-09-07'
  },
  {
    id: 'SO-2026-083',
    orderNumber: 'SO-2026-083',
    customerId: 'CUST-103',
    customerName: 'Navi Mumbai Cold Storage Pvt Ltd',
    customerGst: '27AABCN8821M1Z1',
    items: [
      {
        sku: 'FTN-FG-60F',
        productName: 'Fortinet FortiGate 60F Hardware Firewall with 3-Yr UTP',
        qty: 1,
        unitPrice: 62000,
        total: 62000,
        serialNumbers: ['FGT60FTK2301992']
      }
    ],
    subtotal: 62000,
    gstAmount: 11160,
    totalAmount: 73160,
    paymentStatus: 'PAID',
    fulfillmentStatus: 'DELIVERED',
    courierName: 'Safexpress Logistics',
    awbNumber: 'SAFEX-9981204',
    eWayBillNumber: '271890349921',
    destinationCity: 'Navi Mumbai, Maharashtra',
    deliveryAddress: 'Sector 19, Vashi Turbhe MIDC, Navi Mumbai 400705',
    createdDate: '2026-08-30',
    expectedDelivery: '2026-09-02'
  }
];

export const INITIAL_WORK_ORDERS: InstallationWorkOrder[] = [
  {
    id: 'WO-2026-19',
    workOrderNumber: 'WO-2026-19',
    orderId: 'SO-2026-081',
    customerName: 'FinStack Technologies Ltd',
    siteAddress: 'Unit 402, Nesco IT Park, Goregaon East, Mumbai',
    hardwareSummary: '45x Lenovo ThinkPad deployment + 3x Cisco Catalyst VLAN/PoE Configuration',
    assignedTechnician: 'Suresh Patil (Senior Field Engineer)',
    technicianPhone: '+91 98204 99182',
    scheduledDate: '2026-09-06',
    status: 'SCHEDULED',
    checklist: [
      { item: 'Power and Rack Mount Verification', done: true },
      { item: 'Cisco IOS-XE Firmware upgrade to 17.9.4', done: true },
      { item: 'VLAN 10 (Data) & VLAN 20 (Voice) Tagging', done: false },
      { item: 'ThinkPad Windows 11 Enterprise Autopilot Provisioning', done: false },
      { item: 'Customer IT Acceptance Signature & Signoff', done: false }
    ],
    customerSignoff: false,
    remarks: 'Customer IT Manager requested Saturday afternoon downtime window.'
  },
  {
    id: 'WO-2026-20',
    workOrderNumber: 'WO-2026-20',
    orderId: 'SO-2026-083',
    customerName: 'Navi Mumbai Cold Storage Pvt Ltd',
    siteAddress: 'Sector 19, Vashi Turbhe MIDC, Navi Mumbai',
    hardwareSummary: 'Fortinet FortiGate 60F Dual-WAN Failover & IPsec VPN Setup',
    assignedTechnician: 'Amit Verma (Network Specialist)',
    technicianPhone: '+91 98112 33491',
    scheduledDate: '2026-09-03',
    status: 'COMPLETED',
    checklist: [
      { item: 'Firmware upgrade to FortiOS 7.4.3', done: true },
      { item: 'Dual WAN Failover (Airtel Primary + Tata Secondary)', done: true },
      { item: 'IPsec Site-to-Site Tunnel with HQ', done: true },
      { item: 'UTP Threat Prevention & Anti-Virus Policies', done: true },
      { item: 'Customer Signoff & Service Report Delivered', done: true }
    ],
    customerSignoff: true,
    remarks: 'Signed off by IT Head. Client requested quote for 5x PoE APs.'
  }
];

export const INITIAL_RMAS: RMARequest[] = [
  {
    id: 'RMA-2026-04',
    rmaNumber: 'RMA-2026-04',
    customerName: 'FinStack Technologies Ltd',
    serialNumber: 'PF49X099',
    productModel: 'Lenovo ThinkPad T14 Gen 4',
    issueReported: 'Display backlight flickering and intermittent USB-C Thunderbolt charging failure.',
    status: 'UNDER_DIAGNOSTICS',
    pickupAddress: 'Nesco IT Park, Goregaon East, Mumbai',
    technicianAssigned: 'Suresh Patil',
    createdDate: '2026-09-01'
  }
];

export const INITIAL_PARTNERS: PartnerAccount[] = [
  {
    id: 'PARTNER-01',
    partnerName: 'SysNet Infotech Solutions LLP',
    partnerType: 'SYSTEM_INTEGRATOR',
    tier: 'PLATINUM',
    contactPerson: 'Kunal Singhania (Director)',
    email: 'kunal@sysnetinfo.com',
    phone: '+91 98205 11988',
    city: 'Pune / Mumbai',
    discountMarginPct: 18.0,
    registeredDealsCount: 14,
    totalRevenueGenerated: 8400000,
    commissionEarned: 336000,
    commissionPaid: 280000
  },
  {
    id: 'PARTNER-02',
    partnerName: 'Vega Tech Networks Pvt Ltd',
    partnerType: 'REGIONAL_RESELLER',
    tier: 'GOLD',
    contactPerson: 'Meera Rao (Partner Head)',
    email: 'meera@vegatech.co.in',
    phone: '+91 98450 66201',
    city: 'Bengaluru',
    discountMarginPct: 15.0,
    registeredDealsCount: 8,
    totalRevenueGenerated: 4200000,
    commissionEarned: 168000,
    commissionPaid: 168000
  },
  {
    id: 'PARTNER-03',
    partnerName: 'Apex Cloud & Infra Partners',
    partnerType: 'OEM_PARTNER',
    tier: 'SILVER',
    contactPerson: 'Nitin Sharma',
    email: 'nitin@apexcloud.in',
    phone: '+91 98111 88302',
    city: 'Delhi NCR',
    discountMarginPct: 12.0,
    registeredDealsCount: 4,
    totalRevenueGenerated: 1950000,
    commissionEarned: 78000,
    commissionPaid: 50000
  }
];

export const INITIAL_DEAL_REGISTRATIONS: DealRegistration[] = [
  {
    id: 'DEAL-881',
    dealNumber: 'DR-2026-881',
    partnerId: 'PARTNER-01',
    partnerName: 'SysNet Infotech Solutions LLP',
    endCustomerName: 'Bharat Auto Components Ltd',
    solutionType: 'Dell EMC Server Refresh + 10G SAN Storage',
    estimatedValue: 3800000,
    status: 'LOCKED_APPROVED',
    validUntil: '2026-10-30',
    protectionDaysRemaining: 56
  },
  {
    id: 'DEAL-882',
    dealNumber: 'DR-2026-882',
    partnerId: 'PARTNER-02',
    partnerName: 'Vega Tech Networks Pvt Ltd',
    endCustomerName: 'BioHealth Research Labs',
    solutionType: '60x HP ZBook Mobile Workstations + NVIDIA RTX 4000',
    estimatedValue: 7200000,
    status: 'PENDING_REVIEW',
    validUntil: '2026-10-15',
    protectionDaysRemaining: 41
  }
];

export const INITIAL_COMMISSIONS: CommissionRecord[] = [
  {
    id: 'COMM-101',
    partnerName: 'SysNet Infotech Solutions LLP',
    salesOrderNumber: 'SO-2026-074',
    dealValue: 2400000,
    commissionRatePct: 4.0,
    commissionAmount: 96000,
    payoutStatus: 'PROCESSED',
    disbursedDate: '2026-08-28'
  },
  {
    id: 'COMM-102',
    partnerName: 'Vega Tech Networks Pvt Ltd',
    salesOrderNumber: 'SO-2026-079',
    dealValue: 1800000,
    commissionRatePct: 4.0,
    commissionAmount: 72000,
    payoutStatus: 'PENDING_APPROVAL'
  }
];

export const INITIAL_WORKFLOW_RULES: WorkflowRule[] = [
  {
    id: 'WF-01',
    ruleCode: 'RULE_FOLLOWUP_24H',
    name: 'Autonomous Quotation Follow-up (24h)',
    triggerEvent: 'QuoteCreated',
    condition: 'CustomerStatus == PENDING && HoursSinceQuote >= 24',
    aiDecision: 'Evaluate customer intent score; compose personalized WhatsApp message highlighting stock reservation timer.',
    action: 'Send WhatsApp Follow-up with 1-Click Order Link',
    channel: 'WHATSAPP',
    status: 'ACTIVE',
    executionsCount: 38,
    lastTriggered: '10 mins ago'
  },
  {
    id: 'WF-02',
    ruleCode: 'RULE_LOW_STOCK_RFQ',
    name: 'Critical Stock Shortage RFQ Broadcast',
    triggerEvent: 'StockLevel < ReorderPoint',
    condition: 'AvailableStock <= 2 && OpenOrdersCount > 0',
    aiDecision: 'Determine lowest landing cost supplier based on historical delivery reliability score (>85).',
    action: 'Auto-Broadcast RFQ to Redington, Ingram Micro & Savex',
    channel: 'SYSTEM_EVENT',
    status: 'ACTIVE',
    executionsCount: 19,
    lastTriggered: '1 hour ago'
  },
  {
    id: 'WF-03',
    ruleCode: 'RULE_MARGIN_EXCEPTION',
    name: 'Low Margin Owner Approval Gate (< 15%)',
    triggerEvent: 'QuoteCalculated',
    condition: 'CalculatedMarginPct < CompanyProfile.defaultMarginThreshold',
    aiDecision: 'Format instant interactive Telegram Card with P&L breakdown and 1-tap Approve/Reject action.',
    action: 'Dispatch Telegram Approval Card to Owner',
    channel: 'TELEGRAM',
    status: 'ACTIVE',
    executionsCount: 64,
    lastTriggered: '32 mins ago'
  },
  {
    id: 'WF-04',
    ruleCode: 'RULE_AMC_EXPIRATION_ALERT',
    name: 'Autonomous AMC Contract Renewal Notice (30 Days)',
    triggerEvent: 'AMCDueDateApproaching',
    condition: 'DaysRemaining <= 30 && ContractStatus == ACTIVE',
    aiDecision: 'Calculate renewal quote with 5% inflation buffer and previous service ticket history.',
    action: 'Draft Proforma Renewal Invoice & Email Procurement Head',
    channel: 'EMAIL',
    status: 'ACTIVE',
    executionsCount: 12,
    lastTriggered: '4 hours ago'
  }
];

export const INITIAL_EVENT_BUS_MESSAGES: EventBusMessage[] = [
  {
    id: 'EVT-9921',
    eventId: 'EVT-9921',
    eventType: 'PaymentReceived',
    sourceAgent: 'Finance AI Agent',
    targetModule: 'Warehouse & Fulfillment',
    payloadSnippet: 'Invoice INV-2026-081 settled ₹13,97,120 via ICICI RTGS. Released for Dispatch.',
    status: 'PROCESSED',
    latencyMs: 38,
    timestamp: '2026-09-04 11:22:10'
  },
  {
    id: 'EVT-9920',
    eventId: 'EVT-9920',
    eventType: 'StockShortageDetected',
    sourceAgent: 'Inventory AI Agent',
    targetModule: 'Procurement Engine',
    payloadSnippet: 'SKU FTN-FG-60F stock at Bhiwandi reached 2 units. Reorder point triggered.',
    status: 'PROCESSED',
    latencyMs: 44,
    timestamp: '2026-09-04 11:15:02'
  },
  {
    id: 'EVT-9919',
    eventId: 'EVT-9919',
    eventType: 'QuoteApproved',
    sourceAgent: 'Telegram Owner Command',
    targetModule: 'CRM & Sales Agent',
    payloadSnippet: 'QT-2026-042 approved by Owner via Telegram at 14.2% margin. Sales Order generated.',
    status: 'ACKNOWLEDGED',
    latencyMs: 12,
    timestamp: '2026-09-04 10:48:33'
  },
  {
    id: 'EVT-9918',
    eventId: 'EVT-9918',
    eventType: 'LeadCaptured',
    sourceAgent: 'WhatsApp Inbound Bot',
    targetModule: 'Lead Enrichment Engine',
    payloadSnippet: 'Lead LD-1092 captured from WhatsApp (+91 98201 44520) with high corporate intent.',
    status: 'PROCESSED',
    latencyMs: 52,
    timestamp: '2026-09-04 10:14:18'
  }
];

export const INITIAL_KNOWLEDGE_DOCS: KnowledgeDocument[] = [
  {
    id: 'DOC-01',
    title: 'AadiTech Hi-REL Military Grade DC-DC Converter Technical Datasheet',
    category: 'HARDWARE_DATASHEET',
    productLine: 'AadiTech Power Storage & Conversion',
    snippet: 'Input voltage: 18-36V DC, Output: 24V / 20.8A (500W). Operating temperature: -40°C to +85°C MIL-STD-810G compliant. Mean Time Between Failures (MTBF): 450,000 hours.',
    docSize: '2.4 MB',
    lastUpdated: '2026-08-15'
  },
  {
    id: 'DOC-02',
    title: 'Enterprise Server & SAN Storage SLA & AMC Response Matrix',
    category: 'SLA_TERMS',
    productLine: 'Dell EMC, Lenovo & Cisco Networking',
    snippet: 'Critical Severity 1 outages require 4-hour on-site technician response across Mumbai MMR, Delhi NCR, and Bengaluru. 99.95% hardware uptime guarantee with redundant cold spares.',
    docSize: '1.1 MB',
    lastUpdated: '2026-08-20'
  },
  {
    id: 'DOC-03',
    title: 'AadiTech Reverse Logistics & DOA / RMA Hardware Replacement Policy',
    category: 'RMA_PROCEDURE',
    productLine: 'All IT Infrastructure Hardware',
    snippet: 'Dead-On-Arrival (DOA) within 14 days of delivery qualifies for instant advance replacement prior to supplier warranty claim return. Mandatory serial barcode capture required.',
    docSize: '850 KB',
    lastUpdated: '2026-09-01'
  }
];

// ==========================================
// Sections 54 - 60: Predictive Analytics & Forecasting Datasets
// ==========================================

export const INITIAL_DEAD_STOCK: DeadStockItem[] = [
  {
    id: 'DS-01',
    sku: 'CSCO-2960-24TT',
    productName: 'Cisco Catalyst 2960-Plus 24 10/100 Switch',
    warehouse: 'Bhiwandi Central Hub (MH)',
    ageDays: 142,
    qty: 4,
    unitBookCost: 26000,
    totalBookValue: 104000,
    estimatedMarketValue: 82000,
    monthlyHoldingCost: 1850,
    aiRecommendation: 'LIQUIDATE_25_DISCOUNT',
    recommendationNote: 'Fast deprecation due to Gigabit migration. Offer 25% promo discount to educational/SMB customer segment.',
    status: 'PENDING_ACTION'
  },
  {
    id: 'DS-02',
    sku: 'KNG-ECC-DDR4-16',
    productName: 'Kingston 16GB DDR4-2666MHz ECC Registered DIMM',
    warehouse: 'Delhi Okhla Hub',
    ageDays: 118,
    qty: 12,
    unitBookCost: 4800,
    totalBookValue: 57600,
    estimatedMarketValue: 46000,
    monthlyHoldingCost: 960,
    aiRecommendation: 'BUNDLE_WITH_SERVERS',
    recommendationNote: 'Bundle at zero markup with pending Dell R760 / refurbished server quotations to clear remaining stock.',
    status: 'PENDING_ACTION'
  },
  {
    id: 'DS-03',
    sku: 'APC-BATT-CARTRIDGE',
    productName: 'APC Replacement Battery Cartridge #140',
    warehouse: 'Bangalore Electronic City Hub',
    ageDays: 98,
    qty: 3,
    unitBookCost: 14500,
    totalBookValue: 43500,
    estimatedMarketValue: 39000,
    monthlyHoldingCost: 650,
    aiRecommendation: 'CHANNEL_PARTNER_BULK',
    recommendationNote: 'Broadcast bulk discount to UPS AMC maintenance partners in South India network at 12% distributor margin.',
    status: 'OFFER_DISPATCHED'
  }
];

export const INITIAL_DEMAND_FORECASTS: DemandForecast[] = [
  {
    id: 'DF-01',
    category: 'RACK_SERVERS',
    timeHorizon: '30_DAYS',
    predictedUnits: 14,
    currentAvailableStock: 5,
    pipelineDemand: 18,
    recommendedOrderUnits: 12,
    urgency: 'HIGH_STOCKOUT_RISK',
    keyDriver: 'Q3 Enterprise IT Data Center upgrades & private cloud tenders closing before Oct 15.'
  },
  {
    id: 'DF-02',
    category: 'UTM_FIREWALLS',
    timeHorizon: '14_DAYS',
    predictedUnits: 9,
    currentAvailableStock: 3,
    pipelineDemand: 10,
    recommendedOrderUnits: 8,
    urgency: 'HIGH_STOCKOUT_RISK',
    keyDriver: 'High corporate branch office compliance mandate from RBI-regulated fintech clients.'
  },
  {
    id: 'DF-03',
    category: 'POWER_SYSTEMS',
    timeHorizon: '60_DAYS',
    predictedUnits: 22,
    currentAvailableStock: 16,
    pipelineDemand: 20,
    recommendedOrderUnits: 10,
    urgency: 'NORMAL_BUFFER',
    keyDriver: 'Defense radar and industrial turnkey shelter contracts with 45-day staging cycles.'
  },
  {
    id: 'DF-04',
    category: 'LAPTOPS',
    timeHorizon: '7_DAYS',
    predictedUnits: 35,
    currentAvailableStock: 28,
    pipelineDemand: 30,
    recommendedOrderUnits: 15,
    urgency: 'NORMAL_BUFFER',
    keyDriver: 'Ongoing BPO onboarding cycle; stable lead conversion with Redington supplier buffer.'
  }
];

export const INITIAL_SALES_FORECAST: SalesForecastSummary = {
  period: 'NEXT_30_DAYS',
  pipelineDealsCount: 28,
  grossPipelineValue: 6450000,
  weightedProjectedRevenue: 4850000,
  projectedGrossProfit: 834200,
  projectedMarginPct: 17.2,
  historicalWinRatePct: 75.2,
  topDeals: [
    { customerName: 'TechCorp India Solutions Ltd', value: 1450000, probabilityPct: 85, stage: 'Negotiation / Price Gate' },
    { customerName: 'Bharat Petroleum Allied Logistics', value: 890000, probabilityPct: 80, stage: 'Quotation Sent' },
    { customerName: 'Apex Defense Research Lab', value: 1850000, probabilityPct: 65, stage: 'BOM Solution Approved' },
    { customerName: 'Tata Telematics Operations', value: 660000, probabilityPct: 90, stage: 'Verbal Acceptance' }
  ]
};

export const INITIAL_CASH_FLOW_FORECAST: CashFlowForecastItem[] = [
  {
    month: 'Sep 2026 (Current)',
    expectedCollections: 4250000,
    supplierPayables: 2890000,
    operatingExpenses: 540000,
    gstPayableEstimate: 185000,
    netCashFlow: 635000,
    projectedClosingBalance: 2450000,
    runwayStatus: 'OPTIMAL'
  },
  {
    month: 'Oct 2026',
    expectedCollections: 5100000,
    supplierPayables: 3450000,
    operatingExpenses: 550000,
    gstPayableEstimate: 220000,
    netCashFlow: 880000,
    projectedClosingBalance: 3330000,
    runwayStatus: 'OPTIMAL'
  },
  {
    month: 'Nov 2026',
    expectedCollections: 3900000,
    supplierPayables: 3100000,
    operatingExpenses: 560000,
    gstPayableEstimate: 160000,
    netCashFlow: 80000,
    projectedClosingBalance: 3410000,
    runwayStatus: 'MODERATE_SURPLUS'
  },
  {
    month: 'Dec 2026',
    expectedCollections: 5800000,
    supplierPayables: 4200000,
    operatingExpenses: 580000,
    gstPayableEstimate: 260000,
    netCashFlow: 760000,
    projectedClosingBalance: 4170000,
    runwayStatus: 'OPTIMAL'
  }
];

export const INITIAL_NEXT_BEST_ACTIONS: NextBestAction[] = [
  {
    id: 'NBA-01',
    entityType: 'QUOTE',
    entityName: 'TechCorp India Solutions (QT-2026-042)',
    priority: 'URGENT',
    actionTitle: 'Trigger Telegram Approval for 14.1% Margin',
    rationale: 'Customer agreed to issue PO within 4 hours if quote price locked at ₹11,40,000. Owner Telegram sign-off unlocks deal.',
    projectedRevenueImpact: 1140000,
    suggestedChannel: 'TELEGRAM',
    status: 'RECOMMENDED'
  },
  {
    id: 'NBA-02',
    entityType: 'WARRANTY',
    entityName: 'Zomato Regional Kitchen Operations',
    priority: 'HIGH',
    actionTitle: 'Dispatch AMC 3-Year Extension Offer',
    rationale: '12x Dell OptiPlex desktop OEM warranties expire in 16 days. High historical service reliance.',
    projectedRevenueImpact: 125000,
    suggestedChannel: 'WHATSAPP',
    status: 'RECOMMENDED'
  },
  {
    id: 'NBA-03',
    entityType: 'LEAD',
    entityName: 'Rohan Deshmukh (VP Infrastructure)',
    priority: 'HIGH',
    actionTitle: 'Send WhatsApp Technical Comparison: Dell R760 vs HP DL380',
    rationale: 'Lead opened quotation twice today. Proactive benchmark comparison resolves technical indecision.',
    projectedRevenueImpact: 850000,
    suggestedChannel: 'WHATSAPP',
    status: 'RECOMMENDED'
  },
  {
    id: 'NBA-04',
    entityType: 'CUSTOMER',
    entityName: 'Alpha Infotech Subcontracting',
    priority: 'MEDIUM',
    actionTitle: 'Propose Server Cold Spare Contract',
    rationale: 'Client operating 24/7 financial processing with zero redundant backup UPS modules.',
    projectedRevenueImpact: 240000,
    suggestedChannel: 'EMAIL',
    status: 'RECOMMENDED'
  }
];

export const INITIAL_LOST_DEALS: LostDealAnalysis[] = [
  {
    id: 'LD-LOST-01',
    dealNumber: 'DEAL-2026-009',
    customerName: 'Fintech Cloud Technologies Pune',
    productRequested: '20x Cisco Business 350 Gigabit Switches',
    dealValue: 480000,
    primaryLossReason: 'PRICE_TOO_HIGH',
    competitorWinner: 'Netcom Solutions (Authorized Tier 1)',
    lossDate: '2026-08-28',
    aiPostMortemInsight: 'Competitor passed 2.5% special rebate directly to customer without registering deal protection.',
    correctiveStrategy: 'Enforce early Cisco Deal Registration on all switch inquiries >₹3L to protect 5% wholesale discount.'
  },
  {
    id: 'LD-LOST-02',
    dealNumber: 'DEAL-2026-014',
    customerName: 'Omega Pharma Research Mumbai',
    productRequested: '2x High Performance Workstations with RTX 4090',
    dealValue: 620000,
    primaryLossReason: 'DELIVERY_LEAD_TIME',
    competitorWinner: 'Direct Dell Premier Portal',
    lossDate: '2026-08-19',
    aiPostMortemInsight: 'Customer required 24-hour delivery for urgent molecular simulation. Our lead time was 5 working days.',
    correctiveStrategy: 'Maintain 1 unit high-end GPU workstation as pre-configured rapid-dispatch buffer in Bhiwandi Hub.'
  },
  {
    id: 'LD-LOST-03',
    dealNumber: 'DEAL-2026-003',
    customerName: 'Zenith Logistics Hub Navi Mumbai',
    productRequested: '30x Rugged Barcode Handheld Scanners & Access Points',
    dealValue: 750000,
    primaryLossReason: 'STRICT_CREDIT_TERMS',
    competitorWinner: 'Allied Micro Distribution',
    lossDate: '2026-08-10',
    aiPostMortemInsight: 'Client demanded 60-day open credit terms; system credit risk algorithm held deal at 100% advance requirement.',
    correctiveStrategy: 'Offer bank letter of credit (LC) or 30% advance + 30-day PDC terms for verified corporate entities.'
  }
];

export const INITIAL_CUSTOMER_LTVS: CustomerLTVAnalysis[] = [
  {
    id: 'LTV-01',
    customerName: 'TechCorp India Solutions Ltd',
    industry: 'Enterprise Software & IT Services',
    currentLifetimeSpend: 2840000,
    projected3YearLTV: 7200000,
    expansionOpportunities: [
      { opportunityName: 'Comprehensive Server & Network AMC Renewal', potentialValue: 350000, readiness: 'IMMEDIATE' },
      { opportunityName: 'Core Firewall Migration to Fortinet 100F', potentialValue: 680000, readiness: 'NEXT_QUARTER' },
      { opportunityName: 'Turnkey Hybrid Cloud SAN Storage Tier', potentialValue: 1800000, readiness: 'LONG_TERM' }
    ],
    retentionRisk: 'LOW'
  },
  {
    id: 'LTV-02',
    customerName: 'Zomato Regional Kitchen Operations',
    industry: 'FoodTech & Multi-Location Retail Logistics',
    currentLifetimeSpend: 1420000,
    projected3YearLTV: 3900000,
    expansionOpportunities: [
      { opportunityName: 'Desktop Fleet Refresh (25x Mini PCs)', potentialValue: 950000, readiness: 'IMMEDIATE' },
      { opportunityName: 'High-Density Rugged PoE Switches for Kitchens', potentialValue: 420000, readiness: 'NEXT_QUARTER' }
    ],
    retentionRisk: 'LOW'
  },
  {
    id: 'LTV-03',
    customerName: 'Bharat Petroleum Allied Logistics',
    industry: 'Energy & Heavy Transport Automation',
    currentLifetimeSpend: 890000,
    projected3YearLTV: 3400000,
    expansionOpportunities: [
      { opportunityName: 'MIL-STD DC-DC Power Storage Backups', potentialValue: 850000, readiness: 'IMMEDIATE' },
      { opportunityName: 'Remote Terminal Telematics Server Integration', potentialValue: 1200000, readiness: 'LONG_TERM' }
    ],
    retentionRisk: 'MEDIUM'
  }
];

// ==========================================
// Sections 3, 4, 61, 62, 64, 65, 66: System, Multi-Tenant & Observability Datasets
// ==========================================

export const INITIAL_TENANTS: TenantAccount[] = [
  {
    id: 'TEN-01',
    tenantCode: 'ATS-HQ-MH',
    companyName: 'AadiTech Solution (Mumbai HQ)',
    gstin: '27AABCA9988K1Z5',
    stateCode: '27 (Maharashtra)',
    operatingCurrency: 'INR (₹)',
    activeUsersCount: 14,
    plan: 'ENTERPRISE_DISTRIBUTOR',
    storageQuotaMb: 10000,
    storageUsedMb: 1840,
    status: 'ACTIVE',
    isCurrent: true
  },
  {
    id: 'TEN-02',
    tenantCode: 'ATS-NCR-DL',
    companyName: 'AadiTech North Regional Division (Delhi NCR)',
    gstin: '07AABCA9988K1ZD',
    stateCode: '07 (Delhi)',
    operatingCurrency: 'INR (₹)',
    activeUsersCount: 6,
    plan: 'SYSTEM_INTEGRATOR_PRO',
    storageQuotaMb: 5000,
    storageUsedMb: 620,
    status: 'ACTIVE',
    isCurrent: false
  },
  {
    id: 'TEN-03',
    tenantCode: 'ATS-DEF-HIREL',
    companyName: 'AadiTech Defense & Industrial Turnkey Power Systems',
    gstin: '27AABCA9988K2Z4',
    stateCode: '27 (Maharashtra)',
    operatingCurrency: 'INR (₹)',
    activeUsersCount: 8,
    plan: 'ENTERPRISE_DISTRIBUTOR',
    storageQuotaMb: 10000,
    storageUsedMb: 940,
    status: 'ACTIVE',
    isCurrent: false
  }
];

export const INITIAL_USER_ROLES: UserRoleDefinition[] = [
  {
    roleId: 'SUPER_ADMIN',
    roleName: 'Platform Super Administrator',
    department: 'Executive Operations',
    allowedActions: ['ALL_PERMISSIONS', 'TENANT_PROVISIONING', 'SECURITY_POLICY_OVERRIDE', 'ENCRYPTION_KEY_ROTATE', 'SYSTEM_AUDIT_PURGE_OVERRIDE'],
    restrictedActions: [],
    description: 'Complete unrestricted governance across multi-tenant database clusters, cloud connectors, and API gateways.'
  },
  {
    roleId: 'BUSINESS_OWNER',
    roleName: 'Managing Director / Business Owner',
    department: 'Executive Management',
    allowedActions: ['TELEGRAM_MARGIN_APPROVAL', 'FINANCIAL_REPORTS_EXPORT', 'WORKFLOW_RULE_OVERRIDE', 'CREDIT_LIMIT_EXPANSION', 'BANK_RECONCILIATION_SIGN_OFF'],
    restrictedActions: ['DELETE_AUDIT_LOGS', 'DIRECT_DB_MANIPULATION'],
    description: 'Primary recipient of Telegram exception gates, commercial threshold overrides, and profit analytics.'
  },
  {
    roleId: 'SALES_MANAGER',
    roleName: 'Enterprise Sales Manager',
    department: 'Sales & Business Development',
    allowedActions: ['CREATE_LEAD', 'GENERATE_BOM', 'DISPATCH_QUOTE', 'REQUEST_MARGIN_OVERRIDE', 'VIEW_CUSTOMER_360', 'REGISTER_DEAL'],
    restrictedActions: ['APPROVE_SUB_15_MARGIN', 'OVERRIDE_CREDIT_RISK', 'MODIFY_SUPPLIER_PRICING'],
    description: 'Coordinates customer proposals, AI quotation negotiations within 15% margin boundaries, and deal protection locks.'
  },
  {
    roleId: 'PURCHASE_MANAGER',
    roleName: 'Procurement & Supplier Specialist',
    department: 'Supply Chain Operations',
    allowedActions: ['CREATE_RFQ', 'COMPARE_SUPPLIERS', 'ISSUE_PURCHASE_ORDER', 'APPROVE_GRN_INWARD', 'SUPPLIER_SCORE_ADJUST'],
    restrictedActions: ['APPROVE_PO_ABOVE_10L_WITHOUT_OWNER', 'ACCESS_SALES_COMMISSIONS'],
    description: 'Manages distributor contracts across Redington, Ingram Micro, and Savex with landed cost optimization.'
  },
  {
    roleId: 'WAREHOUSE_MANAGER',
    roleName: 'Logistics & Warehouse QC In-Charge',
    department: 'Fulfillment & Inventory',
    allowedActions: ['SERIAL_BARCODE_SCAN', 'QC_SEAL_APPROVAL', 'COURIER_AWB_GENERATION', 'E_WAY_BILL_TRANSMIT', 'DEAD_STOCK_INSPECTION'],
    restrictedActions: ['MODIFY_PRODUCT_COST', 'APPROVE_CUSTOMER_DISCOUNTS', 'SIGN_OFF_PAYMENT_TERMS'],
    description: 'Oversees Bhiwandi, Delhi, and Bangalore inventory hubs with barcode allocation and courier dispatch.'
  },
  {
    roleId: 'FINANCE_MANAGER',
    roleName: 'Chief Financial Officer / Head Accountant',
    department: 'Finance & Compliance',
    allowedActions: ['GST_INVOICE_GENERATION', 'E_INVOICE_IRN_SUBMIT', 'DEBTOR_OUTSTANDING_AUDIT', 'COMMISSION_PAYOUT_SIGN_OFF', 'TALLY_SYNC'],
    restrictedActions: ['BYPASS_GST_RULES', 'DELETE_INVOICE_RECORDS'],
    description: 'Controls tax calculations, GSTIN validation, invoice numbering, credit control, and bank reconciliation.'
  }
];

export const INITIAL_SYSTEM_HEALTH: SystemHealthMetric[] = [
  {
    serviceId: 'SVC-01',
    serviceName: 'Core REST API Gateway (v4.2)',
    category: 'API',
    status: 'OPERATIONAL',
    latencyMs: 18,
    uptimePercentage: 99.98,
    lastChecked: 'Just now',
    endpointsActive: 46
  },
  {
    serviceId: 'SVC-02',
    serviceName: 'High-Throughput Event Bus (Kafka/Redis)',
    category: 'EVENT_BUS',
    status: 'OPERATIONAL',
    latencyMs: 8,
    uptimePercentage: 99.99,
    lastChecked: 'Just now',
    endpointsActive: 28
  },
  {
    serviceId: 'SVC-03',
    serviceName: 'PostgreSQL & pgvector Knowledge Store',
    category: 'DATABASE',
    status: 'OPERATIONAL',
    latencyMs: 12,
    uptimePercentage: 100.0,
    lastChecked: 'Just now',
    endpointsActive: 64
  },
  {
    serviceId: 'SVC-04',
    serviceName: 'Telegram Bot Autonomous Webhook',
    category: 'MESSAGING',
    status: 'OPERATIONAL',
    latencyMs: 34,
    uptimePercentage: 99.95,
    lastChecked: 'Just now',
    endpointsActive: 8
  },
  {
    serviceId: 'SVC-05',
    serviceName: 'WhatsApp Cloud Business API',
    category: 'MESSAGING',
    status: 'OPERATIONAL',
    latencyMs: 86,
    uptimePercentage: 99.91,
    lastChecked: 'Just now',
    endpointsActive: 4
  },
  {
    serviceId: 'SVC-06',
    serviceName: 'National GST e-Invoice & e-Way Bill NIC Gateway',
    category: 'COMPLIANCE',
    status: 'OPERATIONAL',
    latencyMs: 142,
    uptimePercentage: 99.82,
    lastChecked: '1 min ago',
    endpointsActive: 3
  },
  {
    serviceId: 'SVC-07',
    serviceName: 'Razorpay / ICICI Bank RTGS Gateway',
    category: 'ERP_SYNC',
    status: 'OPERATIONAL',
    latencyMs: 64,
    uptimePercentage: 99.97,
    lastChecked: 'Just now',
    endpointsActive: 6
  },
  {
    serviceId: 'SVC-08',
    serviceName: 'Tally Prime & Zoho Books Two-Way Sync Connector',
    category: 'ERP_SYNC',
    status: 'OPERATIONAL',
    latencyMs: 110,
    uptimePercentage: 99.88,
    lastChecked: '2 mins ago',
    endpointsActive: 5
  }
];

export const INITIAL_DEAD_LETTER_JOBS: DeadLetterJob[] = [
  {
    id: 'DLQ-01',
    jobName: 'Courier AWB Status Webhook Retry',
    sourceModule: 'Delhivery Logistics API',
    targetDestination: 'Orders & Fulfillment Engine',
    payloadSummary: 'Order SO-2026-102 AWB DELH-882190 status transition: OUT_FOR_DELIVERY',
    errorMessage: 'HTTP 504 Gateway Timeout on webhook receiver during peak burst',
    retryCount: 2,
    maxRetries: 5,
    status: 'RETRYING',
    failedAt: '2026-09-05 14:18:22'
  },
  {
    id: 'DLQ-02',
    jobName: 'Lead Telemetry Webhook Ingest',
    sourceModule: 'IndiaMART B2B Lead Webhook Bridge',
    targetDestination: 'Lead Intelligence & AI Scoring Agent',
    payloadSummary: 'Lead inquiry: 15x Core i7 Laptops for IT Training Institute Pune',
    errorMessage: 'Temporary rate limit throttle (HTTP 429) from upstream provider',
    retryCount: 4,
    maxRetries: 5,
    status: 'DEAD_LETTER',
    failedAt: '2026-09-05 11:05:44'
  }
];

export const INITIAL_INTEGRATIONS: IntegrationConnector[] = [
  {
    id: 'INT-01',
    name: 'Tally Prime / Zoho Books ERP',
    category: 'ACCOUNTING_ERP',
    provider: 'Tally Solutions / Zoho Corp',
    connectionStatus: 'CONNECTED',
    lastSyncTimestamp: 'Today, 14:30',
    syncedRecordsToday: 142,
    endpointUrl: 'http://localhost:9000/tally-sync-bridge',
    iconType: 'FileSpreadsheet'
  },
  {
    id: 'INT-02',
    name: 'Delhivery Freight & Express API',
    category: 'LOGISTICS_COURIER',
    provider: 'Delhivery Ltd',
    connectionStatus: 'CONNECTED',
    lastSyncTimestamp: 'Today, 15:45',
    syncedRecordsToday: 24,
    endpointUrl: 'https://track.delhivery.com/api/v1/packages',
    iconType: 'Truck'
  },
  {
    id: 'INT-03',
    name: 'BlueDart Apex Couriers',
    category: 'LOGISTICS_COURIER',
    provider: 'BlueDart Express Ltd',
    connectionStatus: 'CONNECTED',
    lastSyncTimestamp: 'Today, 15:12',
    syncedRecordsToday: 18,
    endpointUrl: 'https://api.bluedart.com/servlet/RoutingEngine',
    iconType: 'Package'
  },
  {
    id: 'INT-04',
    name: 'Razorpay Corporate Banking & Payment Gateway',
    category: 'PAYMENT_GATEWAY',
    provider: 'Razorpay Software Pvt Ltd',
    connectionStatus: 'CONNECTED',
    lastSyncTimestamp: 'Today, 16:02',
    syncedRecordsToday: 38,
    endpointUrl: 'https://api.razorpay.com/v1/payment_links',
    iconType: 'CreditCard'
  },
  {
    id: 'INT-05',
    name: 'WhatsApp Cloud Business API',
    category: 'COMMUNICATION',
    provider: 'Meta Platforms Inc',
    connectionStatus: 'CONNECTED',
    lastSyncTimestamp: 'Today, 16:15',
    syncedRecordsToday: 89,
    endpointUrl: 'https://graph.facebook.com/v19.0/messages',
    iconType: 'MessageSquare'
  },
  {
    id: 'INT-06',
    name: 'IndiaMART B2B Lead Push Bridge',
    category: 'B2B_PORTAL',
    provider: 'IndiaMART InterMESH Ltd',
    connectionStatus: 'CONNECTED',
    lastSyncTimestamp: 'Today, 15:50',
    syncedRecordsToday: 12,
    endpointUrl: 'https://mapi.indiamart.com/wservce/enquiry/listing',
    iconType: 'Globe'
  }
];

export const INITIAL_API_ENDPOINTS: ApiEndpointDoc[] = [
  {
    id: 'API-01',
    method: 'GET',
    path: '/api/v1/leads',
    summary: 'Retrieve real-time filtered leads with AI qualification score and intent classification.',
    category: 'LEADS',
    sampleResponse: '{\n  "total": 42,\n  "leads": [\n    { "id": "LD-1092", "name": "Rohan Deshmukh", "score": "HOT", "intentScore": 94 }\n  ]\n}',
    authRequired: true
  },
  {
    id: 'API-02',
    method: 'POST',
    path: '/api/v1/bom/calculate',
    summary: 'Autonomous Bill-of-Materials compilation with hardware compatibility validation.',
    category: 'BOM',
    sampleResponse: '{\n  "bomId": "BOM-2026-99",\n  "subtotal": 1420000,\n  "totalCost": 1180000,\n  "marginPct": 16.9,\n  "compatibilityStatus": "VERIFIED"\n}',
    authRequired: true
  },
  {
    id: 'API-03',
    method: 'GET',
    path: '/api/v1/quotes',
    summary: 'List quotations with approval tier status and margin threshold checks.',
    category: 'QUOTES',
    sampleResponse: '{\n  "quotes": [\n    { "quoteNumber": "QT-2026-042", "status": "PENDING_APPROVAL", "approvalTier": "OWNER_TELEGRAM" }\n  ]\n}',
    authRequired: true
  },
  {
    id: 'API-04',
    method: 'POST',
    path: '/api/v1/orders/dispatch',
    summary: 'Dispatch order, assign courier AWB, allocate serial barcodes, and generate e-Way Bill.',
    category: 'ORDERS',
    sampleResponse: '{\n  "orderNumber": "SO-2026-101",\n  "fulfillmentStatus": "DISPATCHED",\n  "awbNumber": "BD-77218902",\n  "eWayBillNumber": "271890128912"\n}',
    authRequired: true
  },
  {
    id: 'API-05',
    method: 'GET',
    path: '/api/v1/inventory/dead-stock',
    summary: 'Query aged inventory (>90 days) with AI liquidation discount and bundling recommendations.',
    category: 'INVENTORY',
    sampleResponse: '{\n  "deadStockCount": 3,\n  "totalBookValue": 205100,\n  "recommendations": ["LIQUIDATE_25_DISCOUNT", "BUNDLE_WITH_SERVERS"]\n}',
    authRequired: true
  },
  {
    id: 'API-06',
    method: 'GET',
    path: '/api/v1/telemetry/health',
    summary: 'Comprehensive system heartbeat, event bus latency, and DLQ retry queue status.',
    category: 'TELEMETRY',
    sampleResponse: '{\n  "status": "OPERATIONAL",\n  "uptime": 99.98,\n  "eventBusThroughput": "184 msgs/min",\n  "dlqPending": 2\n}',
    authRequired: false
  }
];

export const INITIAL_GEM_TENDERS: GeMTenderBid[] = [
  {
    id: 'GEM-BID-01',
    bidNumber: 'GEM/2026/B/8912',
    departmentName: 'Western Railway Signal & Telecommunication',
    ministry: 'Ministry of Railways, Govt of India',
    title: 'Turnkey Supply of 48V High-Reliability Rugged DC-DC Converters for Interlocking Cabins',
    category: 'POWER_SYSTEMS',
    estimatedBudget: 4200000,
    bidClosingDate: '2026-09-18',
    emdAmount: 0, // MSME / Startup Exempt
    specs: 'Input 110V/48V DC, 1000W Output, MIL-STD 810G compliant, hot-swappable rack chassis, RDSO approved spec.',
    qualificationStatus: 'MATCHED_ATS_PRODUCTS',
    turnkeyMarginEstimate: 28.5
  },
  {
    id: 'GEM-BID-02',
    bidNumber: 'GEM/2026/B/9044',
    departmentName: 'Naval Dockyard Mumbai (DRDO Sub-station)',
    ministry: 'Ministry of Defence',
    title: 'Supply of 2U High-Density Rackmount Server Cluster with 10G SFP+ Networking',
    category: 'SERVERS_STORAGE',
    estimatedBudget: 6800000,
    bidClosingDate: '2026-09-24',
    emdAmount: 136000,
    specs: '4x Dual Xeon Gold 6430, 256GB ECC DDR5, 8x 3.84TB NVMe Enterprise SSDs, TPM 2.0 Hardware Root of Trust.',
    qualificationStatus: 'OEM_MAJ_REQUIRED',
    turnkeyMarginEstimate: 22.0
  },
  {
    id: 'GEM-BID-03',
    bidNumber: 'GEM/2026/B/9180',
    departmentName: 'Brihanmumbai Municipal Corporation (BMC IT Dept)',
    ministry: 'Govt of Maharashtra',
    title: 'Rate Contract for 120x Commercial Laptops (i5/16GB/512GB SSD) with 3-Year On-Site Comprehensive Support',
    category: 'LAPTOPS_COMPUTING',
    estimatedBudget: 8400000,
    bidClosingDate: '2026-09-29',
    emdAmount: 168000,
    specs: 'MIL-STD tested chassis, Win 11 Pro OEM, backlit keyboard, FHD camera with privacy shutter, Lenovo ThinkPad E14 / Dell Vostro equivalent.',
    qualificationStatus: 'MATCHED_ATS_PRODUCTS',
    turnkeyMarginEstimate: 17.5
  }
];

export const INITIAL_OUTBOUND_TARGETS: OutboundProspectAccount[] = [
  {
    id: 'OUT-01',
    companyName: 'NexaPay Cloud Payments Pvt Ltd',
    industry: 'FinTech / Payment Gateway',
    location: 'Bandra Kurla Complex (BKC), Mumbai',
    expansionTrigger: 'Raised Series B ($22M); expanding 35,000 sq.ft engineering floor with 120+ new hires.',
    targetContact: {
      name: 'Sunil Grover',
      designation: 'VP Infrastructure & SecOps',
      email: 'sunil.grover@nexapay.in',
      phone: '+91 98210 44912'
    },
    recommendedPitch: 'Pre-provisioned ThinkPad T14 bundles with Fortinet HA firewalls & 3-day SLA swap guarantee.',
    projectedOpportunityValue: 5400000,
    outreachStatus: 'SEQUENCE_ACTIVE'
  },
  {
    id: 'OUT-02',
    companyName: 'LogiVantage Supply Chain Networks',
    industry: '3PL & Cold Storage Logistics',
    location: 'Bhiwandi & Taloja Industrial Park, Maharashtra',
    expansionTrigger: 'Commissioned 2 new automated fulfilment centers; requires rugged scanners and switch fabrics.',
    targetContact: {
      name: 'Kunal Singhania',
      designation: 'Head of Warehouse Technology',
      email: 'kunal.s@logivantage.in',
      phone: '+91 98330 11980'
    },
    recommendedPitch: 'Cisco PoE switch stacks + APC Industrial Smart-UPS with ATS high-surge power back-up modules.',
    projectedOpportunityValue: 3600000,
    outreachStatus: 'DISCOVERED'
  },
  {
    id: 'OUT-03',
    companyName: 'MedGenomics LifeSciences',
    industry: 'Biotech & Diagnostic AI',
    location: 'Pune Hinjewadi Phase 3',
    expansionTrigger: 'Setting up high-throughput DNA sequencing lab; compute cluster tender preparing in Q3.',
    targetContact: {
      name: 'Dr. Anita Deshpande',
      designation: 'Director of Bio-IT & Infrastructure',
      email: 'anita.d@medgenomics.org',
      phone: '+91 98230 77120'
    },
    recommendedPitch: 'GPU-accelerated workstation cluster + 100TB central low-latency NAS array.',
    projectedOpportunityValue: 6200000,
    outreachStatus: 'DISCOVERED'
  }
];

export const INITIAL_HARDWARE_REFRESH_ASSETS: HardwareRefreshAsset[] = [
  {
    id: 'REF-01',
    customerId: 'CUST-002',
    customerName: 'Tata Motors Supply Hub (Pimpri)',
    hardwareCategory: 'Enterprise Laptops',
    originalDeploymentDate: '2023-08-15',
    assetAgeMonths: 37,
    deployedQuantity: 35,
    deployedModels: 'Lenovo ThinkPad L14 Gen 2 (i5 11th Gen)',
    suggestedReplacementModel: 'Lenovo ThinkPad T14 Gen 5 (Intel Core Ultra / 16GB)',
    estimatedRefreshBudget: 2850000,
    healthScore: 42, // Aging battery & out-of-warranty
    refreshStatus: 'ELIGIBLE_FOR_REFRESH'
  },
  {
    id: 'REF-02',
    customerId: 'CUST-001',
    customerName: 'TechCorp India Solutions Ltd',
    hardwareCategory: 'Core Network Switches',
    originalDeploymentDate: '2022-11-10',
    assetAgeMonths: 46,
    deployedQuantity: 4,
    deployedModels: 'Cisco Catalyst 2960-X 48-Port PoE+ (Fast Ethernet/Gigabit)',
    suggestedReplacementModel: 'Cisco Catalyst 1200 48-Port Multi-Gigabit PoE+ (10G Uplink)',
    estimatedRefreshBudget: 1120000,
    healthScore: 35, // End-of-Software Support announced by Cisco
    refreshStatus: 'ELIGIBLE_FOR_REFRESH'
  },
  {
    id: 'REF-03',
    customerId: 'CUST-003',
    customerName: 'Reliance Retail IT Operations',
    hardwareCategory: 'Rack Power Systems',
    originalDeploymentDate: '2023-04-20',
    assetAgeMonths: 41,
    deployedQuantity: 6,
    deployedModels: 'Legacy 3kVA Tower SMPS & Lead-Acid Battery Cabinets',
    suggestedReplacementModel: 'ATS Modular N+1 Redundant Rectifier Shelf (2KW) + Lithium LiFePO4 Rack',
    estimatedRefreshBudget: 1950000,
    healthScore: 48,
    refreshStatus: 'PROPOSAL_SENT'
  }
];


