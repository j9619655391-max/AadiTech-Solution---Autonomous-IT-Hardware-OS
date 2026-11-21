import { paise, rupees, calculateLine, QuoteInputError } from './money';

export interface RevisionProduct {
  productId: string;
  sku: string;
  name: string;
  hsn: string;
  quantity: number;
  unitCost: string;
  unitPrice: string;
  gstRate: string;
}
export function evaluateRevision(items: RevisionProduct[], minimumMarginBps = 1500){
  if(!Array.isArray(items) || items.length<1 || items.length>40)throw new QuoteInputError('Revision needs 1–40 lines');
  if(!Number.isSafeInteger(minimumMarginBps) || minimumMarginBps<0 || minimumMarginBps>10000)
    throw new QuoteInputError('Invalid server margin policy');
  let subtotal=0n,tax=0n,cost=0n;
  const snapshot=items.map((item)=>{
    const line=calculateLine(item.unitPrice,item.quantity,item.gstRate);
    cost+=paise(item.unitCost)*BigInt(item.quantity);
    subtotal+=line.subtotal;
    tax+=line.tax;
    return {...item,lineSubtotal:rupees(line.subtotal),lineTaxEstimate:rupees(line.tax)};
  });
  if(subtotal===0n)throw new QuoteInputError('Quote subtotal must be positive');
  if(subtotal+tax>9999999999999999n)throw new QuoteInputError('Quote total too large');
  // integer basis points rounded down; no binary-float money calculations.
  const marginBps=Number(((subtotal-cost)*10000n)/subtotal);
  return {subtotal:rupees(subtotal),taxEstimate:rupees(tax),totalEstimate:rupees(subtotal+tax),
    grossMarginBps:marginBps,reviewStatus:marginBps<minimumMarginBps?'MARGIN_REVIEW_REQUIRED' as const:'DRAFT_OK' as const,
    lines:snapshot};
}
