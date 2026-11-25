import { QuoteInputError, paise } from './money';

export function requiredMinimumMarginBps(envValue: string|undefined):number {
  const raw=envValue??'1500';
  if(!/^\d{1,5}$/.test(raw))throw new Error('Invalid QUOTE_MIN_MARGIN_BPS');
  const value=Number(raw);
  if(!Number.isSafeInteger(value)||value<0||value>10000)throw new Error('Invalid QUOTE_MIN_MARGIN_BPS');
  return value;
}
export function grossMarginBps(subtotal:string,cost:string):number {
  const sale=paise(subtotal,'subtotal'),landed=paise(cost,'cost');
  if(sale===0n)throw new QuoteInputError('Zero-value draft cannot be approved');
  return Number(((sale-landed)*10000n)/sale);
}
export function reviewDecision(input:{
  decision:'APPROVED_INTERNAL'|'REJECTED_INTERNAL';reason:string;overrideRequested:boolean;
  marginBps:number;minimumBps:number
}){
  if(input.decision==='APPROVED_INTERNAL' && input.marginBps<input.minimumBps) {
    if(!input.overrideRequested||input.reason.trim().length<20)
      throw new QuoteInputError('Below-policy margin needs explicit override and a justification of at least 20 characters');
  }
  return {reviewStatus:input.decision,belowPolicy:input.marginBps<input.minimumBps};
}
