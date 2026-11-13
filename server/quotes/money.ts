export class QuoteInputError extends Error {}
export function paise(value: unknown, field = 'amount'): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9]\d{0,12})(\.\d{1,2})?$/.test(value))
    throw new QuoteInputError('Invalid '+field);
  const [whole, fraction = ''] = value.split('.');
  return BigInt(whole)*100n + BigInt(fraction.padEnd(2,'0'));
}
export function rupees(value: bigint): string {
  if(value < 0n) throw new QuoteInputError('Negative amount');
  return (value / 100n).toString()+'.'+(value % 100n).toString().padStart(2,'0');
}
export function calculateLine(unitPrice: string, quantity: number, gstRate: string) {
  if (!Number.isSafeInteger(quantity) || quantity < 1 || quantity > 1000)
    throw new QuoteInputError('Quantity must be between 1 and 1000');
  const unit = paise(unitPrice,'product price');
  const rate = paise(gstRate,'GST rate'); // 18.00% => 1800 hundredths
  if(rate > 10000n) throw new QuoteInputError('GST rate above 100%');
  const subtotal = unit * BigInt(quantity);
  // Round tax to paise, half-up; tax is estimate until verified and invoiced.
  const tax = (subtotal * rate + 5000n) / 10000n;
  const bound = 9999999999999999n; // DECIMAL(18,2) max in paise
  if(subtotal > bound || tax > bound || subtotal+tax > bound) throw new QuoteInputError('Quote total too large');
  return {subtotal, tax};
}
