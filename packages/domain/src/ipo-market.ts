/**
 * Problem and warning codes of feature 009 (specs/009-gmp-expected-profit/contracts/http-api.md)
 * with their English wording, plus the subscription multiple formatter. Adding a code is
 * non-breaking; renaming or removing one is breaking.
 */
export const ipoMarketErrorMessages = {
  "ipomarket.invalid_value":
    "That value is not allowed. Check the note and the date and time, then try again.",
  "ipomarket.idempotency_key_reused":
    "This request key was already used for a different entry. Please start again.",
  "ipomarket.not_published_yet":
    "This IPO has not been published yet, so its market figures cannot be recorded.",
  "ipomarket.frozen": "This IPO is already listed, so its market figures can no longer change.",
  "ipomarket.correction_not_latest":
    "Only the latest entry can be corrected, and only once. Reload and try again.",
  "ipomarket.not_configured": "The service is not set up yet. Please contact the administrator.",
  "ipomarket.gmp_exceeds_price":
    "This GMP is larger than the share price. Please check it before saving.",
} as const;

export type IpoMarketErrorCode = keyof typeof ipoMarketErrorMessages;

/** Formats a subscription multiple held as integer hundredths, e.g. 1234 -> "12.34×". */
export function formatTimesSubscribed(x100: number): string {
  const whole = Math.trunc(x100 / 100);
  const frac = String(Math.abs(x100 % 100)).padStart(2, "0");
  return `${new Intl.NumberFormat("en-IN").format(whole)}.${frac}×`;
}
