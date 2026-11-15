/**
 * IPO catalogue vocabulary and problem codes (specs/008-ipo-catalogue/contracts/error-codes.md,
 * BR-IPO-01..03). The API sends a stable `code` on every problem and warning; screens show the
 * wording from here. Adding a code is non-breaking; renaming or removing one is breaking.
 */

/** Lifecycle statuses, lowest rank first (BR-IPO-03). SETTLED is set only by settlement or an admin. */
export const ipoStatuses = [
  "UPCOMING",
  "OPEN",
  "CLOSED",
  "ALLOTMENT_OUT",
  "LISTED",
  "SETTLED",
] as const;
export type IpoStatus = (typeof ipoStatuses)[number];

/** The operator's verdict on an IPO (BR-IPO-02). */
export const ipoApplyFlags = ["APPLY", "DO_NOT_APPLY"] as const;
export type IpoApplyFlag = (typeof ipoApplyFlags)[number];

/** Mainboard segments only; SME listings are refused (BR-IPO-01). */
export const ipoSegments = ["NSE_MAINBOARD", "BSE_MAINBOARD"] as const;
export type IpoSegment = (typeof ipoSegments)[number];

export const ipoErrorMessages = {
  "ipo.sme_not_allowed":
    "SME listings are not supported. Only NSE and BSE mainboard IPOs can be added.",
  "ipo.invalid_segment": "Choose NSE mainboard, BSE mainboard or both, without repeating one.",
  "ipo.invalid_value": "One of the values is not valid. Please check the highlighted fields.",
  "ipo.date_order":
    "The dates are out of order. Open, close, allotment and listing must follow each other.",
  "ipo.publish_incomplete":
    "This IPO cannot be published yet. Add the apply flag, open and close dates, a price and the lot size.",
  "ipo.stale_version": "Someone else changed this IPO. Reload it and try again.",
  "ipo.no_change": "The IPO is already in that state.",
  "ipo.published_not_deletable": "A published IPO cannot be deleted. Unpublish it instead.",
  "ipo.not_listed_yet": "This IPO has not been listed yet, so it cannot be settled.",
  "ipo.min_application_out_of_range":
    "The minimum application value is outside the usual range of 10,000 to 20,000 rupees.",
  "ipo.weekdays_only": "Suggested dates skip weekends only. Check exchange holidays.",
} as const;

export type IpoErrorCode = keyof typeof ipoErrorMessages;

export const ipoErrorCodes = Object.keys(ipoErrorMessages) as IpoErrorCode[];

const fallbackMessage = "Something went wrong with this IPO. Please try again.";

export function isIpoErrorCode(code: string | undefined): code is IpoErrorCode {
  return code !== undefined && Object.hasOwn(ipoErrorMessages, code);
}

/** English wording for a code; any other code gets one generic message that never echoes it. */
export function ipoErrorMessage(code: string | undefined): string {
  return isIpoErrorCode(code) ? ipoErrorMessages[code] : fallbackMessage;
}
