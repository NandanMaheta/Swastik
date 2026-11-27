/**
 * The problem codes feature 004 (OTP delivery) adds and their English wording
 * (specs/004-otp-delivery/contracts/error-codes.md). The API sends a stable, language-neutral
 * `code` on every refusal; screens show the wording from here. Gujarati and Hindi come with
 * feature 024. Adding a code is non-breaking; renaming or removing one is breaking. Codes reused
 * from other features (auth.identifier_invalid, auth.password_*, auth.busy, rate_limited,
 * validation_failed) live in auth-error-codes.ts.
 *
 * Two codes carry a wait time: `{seconds}` and `{minutes}` are filled from the `Retry-After`
 * seconds the API sends with the 429. No wording ever names a contact, code, handle or token.
 */
export const otpErrorMessages = {
  "otp.verification_invalid": "This verification is not valid. Please start again.",
  "otp.verification_expired": "This verification has expired. Please start again.",
  "otp.nothing_to_send": "There is nothing to send for this step.",
  "otp.cooldown": "Please wait {seconds} seconds before asking for a new code.",
  "otp.rate_limited": "Too many codes were requested. Please try again in {minutes} minutes.",
  "otp.code_wrong": "That code is not correct. Please check it and try again.",
  "otp.code_expired": "That code has expired. Ask for a new one.",
  "otp.code_used_up": "Too many wrong tries. Ask for a new code.",
  "otp.email_first": "Please verify your email first.",
  "otp.proof_invalid": "We could not confirm your mobile number. Please try again.",
  "otp.proof_stale": "That confirmation is too old. Please request a new SMS code.",
  "otp.proof_replayed": "That confirmation was already used. Please request a new SMS code.",
  "otp.number_mismatch": "The number you confirmed is different from the one on your account.",
  "otp.contact_unavailable": "This email or mobile number cannot be used. Please choose another.",
  "otp.reset_token_invalid": "This reset link has expired or was already used. Please start again.",
  "otp.not_configured": "This step is not available right now. Please try again later.",
} as const;

export type OtpErrorCode = keyof typeof otpErrorMessages;

export const otpErrorCodes = Object.keys(otpErrorMessages) as readonly OtpErrorCode[];

const fallbackMessage = "Something went wrong. Please try again.";

/** Wording for a wait time that is not known (a cooldown or limit without Retry-After). */
const unknownWait: Partial<Record<OtpErrorCode, string>> = {
  "otp.cooldown": "Please wait a little before asking for a new code.",
  "otp.rate_limited": "Too many codes were requested. Please try again later.",
};

/** True when `code` is a problem code of feature 004 (exact, case-sensitive match). */
export function isOtpErrorCode(code: unknown): code is OtpErrorCode {
  return typeof code === "string" && Object.hasOwn(otpErrorMessages, code);
}

export interface OtpErrorOptions {
  /** Seconds from the `Retry-After` header or `retry_after_seconds`. */
  retryAfterSeconds?: number;
}

function plural(n: number, unit: string): string {
  return `${n} ${unit}${n === 1 ? "" : "s"}`;
}

/**
 * Calm English wording for a problem code, with the wait time filled in. An unknown, missing or
 * empty code gets one generic message that never echoes the code.
 */
export function otpErrorMessage(
  code: string | null | undefined,
  options: OtpErrorOptions = {},
): string {
  if (!isOtpErrorCode(code)) return fallbackMessage;
  const wait = options.retryAfterSeconds;
  const known = typeof wait === "number" && Number.isFinite(wait) && wait > 0;
  if (code === "otp.cooldown") {
    return known
      ? `Please wait ${plural(Math.ceil(wait), "second")} before asking for a new code.`
      : (unknownWait[code] ?? fallbackMessage);
  }
  if (code === "otp.rate_limited") {
    return known
      ? `Too many codes were requested. Please try again in ${plural(Math.ceil(wait / 60), "minute")}.`
      : (unknownWait[code] ?? fallbackMessage);
  }
  return otpErrorMessages[code];
}
