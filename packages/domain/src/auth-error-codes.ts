/**
 * Every problem code a client of the API can meet and its English wording
 * (specs/003-auth-core/contracts/error-codes.md). The API sends a stable, language-neutral `code`
 * on every non-2xx response; screens show the wording from here. Gujarati and Hindi are added by
 * features 022 and 024. Adding a code is non-breaking; renaming or removing one is breaking.
 */
export const authErrorMessages = {
  // Platform (all features)
  bad_request: "The request could not be read. Please try again.",
  validation_failed: "Some of the details are not valid. Please check them and try again.",
  not_found: "We could not find what you asked for.",
  unsupported_media_type: "The request was sent in a format the server does not accept.",
  rate_limited: "Too many requests. Please wait a minute and try again.",
  internal: "Something went wrong on our side. Please try again.",
  "platform.security_undeclared": "This action is not available right now.",

  // Sign-in and sessions
  "auth.invalid_credentials": "The email, mobile number or password is not correct.",
  "auth.identifier_invalid": "Enter a valid email address or a 10-digit Indian mobile number.",
  "auth.unauthenticated": "Please sign in to continue.",
  "auth.forbidden": "You do not have permission to do this.",
  "auth.refresh_rejected": "Your session has ended. Please sign in again.",
  "auth.csrf_rejected": "This request was blocked for your safety. Reload the page and try again.",
  "auth.reauth_failed": "The password or code you entered is not correct.",

  // Password policy
  "auth.password_too_short": "The password must have at least 10 characters.",
  "auth.password_too_long": "The password can have at most 256 characters.",
  "auth.password_matches_identifier":
    "The password must not be the same as your email address or mobile number.",
  "auth.password_too_common": "This password is used too often. Choose a less common one.",
  "auth.password_unchanged": "The new password must be different from the current one.",

  // Devices, users, second factor, service state
  "auth.device_not_found": "This device session was not found. It may have ended already.",
  "auth.user_not_found": "This user was not found.",
  "auth.mfa_no_pending_secret": "Start setting up the authenticator first, then confirm the code.",
  "auth.busy": "The server is busy. Please try again in a moment.",
  "auth.not_configured": "The service is not set up yet. Please contact the administrator.",

  // Capability errors other features surface (004, 005, 007)
  "auth.email_taken": "This email address is already used by another account.",
  "auth.mobile_taken": "This mobile number is already used by another account.",
  "auth.status_transition_invalid":
    "This account cannot be moved to that status from where it is now.",
  "auth.last_admin": "The last active admin cannot be removed or disabled.",
} as const;

export type AuthErrorCode = keyof typeof authErrorMessages;

export const authErrorCodes = Object.keys(authErrorMessages) as readonly AuthErrorCode[];

const fallbackMessage = "Something went wrong. Please try again.";

/** True when `code` is a problem code this package knows (exact, case-sensitive match). */
export function isAuthErrorCode(code: unknown): code is AuthErrorCode {
  return typeof code === "string" && Object.hasOwn(authErrorMessages, code);
}

/**
 * The English wording for a problem code. An unknown, missing or empty code (a code added by a
 * later feature, or a network failure with no body) gets one generic message that never echoes
 * the code.
 */
export function authErrorMessage(code: string | null | undefined): string {
  return isAuthErrorCode(code) ? authErrorMessages[code] : fallbackMessage;
}
