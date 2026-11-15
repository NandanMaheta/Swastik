import { describe, expect, it } from "vitest";
import {
  authErrorCodes,
  authErrorMessage,
  authErrorMessages,
  isAuthErrorCode,
} from "./auth-error-codes";
import * as domain from "./index";

// Every problem code a client of the API can meet (specs/003-auth-core/contracts/error-codes.md).
// Adding a code is non-breaking; renaming or removing one is breaking, so this list may only grow.
const platformCodes = [
  "bad_request",
  "validation_failed",
  "not_found",
  "unsupported_media_type",
  "rate_limited",
  "internal",
  "platform.security_undeclared",
];

const authHttpCodes = [
  "auth.invalid_credentials",
  "auth.identifier_invalid",
  "auth.unauthenticated",
  "auth.forbidden",
  "auth.refresh_rejected",
  "auth.csrf_rejected",
  "auth.reauth_failed",
  "auth.password_too_short",
  "auth.password_too_long",
  "auth.password_matches_identifier",
  "auth.password_too_common",
  "auth.password_unchanged",
  "auth.device_not_found",
  "auth.user_not_found",
  "auth.mfa_no_pending_secret",
  "auth.busy",
  "auth.not_configured",
];

// Capability errors other features surface (004, 005, 007).
const capabilityCodes = [
  "auth.email_taken",
  "auth.mobile_taken",
  "auth.status_transition_invalid",
  "auth.last_admin",
];

const required = [...platformCodes, ...authHttpCodes, ...capabilityCodes];

describe("authErrorCodes", () => {
  it.each(required)("lists %s", (code) => {
    expect(authErrorCodes as readonly string[]).toContain(code);
  });

  it("has no duplicates and only well-formed codes", () => {
    const codes = [...authErrorCodes] as string[];
    expect(new Set(codes).size).toBe(codes.length);
    for (const code of codes) {
      expect(code).toMatch(/^(auth|platform)\.[a-z][a-z_]*$|^[a-z][a-z_]*$/);
    }
  });

  it("has an English message for every code", () => {
    for (const code of authErrorCodes) {
      const message: string = authErrorMessages[code];
      expect(typeof message, code).toBe("string");
      expect(message.trim().length, code).toBeGreaterThan(5);
      expect(message.length, code).toBeLessThanOrEqual(160);
      expect(message, code).not.toMatch(/[{}<>]|undefined|null/);
    }
  });

  it("has no message for a code that is not listed", () => {
    expect(Object.keys(authErrorMessages).sort()).toEqual([...authErrorCodes].sort());
  });
});

describe("authErrorMessage", () => {
  it.each(required)("returns the message of %s", (code) => {
    expect(authErrorMessage(code)).toBe(authErrorMessages[code as keyof typeof authErrorMessages]);
  });

  it("keeps the sign-in failure generic (no enumeration, D-09)", () => {
    const message = authErrorMessage("auth.invalid_credentials");
    expect(message).not.toMatch(
      /lock|disabled|pending|approv|exist|unknown|not found|verified|wrong password|too many/i,
    );
  });

  it("names the numbers of the password policy (D-07)", () => {
    expect(authErrorMessage("auth.password_too_short")).toMatch(/10/);
    expect(authErrorMessage("auth.password_too_long")).toMatch(/256/);
  });

  it("answers an unknown, missing or empty code with one generic message that never echoes the code", () => {
    const fallback = authErrorMessage("something.new_from_a_later_feature");
    expect(fallback.trim().length).toBeGreaterThan(5);
    expect(fallback).not.toContain("something.new_from_a_later_feature");
    for (const code of [undefined, null, "", "   "]) {
      expect(authErrorMessage(code)).toBe(fallback);
    }
  });
});

describe("isAuthErrorCode", () => {
  it.each(required)("accepts %s", (code) => {
    expect(isAuthErrorCode(code)).toBe(true);
  });

  it.each([undefined, null, "", "auth.nope", "AUTH.FORBIDDEN", 401, {}])("rejects %j", (value) => {
    expect(isAuthErrorCode(value)).toBe(false);
  });
});

describe("package entry point", () => {
  it("re-exports the auth error codes", () => {
    expect(domain.authErrorCodes).toBe(authErrorCodes);
    expect(domain.authErrorMessage).toBe(authErrorMessage);
    expect(domain.isAuthErrorCode).toBe(isAuthErrorCode);
  });
});
