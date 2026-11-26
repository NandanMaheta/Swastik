import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as domain from "./index";
import {
  isOtpErrorCode,
  otpErrorCodes,
  otpErrorMessage,
  otpErrorMessages,
} from "./otp-error-codes";

// Every problem code feature 004 adds (specs/004-otp-delivery/contracts/error-codes.md) with the
// wording of that table. Adding a code is non-breaking; renaming or removing one is breaking, so
// this list may only grow. Codes reused from other features (auth.identifier_invalid, auth.password_*,
// auth.busy, rate_limited, validation_failed) live in auth-error-codes.ts.
const wording: Record<string, string> = {
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
  "otp.reset_token_invalid":
    "This reset link has expired or was already used. Please start again.",
  "otp.not_configured": "This step is not available right now. Please try again later.",
};
const codes = Object.keys(wording);

describe("otpErrorCodes", () => {
  it.each(codes)("lists %s", (code) => {
    expect(otpErrorCodes as readonly string[]).toContain(code);
  });

  it("has no duplicates and only well-formed codes", () => {
    const list = [...otpErrorCodes] as string[];
    expect(new Set(list).size).toBe(list.length);
    for (const code of list) {
      expect(code).toMatch(/^otp\.[a-z][a-z_]*$/);
    }
  });

  it("has no message for a code that is not listed, and none missing", () => {
    expect(Object.keys(otpErrorMessages).sort()).toEqual([...otpErrorCodes].sort());
  });

  it("has calm English wording for every code, as written in the contract", () => {
    for (const code of codes) {
      expect((otpErrorMessages as Record<string, string>)[code], code).toBe(wording[code]);
    }
    for (const code of otpErrorCodes) {
      const message: string = otpErrorMessages[code];
      expect(message.trim().length, code).toBeGreaterThan(5);
      expect(message.length, code).toBeLessThanOrEqual(160);
      expect(message.replace(/\{(seconds|minutes)\}/g, ""), code).not.toMatch(/[{}<>]|undefined|null/);
    }
  });

  it("never names a contact, a code, a handle or a token in any wording", () => {
    for (const code of otpErrorCodes) {
      expect(otpErrorMessages[code], code).not.toMatch(/@|\+91|ovh_|prt_|[0-9]{4,}/);
    }
  });

  // FR-016: the codes the API can send and the codes the apps know are the same list.
  it("matches the problem codes of the Go module (internal/otp/errors.go)", () => {
    const go = readFileSync(new URL("../../../apps/api/internal/otp/errors.go", import.meta.url), "utf8");
    const goCodes = [...go.matchAll(/"(otp\.[a-z_]+)"/g)].map((m) => m[1]).filter((c) => c !== undefined);
    expect([...new Set(goCodes)].sort()).toEqual([...otpErrorCodes].sort());
  });
});

describe("otpErrorMessage", () => {
  it("fills the seconds of a cooldown", () => {
    expect(otpErrorMessage("otp.cooldown", { retryAfterSeconds: 40 })).toBe(
      "Please wait 40 seconds before asking for a new code.",
    );
  });

  it("fills the minutes of a rate limit from whole seconds", () => {
    expect(otpErrorMessage("otp.rate_limited", { retryAfterSeconds: 3300 })).toBe(
      "Too many codes were requested. Please try again in 55 minutes.",
    );
    expect(otpErrorMessage("otp.rate_limited", { retryAfterSeconds: 120 })).toContain("in 2 minutes");
  });

  it("never leaves a placeholder behind, even without a wait time", () => {
    for (const code of ["otp.cooldown", "otp.rate_limited"]) {
      expect(otpErrorMessage(code), code).not.toMatch(/[{}]/);
      expect(otpErrorMessage(code, {}), code).not.toMatch(/[{}]/);
    }
  });

  it("returns fixed wording for codes without placeholders and ignores the wait time", () => {
    expect(otpErrorMessage("otp.code_wrong", { retryAfterSeconds: 9 })).toBe(wording["otp.code_wrong"]);
    expect(otpErrorMessage("otp.email_first")).toBe(wording["otp.email_first"]);
  });

  it("answers an unknown, missing or empty code with one generic message that never echoes the code", () => {
    const fallback = otpErrorMessage("something.new_from_a_later_feature");
    expect(fallback.trim().length).toBeGreaterThan(5);
    expect(fallback).not.toContain("something.new_from_a_later_feature");
    for (const code of [undefined, null, "", "   "]) {
      expect(otpErrorMessage(code)).toBe(fallback);
    }
  });
});

describe("isOtpErrorCode", () => {
  it.each(codes)("accepts %s", (code) => {
    expect(isOtpErrorCode(code)).toBe(true);
  });

  it.each([undefined, null, "", "otp.nope", "OTP.COOLDOWN", "auth.forbidden", 429, {}])(
    "rejects %j",
    (value) => {
      expect(isOtpErrorCode(value)).toBe(false);
    },
  );
});

describe("package entry point", () => {
  it("re-exports the otp error codes", () => {
    expect(domain.otpErrorCodes).toBe(otpErrorCodes);
    expect(domain.otpErrorMessage).toBe(otpErrorMessage);
    expect(domain.isOtpErrorCode).toBe(isOtpErrorCode);
  });
});
