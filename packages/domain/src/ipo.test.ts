import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as domain from "./index";
import {
  ipoApplyFlags,
  ipoErrorCodes,
  ipoErrorMessage,
  ipoErrorMessages,
  ipoSegments,
  ipoStatuses,
  isIpoErrorCode,
} from "./ipo";

// specs/008-ipo-catalogue/contracts/error-codes.md is the source of the codes; this file mirrors it
// for UI translation (features 022, 023, 025). Adding a code is non-breaking; removing one is not.
const doc = readFileSync(
  new URL("../../../specs/008-ipo-catalogue/contracts/error-codes.md", import.meta.url),
  "utf8",
);
const documentedIpoCodes = [...doc.matchAll(/^\| `(ipo\.[a-z_]+)` \|/gm)].map((m) => m[1]);
const warningAndNotice = ["ipo.min_application_out_of_range", "ipo.weekdays_only"];

describe("ipo vocabulary", () => {
  it("lists the six lifecycle statuses in order (BR-IPO-03)", () => {
    expect([...ipoStatuses]).toEqual([
      "UPCOMING",
      "OPEN",
      "CLOSED",
      "ALLOTMENT_OUT",
      "LISTED",
      "SETTLED",
    ]);
  });

  it("lists the two apply flags (BR-IPO-02)", () => {
    expect([...ipoApplyFlags]).toEqual(["APPLY", "DO_NOT_APPLY"]);
  });

  it("lists mainboard segments only (BR-IPO-01)", () => {
    expect([...ipoSegments]).toEqual(["NSE_MAINBOARD", "BSE_MAINBOARD"]);
    expect([...ipoSegments].join()).not.toMatch(/EMERGE|SME/);
  });

  it("is exported from the package index", () => {
    expect(domain.ipoStatuses).toBe(ipoStatuses);
    expect(domain.ipoErrorCodes).toBe(ipoErrorCodes);
  });
});

describe("ipoErrorCodes", () => {
  it("parsed the documented codes", () => {
    expect(documentedIpoCodes.length).toBeGreaterThanOrEqual(9);
  });

  it.each(documentedIpoCodes)("lists %s", (code) => {
    expect(ipoErrorCodes as readonly string[]).toContain(code);
  });

  it.each(warningAndNotice)("lists the warning or notice code %s", (code) => {
    expect(ipoErrorCodes as readonly string[]).toContain(code);
  });

  it("has no duplicates and only well-formed codes", () => {
    const codes = [...ipoErrorCodes] as string[];
    expect(new Set(codes).size).toBe(codes.length);
    for (const code of codes) expect(code).toMatch(/^ipo\.[a-z][a-z_]*$/);
  });

  it("has an English message for every code and none for an unlisted one", () => {
    for (const code of ipoErrorCodes) {
      const message: string = ipoErrorMessages[code];
      expect(typeof message, code).toBe("string");
      expect(message.trim().length, code).toBeGreaterThan(5);
      expect(message.length, code).toBeLessThanOrEqual(160);
      expect(message, code).not.toMatch(/[{}<>]|undefined|null/);
    }
    expect(Object.keys(ipoErrorMessages).sort()).toEqual([...ipoErrorCodes].sort());
  });

  it("says why SME listings are refused", () => {
    expect(ipoErrorMessage("ipo.sme_not_allowed")).toMatch(/mainboard/i);
  });
});

describe("ipoErrorMessage and isIpoErrorCode", () => {
  it.each(documentedIpoCodes)("returns the message of %s", (code) => {
    expect(isIpoErrorCode(code)).toBe(true);
    expect(ipoErrorMessage(code)).toBe(ipoErrorMessages[code as keyof typeof ipoErrorMessages]);
  });

  it("answers an unknown, missing or empty code with one generic message that never echoes it", () => {
    const fallback = ipoErrorMessage("deal.something_new");
    expect(fallback.trim().length).toBeGreaterThan(5);
    expect(fallback).not.toContain("deal.something_new");
    expect(ipoErrorMessage(undefined)).toBe(fallback);
    expect(ipoErrorMessage("")).toBe(fallback);
    expect(isIpoErrorCode("deal.something_new")).toBe(false);
    expect(isIpoErrorCode(undefined)).toBe(false);
  });
});
