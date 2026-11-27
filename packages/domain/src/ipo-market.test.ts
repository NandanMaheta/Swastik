import { describe, expect, it } from "vitest";
import * as domain from "./index";
import { formatTimesSubscribed, ipoMarketErrorMessages } from "./ipo-market";

// Problem codes of feature 009 (specs/009-gmp-expected-profit/contracts/http-api.md). May only grow.
const ipoMarketCodes = [
  "ipomarket.invalid_value",
  "ipomarket.idempotency_key_reused",
  "ipomarket.not_published_yet",
  "ipomarket.frozen",
  "ipomarket.correction_not_latest",
  "ipomarket.not_configured",
  "ipomarket.gmp_exceeds_price",
];

describe("BR_IPO_04 ipoMarketErrorMessages", () => {
  it.each(ipoMarketCodes)("has a non-empty message for %s", (code) => {
    const m = (ipoMarketErrorMessages as Record<string, string>)[code];
    expect(m).toBeDefined();
    expect(typeof m).toBe("string");
    expect((m ?? "").trim().length).toBeGreaterThan(0);
  });

  it("is re-exported from the package index", () => {
    expect(domain.ipoMarketErrorMessages).toBe(ipoMarketErrorMessages);
    expect(domain.formatTimesSubscribed).toBe(formatTimesSubscribed);
  });
});

describe("BR_IPO_04 formatTimesSubscribed", () => {
  it.each([
    [1234, "12.34×"],
    [0, "0.00×"],
    [5, "0.05×"],
    [100, "1.00×"],
  ])("formats %i hundredths as %s", (x100, want) => {
    expect(formatTimesSubscribed(x100)).toBe(want);
  });

  it("formats the 10,000,000 maximum (grouping separators optional)", () => {
    expect(formatTimesSubscribed(10_000_000)).toMatch(/^1,?00,?000\.00×$/);
  });
});
