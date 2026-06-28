import { describe, expect, it } from "vitest";
import { expiryStatus, humanizeDays, keyWarnings, certWarnings } from "../src/format.js";
import { parseTarget, looksLikeUrl } from "../src/target.js";
import { splitPemCerts, isPem } from "../src/pem.js";
import { parseSan, parseInfoAccess } from "../src/inspect.js";

const day = 86_400_000;

describe("expiryStatus", () => {
  it("classifies valid / expired / not-yet-valid", () => {
    expect(expiryStatus(0, 100 * day, 50 * day)).toEqual({ status: "valid", daysRemaining: 50 });
    expect(expiryStatus(0, 100 * day, 101 * day).status).toBe("expired");
    expect(expiryStatus(10 * day, 100 * day, 5 * day).status).toBe("not-yet-valid");
  });
});

describe("humanizeDays", () => {
  it("phrases future and past", () => {
    expect(humanizeDays(45)).toBe("in 45 days");
    expect(humanizeDays(1)).toBe("in 1 day");
    expect(humanizeDays(-3)).toBe("3 days ago");
    expect(humanizeDays(0)).toBe("today");
  });
});

describe("keyWarnings / certWarnings", () => {
  it("flags weak RSA keys", () => {
    expect(keyWarnings({ type: "rsa", size: 1024 })).toHaveLength(1);
    expect(keyWarnings({ type: "rsa", size: 2048 })).toHaveLength(0);
    expect(keyWarnings({ type: "ec" })).toHaveLength(0);
  });

  it("combines expiry and key warnings", () => {
    const expiring = certWarnings({ status: "valid", daysRemaining: 10, keyType: "rsa", keySize: 2048 }, 30);
    expect(expiring[0]).toMatch(/expires soon/);
    const expired = certWarnings({ status: "expired", daysRemaining: -2, keyType: "ec" }, 30);
    expect(expired[0]).toMatch(/expired/);
    expect(certWarnings({ status: "valid", daysRemaining: 200, keyType: "rsa", keySize: 4096 }, 30)).toEqual([]);
  });
});

describe("parseTarget / looksLikeUrl", () => {
  it("parses urls, host:port, and bare hosts", () => {
    expect(parseTarget("https://example.com")).toEqual({ host: "example.com", port: 443 });
    expect(parseTarget("https://example.com:8443/path")).toEqual({ host: "example.com", port: 8443 });
    expect(parseTarget("example.com:993")).toEqual({ host: "example.com", port: 993 });
    expect(parseTarget("example.com")).toEqual({ host: "example.com", port: 443 });
  });
  it("detects url-shaped input", () => {
    expect(looksLikeUrl("https://x")).toBe(true);
    expect(looksLikeUrl("example.com")).toBe(false);
  });
});

describe("pem / san / infoAccess helpers", () => {
  it("splits PEM blocks", () => {
    const two = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----";
    expect(splitPemCerts(two)).toHaveLength(2);
    expect(isPem(two)).toBe(true);
    expect(isPem("\x00\x01binary")).toBe(false);
  });
  it("parses SAN and infoAccess strings", () => {
    expect(parseSan("DNS:a.com, DNS:b.com, IP Address:1.2.3.4")).toEqual(["a.com", "b.com", "IP:1.2.3.4"]);
    expect(parseSan(undefined)).toEqual([]);
    const ia = parseInfoAccess("OCSP - URI:http://ocsp.x\nCA Issuers - URI:http://ca.x");
    expect(ia.ocsp).toEqual(["http://ocsp.x"]);
    expect(ia.caIssuers).toEqual(["http://ca.x"]);
  });
});
