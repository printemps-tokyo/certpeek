import { describe, expect, it } from "vitest";
import { matchPin } from "../src/pin.js";

const FP256 = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
const FP1 = "11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44";

describe("matchPin", () => {
  it("matches a SHA-256 pin regardless of colons, case, or prefix", () => {
    expect(matchPin(FP256, FP256, FP1)).toEqual({ matches: true, algorithm: "sha256" });
    expect(matchPin(FP256.replace(/:/g, "").toLowerCase(), FP256, FP1).matches).toBe(true);
    expect(matchPin(`sha256:${FP256}`, FP256, FP1).matches).toBe(true);
  });

  it("matches a SHA-1 pin by its 40-hex length", () => {
    expect(matchPin(FP1, FP256, FP1)).toEqual({ matches: true, algorithm: "sha1" });
  });

  it("reports a mismatch", () => {
    const wrong = "00:".repeat(31) + "00";
    expect(matchPin(wrong, FP256, FP1)).toEqual({ matches: false, algorithm: "sha256" });
  });

  it("flags an unparseable / wrong-length pin as unknown", () => {
    expect(matchPin("nothex", FP256, FP1).algorithm).toBe("unknown");
    expect(matchPin("ABCD", FP256, FP1).algorithm).toBe("unknown");
  });
});
