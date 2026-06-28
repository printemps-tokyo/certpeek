import { describe, expect, it } from "vitest";
import { matchHost } from "../src/match.js";

describe("matchHost", () => {
  it("matches an exact name, case-insensitively, with FQDN trailing dot", () => {
    expect(matchHost(["example.com"], "example.com")).toEqual({ matches: true, matchedBy: "example.com" });
    expect(matchHost(["Example.COM"], "example.com").matches).toBe(true);
    expect(matchHost(["example.com"], "example.com.").matches).toBe(true);
  });

  it("applies single left-most wildcard rules", () => {
    expect(matchHost(["*.example.com"], "a.example.com").matches).toBe(true);
    expect(matchHost(["*.example.com"], "example.com").matches).toBe(false); // not the bare domain
    expect(matchHost(["*.example.com"], "a.b.example.com").matches).toBe(false); // not across a dot
  });

  it("does not honor partial-label wildcards", () => {
    expect(matchHost(["f*.example.com"], "foo.example.com").matches).toBe(false);
  });

  it("returns the matching SAN among several", () => {
    expect(matchHost(["other.com", "*.example.com"], "a.example.com")).toEqual({
      matches: true,
      matchedBy: "*.example.com",
    });
  });

  it("handles IP SANs by exact equality only", () => {
    expect(matchHost(["IP:1.2.3.4"], "1.2.3.4").matches).toBe(true);
    expect(matchHost(["*.example.com"], "1.2.3.4").matches).toBe(false);
  });

  it("no match for empty SAN list, without throwing", () => {
    expect(matchHost([], "example.com")).toEqual({ matches: false });
  });
});
