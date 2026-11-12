import { describe, expect, it } from "vitest";
import { mapLimit, parseHostList, renderHostTable, sortRows, type HostRow } from "../src/fleet.js";
import { fetchIssuances, renderIssuances, summarizeIssuances } from "../src/ct.js";

describe("host lists", () => {
  it("skips comments and blank lines", () => {
    expect(parseHostList("a.example\n# note\n\n b.example:8443  # api\r\n")).toEqual(["a.example", "b.example:8443"]);
  });

  it("puts failing hosts first, then the soonest expiry", () => {
    const rows: HostRow[] = [
      { target: "c", daysRemaining: 80, failed: false },
      { target: "a", daysRemaining: 5, failed: true },
      { target: "b", daysRemaining: 20, failed: false },
      { target: "e", error: "ENOTFOUND", failed: true },
    ];
    expect(sortRows(rows).map((r) => r.target)).toEqual(["e", "a", "b", "c"]);
    const text = renderHostTable(rows, 30, false);
    expect(text).toContain("error: ENOTFOUND");
    expect(text).toContain("4 host(s), 2 failing");
  });

  it("runs at most `limit` at once and keeps the order", async () => {
    let running = 0;
    let peak = 0;
    const out = await mapLimit([1, 2, 3, 4, 5, 6], 2, async (n) => {
      running++;
      peak = Math.max(peak, running);
      await new Promise((r) => setTimeout(r, 5 * (7 - n)));
      running--;
      return n * 10;
    });
    expect(out).toEqual([10, 20, 30, 40, 50, 60]);
    expect(peak).toBe(2);
  });
});

describe("Certificate Transparency", () => {
  const page = (ids: string[]) =>
    ids.map((id, i) => ({
      id,
      dns_names: ["example.com", "*.example.com"],
      issuer: { friendly_name: i % 2 ? "Sectigo" : "Let's Encrypt" },
      not_before: `2026-0${i + 1}-01T00:00:00Z`,
      not_after: `2027-0${i + 1}-01T00:00:00Z`,
      revoked: false,
    }));

  it("pages through the API with after= and sends only the domain", async () => {
    const urls: URL[] = [];
    const fn = (async (url: URL) => {
      urls.push(url);
      const after = url.searchParams.get("after");
      return new Response(JSON.stringify(after === null ? page(["1", "2"]) : after === "2" ? page(["3"]) : []));
    }) as unknown as typeof fetch;
    const { issuances, complete } = await fetchIssuances("example.com", { fetchFn: fn, subdomains: true });
    expect(issuances.map((i) => i.id)).toEqual(["1", "2", "3"]);
    expect(complete).toBe(true);
    expect(urls[0]!.searchParams.get("domain")).toBe("example.com");
    expect(urls[0]!.searchParams.get("include_subdomains")).toBe("true");
    expect(urls[0]!.searchParams.getAll("expand")).toEqual(["dns_names", "issuer"]);
  });

  it("explains the rate limit", async () => {
    const fn = (async () => new Response("", { status: 429 })) as unknown as typeof fetch;
    await expect(fetchIssuances("example.com", { fetchFn: fn })).rejects.toThrow(/CERTSPOTTER_API_KEY/);
  });

  it("summarizes issuers and current certificates", async () => {
    const fn = (async (url: URL) =>
      new Response(JSON.stringify(url.searchParams.get("after") ? [] : page(["1", "2", "3"])))) as unknown as typeof fetch;
    const { issuances, complete } = await fetchIssuances("example.com", { fetchFn: fn });
    const s = summarizeIssuances(issuances, Date.parse("2026-02-15T00:00:00Z"));
    expect(s).toEqual({ total: 3, current: 2, issuers: [{ issuer: "Let's Encrypt", count: 2 }, { issuer: "Sectigo", count: 1 }] });
    expect(renderIssuances("example.com", issuances, complete, Date.parse("2026-02-15T00:00:00Z"))).toContain("2 currently valid");
  });
});
