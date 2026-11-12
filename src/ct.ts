/**
 * Certificate Transparency: certificates CAs have logged for a domain, from
 * SSLMate's Cert Spotter API (`/v1/issuances`), which answers without an
 * account at a low rate (an API key in CERTSPOTTER_API_KEY raises it). Only
 * the domain name is sent. Useful for spotting a certificate you did not
 * ask for, or an unexpected issuer.
 */

export interface Issuance {
  id: string;
  dnsNames: string[];
  issuer: string;
  notBefore: string;
  notAfter: string;
  revoked: boolean;
}

export const CERTSPOTTER = "https://api.certspotter.com/v1/issuances";

export interface CtOptions {
  subdomains?: boolean;
  apiKey?: string;
  fetchFn?: typeof fetch;
  /** Pages of results to read at most (the API pages by id). */
  maxPages?: number;
  timeoutMs?: number;
}

interface ApiIssuance {
  id: string;
  dns_names?: string[];
  issuer?: { friendly_name?: string; name?: string };
  not_before?: string;
  not_after?: string;
  revoked?: boolean;
}

/** The issuances logged for `domain`, oldest first (as the API returns them). */
export async function fetchIssuances(domain: string, opts: CtOptions = {}): Promise<{ issuances: Issuance[]; complete: boolean }> {
  const fetchFn = opts.fetchFn ?? fetch;
  const out: Issuance[] = [];
  let after: string | undefined;
  for (let page = 0; page < (opts.maxPages ?? 5); page++) {
    const url = new URL(CERTSPOTTER);
    url.searchParams.set("domain", domain);
    if (opts.subdomains) url.searchParams.set("include_subdomains", "true");
    url.searchParams.append("expand", "dns_names");
    url.searchParams.append("expand", "issuer");
    if (after) url.searchParams.set("after", after);
    const res = await fetchFn(url, {
      headers: opts.apiKey ? { authorization: `Bearer ${opts.apiKey}` } : {},
      signal: AbortSignal.timeout(opts.timeoutMs ?? 30_000),
    });
    if (res.status === 429) {
      throw new Error("Cert Spotter rate limit reached (set CERTSPOTTER_API_KEY, or try again later)");
    }
    if (!res.ok) throw new Error(`Cert Spotter answered HTTP ${res.status}`);
    const rows = (await res.json()) as ApiIssuance[];
    if (!Array.isArray(rows)) throw new Error("unexpected Cert Spotter response");
    for (const r of rows) {
      out.push({
        id: r.id,
        dnsNames: r.dns_names ?? [],
        issuer: r.issuer?.friendly_name || r.issuer?.name || "?",
        notBefore: r.not_before ?? "",
        notAfter: r.not_after ?? "",
        revoked: r.revoked === true,
      });
    }
    if (rows.length === 0) return { issuances: out, complete: true };
    after = rows[rows.length - 1]!.id;
  }
  return { issuances: out, complete: false };
}

/** Counts per issuer, and the certificates still valid at `nowMs`. */
export function summarizeIssuances(list: Issuance[], nowMs: number) {
  const issuers = new Map<string, number>();
  for (const i of list) issuers.set(i.issuer, (issuers.get(i.issuer) ?? 0) + 1);
  const current = list.filter((i) => !i.revoked && Date.parse(i.notAfter) > nowMs && Date.parse(i.notBefore) <= nowMs);
  return {
    total: list.length,
    current: current.length,
    issuers: [...issuers.entries()].sort((a, b) => b[1] - a[1]).map(([issuer, count]) => ({ issuer, count })),
  };
}

/** The newest `limit` issuances and the issuer summary, as text. */
export function renderIssuances(domain: string, list: Issuance[], complete: boolean, nowMs: number, limit = 20): string {
  const s = summarizeIssuances(list, nowMs);
  const lines = [
    `Certificate Transparency: ${domain} (Cert Spotter)`,
    `  ${s.total} certificate(s) logged${complete ? "" : " (more not shown; narrow with a subdomain)"}, ${s.current} currently valid`,
    `  issuers: ${s.issuers.map((i) => `${i.issuer} ${i.count}`).join(", ") || "-"}`,
    "",
  ];
  const newest = [...list].sort((a, b) => b.notBefore.localeCompare(a.notBefore)).slice(0, limit);
  for (const i of newest) {
    const names = i.dnsNames.slice(0, 3).join(" ") + (i.dnsNames.length > 3 ? ` +${i.dnsNames.length - 3}` : "");
    lines.push(`  ${i.notBefore.slice(0, 10)} .. ${i.notAfter.slice(0, 10)}  ${i.issuer.padEnd(16).slice(0, 16)}  ${names}${i.revoked ? "  (revoked)" : ""}`);
  }
  return lines.join("\n") + "\n";
}
