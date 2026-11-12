/**
 * Several hosts at once: one row per host with its expiry, chain and name
 * check, for watching a set of sites from cron. Pure parts only; the CLI
 * does the connections.
 */

export interface HostRow {
  target: string;
  /** Set when the connection or inspection failed. */
  error?: string;
  daysRemaining?: number;
  /** Expiry date, YYYY-MM-DD (UTC). */
  validTo?: string;
  issuer?: string;
  status?: string;
  authorized?: boolean;
  matches?: boolean;
  /** True when the row should fail the run (expired, unverified, name mismatch, or within --fail-days). */
  failed: boolean;
}

/** Hosts from a file: one per line, `#` comments and blank lines ignored. */
export function parseHostList(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.replace(/#.*$/, "").trim())
    .filter((l) => l !== "");
}

/** Failing rows first, then by the fewest days left. */
export function sortRows(rows: HostRow[]): HostRow[] {
  return [...rows].sort(
    (a, b) =>
      Number(b.failed) - Number(a.failed) ||
      (a.daysRemaining ?? -Infinity) - (b.daysRemaining ?? -Infinity) ||
      a.target.localeCompare(b.target),
  );
}

/** Run `fn` over `items` with at most `limit` at a time, keeping the order. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i] as T);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

/** The rows as an aligned text table. */
export function renderHostTable(rows: HostRow[], warnDays: number, color: boolean): string {
  const paint = (t: string, code: string): string => (color ? `\x1b[${code}m${t}\x1b[0m` : t);
  const tw = Math.max(4, ...rows.map((r) => r.target.length));
  const lines = [`${"HOST".padEnd(tw)}   DAYS  EXPIRES      ISSUER                    CHECK`];
  for (const r of sortRows(rows)) {
    if (r.error) {
      lines.push(`${r.target.padEnd(tw)}  ${paint("    -", "1;31")}  ${"".padEnd(11)}  ${"".padEnd(24)}  ${paint(`error: ${r.error}`, "1;31")}`);
      continue;
    }
    const days = String(r.daysRemaining ?? "?").padStart(5);
    const dayText = (r.daysRemaining ?? 0) < 0 || r.failed ? paint(days, "1;31") : (r.daysRemaining ?? 0) <= warnDays ? paint(days, "33") : days;
    const checks = [r.authorized === false ? "UNVERIFIED" : "", r.matches === false ? "NAME MISMATCH" : "", r.status && r.status !== "valid" ? r.status.toUpperCase() : ""]
      .filter((c) => c !== "")
      .join(", ");
    const check = r.failed ? paint(checks || "FAIL", "1;31") : paint("ok", "32");
    const expires = (r.validTo ?? "").slice(0, 10).padEnd(11);
    lines.push(`${r.target.padEnd(tw)}  ${dayText}  ${expires}  ${(r.issuer ?? "").slice(0, 24).padEnd(24)}  ${check}`);
  }
  const failed = rows.filter((r) => r.failed).length;
  lines.push("", `${rows.length} host(s), ${failed} failing`);
  return lines.join("\n") + "\n";
}
