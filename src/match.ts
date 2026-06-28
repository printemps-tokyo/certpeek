/**
 * Check whether a certificate's names cover a hostname (RFC 6125).
 *
 * This answers the question developers most often bring to a cert tool — "does
 * this certificate actually cover example.com?" — and works offline against the
 * SAN list `inspect` already extracted. Wildcards follow the strict rules: a
 * single left-most `*` label only, never matching the bare domain or across a
 * dot, and never a partial label. Pure and easy to unit test (it can also be
 * cross-checked against Node's built-in `X509Certificate.checkHost`).
 */

export interface HostMatch {
  matches: boolean;
  /** The SAN entry that matched, when one did. */
  matchedBy?: string;
}

function normalize(name: string): string {
  return name.trim().toLowerCase().replace(/\.$/, "");
}

/** Whether any SAN entry covers `hostname`, and which one. */
export function matchHost(san: string[], hostname: string): HostMatch {
  const host = normalize(hostname);
  for (const entry of san) {
    if (entry.startsWith("IP:")) {
      if (entry.slice(3).trim() === hostname.trim()) {
        return { matches: true, matchedBy: entry };
      }
      continue;
    }
    const name = normalize(entry);
    if (name === host) {
      return { matches: true, matchedBy: entry };
    }
    // Wildcard: only an entire left-most "*" label, e.g. "*.example.com".
    if (name.startsWith("*.")) {
      const base = name.slice(2);
      if (host.endsWith(`.${base}`)) {
        const label = host.slice(0, host.length - base.length - 1);
        if (label.length > 0 && !label.includes(".")) {
          return { matches: true, matchedBy: entry };
        }
      }
    }
  }
  return { matches: false };
}
