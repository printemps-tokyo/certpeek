/** Parse a URL-mode target into a host and port. Pure. */

export interface Target {
  host: string;
  port: number;
}

/** Accepts `https://host[:port][/path]`, `host:port`, or a bare `host`. */
export function parseTarget(input: string): Target {
  const s = input.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    const url = new URL(s);
    return { host: url.hostname, port: url.port ? Number(url.port) : 443 };
  }
  const m = /^([^/\s:]+)(?::(\d+))?$/.exec(s);
  if (!m) {
    throw new Error(`invalid target ${JSON.stringify(input)} (use host, host:port, or https://host)`);
  }
  return { host: m[1] as string, port: m[2] ? Number(m[2]) : 443 };
}

/** Heuristic: does this argument look like a network target rather than a file? */
export function looksLikeUrl(input: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(input);
}
