/**
 * SMTP STARTTLS protocol helpers (pure).
 *
 * These functions parse SMTP replies and decide the STARTTLS negotiation
 * steps; the socket dance itself lives in fetch.ts. Kept pure so the reply
 * parser (multi-line 250 responses, STARTTLS detection, error codes) can be
 * unit-tested without a network.
 */

/** Protocols certpeek can negotiate STARTTLS for. Extend with imap/pop3 later. */
export const STARTTLS_PROTOCOLS = ["smtp"] as const;
export type StartTlsProto = (typeof STARTTLS_PROTOCOLS)[number];

/** Default port per STARTTLS protocol (used when neither the target nor --port gives one). */
export const STARTTLS_DEFAULT_PORT: Record<StartTlsProto, number> = { smtp: 587 };

/** Validate a --starttls value; throws a clear error on unsupported protocols. */
export function parseStartTlsProto(input: string): StartTlsProto {
  const proto = input.trim().toLowerCase();
  if ((STARTTLS_PROTOCOLS as readonly string[]).includes(proto)) {
    return proto as StartTlsProto;
  }
  throw new Error(
    `unsupported --starttls protocol ${JSON.stringify(input)} (supported: ${STARTTLS_PROTOCOLS.join(", ")})`,
  );
}

/** One complete SMTP reply: the 3-digit code and the text of each line (prefix stripped). */
export interface SmtpReply {
  code: number;
  lines: string[];
}

/**
 * Take one complete SMTP reply off the front of `input`.
 *
 * Returns the parsed reply and the unconsumed remainder, or `null` when the
 * buffer does not yet hold a complete reply (more data is needed). Handles
 * multi-line replies (`250-...` continuations ended by `250 ...`) and throws
 * on malformed or inconsistently-coded lines. Per RFC 5321 the 3-digit code
 * must be followed by a space, a hyphen, or the end of the line, so lines
 * like `250xyz` or `2500 hi` are rejected as malformed rather than being
 * loosely parsed as code 250.
 */
export function takeSmtpReply(input: string): { reply: SmtpReply; rest: string } | null {
  let rest = input;
  const lines: string[] = [];
  let code: number | undefined;
  for (;;) {
    const nl = rest.indexOf("\n");
    if (nl === -1) {
      return null; // incomplete: wait for more data
    }
    const raw = rest.slice(0, nl).replace(/\r$/, "");
    rest = rest.slice(nl + 1);
    const m = /^(\d{3})(?:([ -])(.*))?$/.exec(raw);
    if (!m) {
      throw new Error(`malformed SMTP reply line: ${JSON.stringify(raw)}`);
    }
    const lineCode = Number(m[1]);
    code ??= lineCode;
    if (lineCode !== code) {
      throw new Error(`inconsistent SMTP reply codes: ${code} then ${lineCode}`);
    }
    lines.push(m[3] ?? "");
    if (m[2] !== "-") {
      return { reply: { code, lines }, rest };
    }
  }
}

/** Does an EHLO reply advertise the STARTTLS extension (RFC 3207)? */
export function advertisesStartTls(reply: SmtpReply): boolean {
  return reply.lines.some((line) => line.trim().split(/\s+/)[0]?.toUpperCase() === "STARTTLS");
}

/** First line of a reply, for error messages. */
export function replySummary(reply: SmtpReply): string {
  return `${reply.code} ${reply.lines[0] ?? ""}`.trimEnd();
}
