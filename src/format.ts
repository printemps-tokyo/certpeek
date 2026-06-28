/** Pure date/validity/warning logic, independent of any certificate object. */

export type Status = "valid" | "expired" | "not-yet-valid";

/** Validity status and whole days remaining, given the window and "now". */
export function expiryStatus(fromMs: number, toMs: number, nowMs: number): { status: Status; daysRemaining: number } {
  const status: Status = nowMs < fromMs ? "not-yet-valid" : nowMs > toMs ? "expired" : "valid";
  const daysRemaining = Math.floor((toMs - nowMs) / 86_400_000);
  return { status, daysRemaining };
}

/** Human phrasing for a signed day count: "in 45 days" / "3 days ago". */
export function humanizeDays(days: number): string {
  const abs = Math.abs(days);
  const unit = abs === 1 ? "day" : "days";
  if (days === 0) {
    return "today";
  }
  return days > 0 ? `in ${days} ${unit}` : `${abs} ${unit} ago`;
}

/** Warnings about a public key's strength. */
export function keyWarnings(key: { type: string; size?: number }): string[] {
  if (key.type === "rsa" && key.size !== undefined && key.size < 2048) {
    return [`weak RSA key (${key.size}-bit; use >= 2048)`];
  }
  if (key.type === "dsa") {
    return ["DSA keys are deprecated"];
  }
  return [];
}

/** All warnings for a certificate: expiry state plus key strength. */
export function certWarnings(
  info: { status: Status; daysRemaining: number; keyType: string; keySize?: number },
  warnDays: number,
): string[] {
  const warnings: string[] = [];
  if (info.status === "expired") {
    warnings.push(`certificate expired (${humanizeDays(info.daysRemaining)})`);
  } else if (info.status === "not-yet-valid") {
    warnings.push("certificate is not yet valid");
  } else if (info.daysRemaining <= warnDays) {
    warnings.push(`expires soon (${humanizeDays(info.daysRemaining)})`);
  }
  warnings.push(...keyWarnings({ type: info.keyType, size: info.keySize }));
  return warnings;
}
