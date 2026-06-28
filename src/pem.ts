/** Pure helpers for splitting PEM text into individual certificates. */

const CERT_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

/** Whether the text contains a PEM block (vs. raw DER bytes). */
export function isPem(text: string): boolean {
  return text.includes("-----BEGIN");
}

/** Extract each `-----BEGIN CERTIFICATE-----` block from PEM text. */
export function splitPemCerts(text: string): string[] {
  return text.match(CERT_BLOCK) ?? [];
}
