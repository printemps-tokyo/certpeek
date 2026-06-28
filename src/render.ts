import type { CertInfo, ChainEntry } from "./inspect.js";

/** Everything needed to render one inspection. */
export interface Report {
  info: CertInfo;
  warnings: string[];
  chain: ChainEntry[];
  source: { kind: "file" | "url"; host?: string; port?: number; authorized?: boolean; authorizationError?: string };
  /** Result of a hostname-coverage check, when one was requested/applicable. */
  match?: { hostname: string; matches: boolean; matchedBy?: string };
}

const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  green: "\x1b[32m",
  red: "\x1b[1;31m",
  yellow: "\x1b[33m",
  dim: "\x1b[2m",
};

function paint(text: string, code: string, on: boolean): string {
  return on ? `${code}${text}${C.reset}` : text;
}

function keyDescription(info: CertInfo): string {
  if (info.keyType === "rsa" && info.keySize) {
    return `RSA ${info.keySize}-bit`;
  }
  if (info.keyType === "ec") {
    return `EC ${info.curve ?? ""}`.trim();
  }
  return info.keyType.toUpperCase();
}

/** Render an inspection as human-readable text. */
export function renderText(report: Report, color: boolean): string {
  const { info, warnings, chain, source } = report;
  const lines: string[] = [];

  if (source.kind === "url") {
    const verdict = source.authorized
      ? paint("chain verified", C.green, color)
      : paint(`chain NOT verified${source.authorizationError ? `: ${source.authorizationError}` : ""}`, C.red, color);
    lines.push(`${paint("Host", C.bold, color)}: ${source.host}:${source.port}  (${verdict})`, "");
  }

  const statusColor = info.status === "valid" ? C.green : C.red;
  lines.push(paint("Certificate", C.bold, color));
  lines.push(`  Subject:    ${info.subjectCN}`);
  lines.push(`  Issuer:     ${info.issuerCN}`);
  lines.push(
    `  Valid:      ${info.validFrom} -> ${info.validTo}  ${paint(
      `[${info.status.toUpperCase()}]`,
      statusColor,
      color,
    )}`,
  );
  if (info.san.length > 0) {
    lines.push(`  SANs:       ${info.san.join(", ")}`);
  }
  if (report.match) {
    const m = report.match;
    const verdict = m.matches
      ? paint(`covered by ${m.matchedBy}`, C.green, color)
      : paint("NOT covered", C.red, color);
    lines.push(`  Match:      ${m.hostname} -> ${verdict}`);
  }
  lines.push(`  Key:        ${keyDescription(info)}`);
  lines.push(`  Serial:     ${info.serialNumber}`);
  lines.push(`  SHA-256:    ${info.fingerprintSha256}`);
  if (info.ocsp && info.ocsp.length > 0) {
    lines.push(`  OCSP:       ${info.ocsp.join(", ")}`);
  }

  if (chain.length > 1) {
    lines.push("", paint("Chain", C.bold, color));
    chain.forEach((c, i) => {
      const root = c.selfSigned ? paint(" (self-signed root)", C.dim, color) : "";
      lines.push(`  ${i + 1}. ${c.subjectCN}${root}`);
    });
  }

  if (warnings.length > 0) {
    lines.push("", paint("Warnings", C.bold, color));
    for (const w of warnings) {
      lines.push(`  - ${paint(w, C.yellow, color)}`);
    }
  }

  return lines.join("\n") + "\n";
}

/** Render an inspection as JSON. */
export function renderJson(report: Report): string {
  return JSON.stringify(report, null, 2) + "\n";
}
