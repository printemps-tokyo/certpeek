/**
 * Turn a parsed X.509 certificate into a structured, displayable view.
 *
 * Parsing uses Node's built-in `X509Certificate`, so there is no dependency and
 * the DER handling is robust. `inspectCert` is otherwise pure: it takes the
 * certificate and the current time and returns plain data, which keeps the
 * formatting and validity logic easy to unit test against a fixture.
 */

import { createHash, type X509Certificate } from "node:crypto";
import { expiryStatus, type Status } from "./format.js";

export interface CertInfo {
  subjectCN: string;
  subject: string;
  issuerCN: string;
  issuer: string;
  serialNumber: string;
  san: string[];
  validFrom: string;
  validTo: string;
  validFromMs: number;
  validToMs: number;
  status: Status;
  daysRemaining: number;
  keyType: string;
  keySize?: number;
  curve?: string;
  fingerprintSha256: string;
  fingerprintSha1: string;
  /** SHA-256 of the public key (SubjectPublicKeyInfo) — for public-key pinning. */
  spkiSha256: string;
  ca: boolean;
  keyUsage?: string[];
  ocsp?: string[];
  caIssuers?: string[];
}

/** A summary of one certificate in a chain, with its validity. */
export interface ChainEntry {
  subjectCN: string;
  issuerCN: string;
  /** Full subject / issuer distinguished names, for linkage checks. */
  subject: string;
  issuer: string;
  validTo: string;
  validToMs: number;
  status: Status;
  daysRemaining: number;
  selfSigned: boolean;
}

/** Pull the Common Name out of a `CN=..\nO=..` distinguished-name string. */
function commonName(dn: string): string {
  const m = /(?:^|\n)CN=([^\n]+)/.exec(dn);
  return m ? (m[1] as string) : (dn.split("\n")[0] ?? dn);
}

/** Parse the `subjectAltName` string ("DNS:a, DNS:b, IP Address:1.2.3.4"). */
export function parseSan(san: string | undefined): string[] {
  if (!san) {
    return [];
  }
  return san
    .split(",")
    .map((s) => s.trim().replace(/^DNS:/, "").replace(/^IP Address:/, "IP:"))
    .filter((s) => s !== "");
}

/** Parse the `infoAccess` string into OCSP and CA-issuer URLs. */
export function parseInfoAccess(text: string | undefined): { ocsp?: string[]; caIssuers?: string[] } {
  if (!text) {
    return {};
  }
  const ocsp: string[] = [];
  const caIssuers: string[] = [];
  for (const line of text.split("\n")) {
    const uri = /URI:(\S+)/.exec(line)?.[1];
    if (!uri) {
      continue;
    }
    if (/ocsp/i.test(line)) {
      ocsp.push(uri);
    } else if (/ca\s*issuers/i.test(line)) {
      caIssuers.push(uri);
    }
  }
  return {
    ...(ocsp.length > 0 ? { ocsp } : {}),
    ...(caIssuers.length > 0 ? { caIssuers } : {}),
  };
}

/** Inspect a certificate as of `nowMs`. */
export function inspectCert(cert: X509Certificate, nowMs: number): CertInfo {
  const validFromMs = Date.parse(cert.validFrom);
  const validToMs = Date.parse(cert.validTo);
  const { status, daysRemaining } = expiryStatus(validFromMs, validToMs, nowMs);

  const key = cert.publicKey;
  const details = (key.asymmetricKeyDetails ?? {}) as { modulusLength?: number; namedCurve?: string };
  const spkiHex = createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
  const spkiSha256 = spkiHex.toUpperCase().replace(/(..)(?=.)/g, "$1:");

  return {
    subjectCN: commonName(cert.subject),
    subject: cert.subject.replace(/\n/g, ", "),
    issuerCN: commonName(cert.issuer),
    issuer: cert.issuer.replace(/\n/g, ", "),
    serialNumber: cert.serialNumber,
    san: parseSan(cert.subjectAltName),
    validFrom: cert.validFrom,
    validTo: cert.validTo,
    validFromMs,
    validToMs,
    status,
    daysRemaining,
    keyType: key.asymmetricKeyType ?? "unknown",
    keySize: typeof details.modulusLength === "number" ? details.modulusLength : undefined,
    curve: typeof details.namedCurve === "string" ? details.namedCurve : undefined,
    fingerprintSha256: cert.fingerprint256,
    fingerprintSha1: cert.fingerprint,
    spkiSha256,
    ca: cert.ca,
    keyUsage: cert.keyUsage ?? undefined,
    ...parseInfoAccess(cert.infoAccess),
  };
}

/** Summarize a certificate chain (leaf first) for display, as of `nowMs`. */
export function chainSummary(certs: X509Certificate[], nowMs: number): ChainEntry[] {
  return certs.map((c) => {
    const validToMs = Date.parse(c.validTo);
    const { status, daysRemaining } = expiryStatus(Date.parse(c.validFrom), validToMs, nowMs);
    return {
      subjectCN: commonName(c.subject),
      issuerCN: commonName(c.issuer),
      subject: c.subject,
      issuer: c.issuer,
      validTo: c.validTo,
      validToMs,
      status,
      daysRemaining,
      selfSigned: c.subject === c.issuer,
    };
  });
}

/**
 * Problems with a chain: a broken/out-of-order link (a certificate not issued
 * by the next one) or an expired/not-yet-valid intermediate. Pure.
 */
export function chainIssues(entries: ChainEntry[]): string[] {
  const issues: string[] = [];
  for (let i = 0; i < entries.length - 1; i++) {
    if ((entries[i] as ChainEntry).issuer !== (entries[i + 1] as ChainEntry).subject) {
      issues.push(`chain order looks wrong: "${(entries[i] as ChainEntry).subjectCN}" is not issued by the next certificate`);
    }
  }
  for (let i = 1; i < entries.length; i++) {
    const e = entries[i] as ChainEntry;
    if (e.status === "expired") {
      issues.push(`intermediate "${e.subjectCN}" is expired`);
    } else if (e.status === "not-yet-valid") {
      issues.push(`intermediate "${e.subjectCN}" is not yet valid`);
    }
  }
  return issues;
}
