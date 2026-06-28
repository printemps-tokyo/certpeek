/**
 * Compare a certificate against an expected fingerprint ("pinning").
 *
 * Useful in CI or monitoring to assert that a host still presents the exact
 * certificate you expect. The pin is accepted in the shapes people copy around:
 * with or without colons, and with an optional `sha256:` / `sha1:` prefix. The
 * algorithm is inferred from the hex length (64 = SHA-256, 40 = SHA-1). Pure.
 */

export interface PinMatch {
  matches: boolean;
  algorithm: "sha256" | "sha1" | "spki" | "unknown";
}

function normalize(fp: string): string {
  return fp.replace(/^(?:sha(?:256|1)|spki|pubkey):/i, "").replace(/[:\s]/g, "").toUpperCase();
}

/**
 * Compare a pin against a certificate's fingerprints. A `spki:`/`pubkey:`
 * prefix pins the public key (SubjectPublicKeyInfo) SHA-256 instead of the
 * certificate; otherwise the algorithm is inferred from the hex length.
 */
export function matchPin(pin: string, fingerprintSha256: string, fingerprintSha1: string, spkiSha256?: string): PinMatch {
  const p = normalize(pin);
  if (!/^[0-9A-F]+$/.test(p)) {
    return { matches: false, algorithm: "unknown" };
  }
  if (/^(?:spki|pubkey):/i.test(pin.trim())) {
    if (p.length !== 64 || spkiSha256 === undefined) {
      return { matches: false, algorithm: "unknown" };
    }
    return { matches: p === normalize(spkiSha256), algorithm: "spki" };
  }
  if (p.length === 64) {
    return { matches: p === normalize(fingerprintSha256), algorithm: "sha256" };
  }
  if (p.length === 40) {
    return { matches: p === normalize(fingerprintSha1), algorithm: "sha1" };
  }
  return { matches: false, algorithm: "unknown" };
}
