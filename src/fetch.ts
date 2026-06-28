/**
 * Fetch a live certificate chain by opening a TLS connection (IO).
 *
 * This is the one part of certpeek that uses the network. It connects with
 * `rejectUnauthorized: false` so an expired or otherwise invalid certificate
 * can still be inspected, and reports the verification result separately.
 */

import tls from "node:tls";
import type { X509Certificate } from "node:crypto";

export interface FetchedChain {
  certs: X509Certificate[];
  authorized: boolean;
  authorizationError?: string;
}

/** Connect to `host:port` and return its certificate chain (leaf first). */
export function fetchCertChain(
  host: string,
  port: number,
  opts: { servername?: string; timeoutMs?: number } = {},
): Promise<FetchedChain> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host, port, servername: opts.servername ?? host, rejectUnauthorized: false },
      () => {
        const certs: X509Certificate[] = [];
        const seen = new Set<string>();
        let cert = socket.getPeerX509Certificate();
        while (cert && !seen.has(cert.fingerprint256)) {
          seen.add(cert.fingerprint256);
          certs.push(cert);
          cert = cert.issuerCertificate ?? undefined;
        }
        const authorized = socket.authorized;
        const authorizationError = socket.authorizationError ? String(socket.authorizationError) : undefined;
        socket.end();
        if (certs.length === 0) {
          reject(new Error("the server presented no certificate"));
          return;
        }
        resolve({ certs, authorized, authorizationError });
      },
    );
    socket.setTimeout(opts.timeoutMs ?? 8000, () => {
      socket.destroy();
      reject(new Error(`connection to ${host}:${port} timed out`));
    });
    socket.on("error", (err) => reject(err));
  });
}
