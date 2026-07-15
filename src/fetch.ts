/**
 * Fetch a live certificate chain by opening a TLS connection (IO).
 *
 * This is the one part of certpeek that uses the network. It connects with
 * `rejectUnauthorized: false` so an expired or otherwise invalid certificate
 * can still be inspected, and reports the verification result separately.
 *
 * With `starttls: "smtp"` it first performs a minimal SMTP STARTTLS dance on
 * a plain TCP socket (greeting, EHLO, STARTTLS) and then upgrades that same
 * socket to TLS — still a single outbound connection.
 */

import net from "node:net";
import tls from "node:tls";
import type { X509Certificate } from "node:crypto";

import { takeSmtpReply, advertisesStartTls, replySummary, type SmtpReply, type StartTlsProto } from "./smtp.js";

export interface FetchedChain {
  certs: X509Certificate[];
  authorized: boolean;
  authorizationError?: string;
}

/** Read the peer chain (leaf first) off a connected TLS socket and settle the promise. */
function collectChain(
  socket: tls.TLSSocket,
  resolve: (chain: FetchedChain) => void,
  reject: (err: Error) => void,
): void {
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
}

/** Connect to `host:port` and return its certificate chain (leaf first). */
export function fetchCertChain(
  host: string,
  port: number,
  opts: { servername?: string; timeoutMs?: number; starttls?: StartTlsProto } = {},
): Promise<FetchedChain> {
  const servername = opts.servername ?? host;
  const timeoutMs = opts.timeoutMs ?? 8000;

  if (opts.starttls === "smtp") {
    return fetchViaSmtpStartTls(host, port, servername, timeoutMs);
  }

  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port, servername, rejectUnauthorized: false }, () => {
      collectChain(socket, resolve, reject);
    });
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      reject(new Error(`connection to ${host}:${port} timed out`));
    });
    socket.on("error", (err) => reject(err));
  });
}

/**
 * Connect plain TCP, negotiate SMTP STARTTLS (220 greeting -> EHLO -> 250
 * with STARTTLS advertised -> STARTTLS -> 220), then upgrade the same socket
 * to TLS and read the certificate chain.
 */
function fetchViaSmtpStartTls(
  host: string,
  port: number,
  servername: string,
  timeoutMs: number,
): Promise<FetchedChain> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (chain: FetchedChain) => {
      if (!settled) {
        settled = true;
        resolve(chain);
      }
    };
    const fail = (err: Error) => {
      if (!settled) {
        settled = true;
        plain.destroy();
        reject(err);
      }
    };

    const plain = net.connect({ host, port });
    plain.setTimeout(timeoutMs, () => fail(new Error(`connection to ${host}:${port} timed out`)));
    plain.on("error", fail);

    let stage: "greeting" | "ehlo" | "starttls" = "greeting";

    /** Advance the negotiation by one server reply; returns true when ready to upgrade. */
    const step = (reply: SmtpReply): boolean => {
      if (stage === "greeting") {
        if (reply.code !== 220) {
          throw new Error(`unexpected SMTP greeting from ${host}:${port}: ${replySummary(reply)}`);
        }
        plain.write("EHLO certpeek.local\r\n");
        stage = "ehlo";
      } else if (stage === "ehlo") {
        if (reply.code !== 250) {
          throw new Error(`EHLO rejected by ${host}:${port}: ${replySummary(reply)}`);
        }
        if (!advertisesStartTls(reply)) {
          throw new Error(`${host}:${port} does not advertise STARTTLS (EHLO reply: ${replySummary(reply)})`);
        }
        plain.write("STARTTLS\r\n");
        stage = "starttls";
      } else {
        if (reply.code !== 220) {
          throw new Error(`STARTTLS rejected by ${host}:${port}: ${replySummary(reply)}`);
        }
        return true;
      }
      return false;
    };

    const upgrade = () => {
      const socket = tls.connect({ socket: plain, servername, rejectUnauthorized: false }, () => {
        collectChain(socket, done, fail);
      });
      socket.setTimeout(timeoutMs, () => {
        socket.destroy();
        fail(new Error(`TLS handshake with ${host}:${port} timed out`));
      });
      socket.on("error", fail);
    };

    let buffer = "";
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      try {
        for (;;) {
          const taken = takeSmtpReply(buffer);
          if (taken === null) {
            return; // wait for more data
          }
          buffer = taken.rest;
          if (step(taken.reply)) {
            plain.off("data", onData);
            plain.setTimeout(0);
            upgrade();
            return;
          }
        }
      } catch (err) {
        fail(err as Error);
      }
    };
    plain.on("data", onData);
  });
}
