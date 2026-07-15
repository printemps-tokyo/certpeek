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

/**
 * Caps on the plaintext SMTP negotiation. A misbehaving server that drips
 * endless continuation lines would otherwise grow the reply buffer without
 * bound while resetting the idle timer; these limits end the fetch with a
 * clear error instead.
 */
const MAX_NEGOTIATION_BYTES = 64 * 1024;
const MAX_NEGOTIATION_LINES = 100;

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

/**
 * Connect to `host:port` and return its certificate chain (leaf first).
 *
 * `timeoutMs` bounds each phase of the fetch: for a direct TLS connection it
 * is the socket idle timeout, and with `starttls` it additionally caps the
 * total duration of the plaintext SMTP negotiation (greeting through
 * STARTTLS accepted), not just the gaps between reads.
 */
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
 *
 * The whole plaintext negotiation must finish within `timeoutMs` (an overall
 * deadline, in addition to the per-read idle timeout), and the accumulated
 * replies are capped in size and line count, so a server that drips data
 * forever cannot keep the fetch alive or grow the buffer without bound.
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
        clearTimeout(deadline);
        resolve(chain);
      }
    };
    const fail = (err: Error) => {
      if (!settled) {
        settled = true;
        clearTimeout(deadline);
        plain.destroy();
        reject(err);
      }
    };

    // Overall deadline for the plaintext dance (greeting through STARTTLS
    // accepted). The idle timeout below only fires on silence, so a server
    // that keeps dripping bytes would reset it forever without this.
    const deadline = setTimeout(() => {
      fail(new Error(`SMTP STARTTLS negotiation with ${host}:${port} timed out`));
    }, timeoutMs);

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
      clearTimeout(deadline); // plaintext negotiation is done; TLS has its own timeout
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
    let receivedBytes = 0;
    let receivedLines = 0;
    const onData = (chunk: Buffer) => {
      const text = chunk.toString("utf8");
      receivedBytes += chunk.length;
      receivedLines += text.split("\n").length - 1;
      if (receivedBytes > MAX_NEGOTIATION_BYTES) {
        fail(
          new Error(
            `SMTP negotiation with ${host}:${port} exceeded ${MAX_NEGOTIATION_BYTES} bytes of replies without completing`,
          ),
        );
        return;
      }
      if (receivedLines > MAX_NEGOTIATION_LINES) {
        fail(
          new Error(
            `SMTP negotiation with ${host}:${port} exceeded ${MAX_NEGOTIATION_LINES} reply lines without completing`,
          ),
        );
        return;
      }
      buffer += text;
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
