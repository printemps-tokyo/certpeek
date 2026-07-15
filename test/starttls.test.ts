/**
 * Integration tests: a tiny local mock SMTP server (net.createServer) performs
 * the STARTTLS dance and upgrades the connection to TLS with a self-signed
 * fixture certificate, and fetchCertChain inspects it through the upgrade.
 */

import { afterEach, describe, expect, it } from "vitest";
import net from "node:net";
import tls from "node:tls";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { fetchCertChain } from "../src/fetch.js";

const KEY = readFileSync(fileURLToPath(new URL("./fixtures/localhost-key.pem", import.meta.url)));
const CERT = readFileSync(fileURLToPath(new URL("./fixtures/localhost-cert.pem", import.meta.url)));

interface MockSmtpOptions {
  /** EHLO reply lines; the default advertises STARTTLS. */
  ehloReply?: string;
  /** Reply to the STARTTLS command; the default accepts and upgrades to TLS. */
  starttlsReply?: string;
  /** Chunk every write into single bytes to exercise reassembly. */
  fragment?: boolean;
}

interface MockSmtp {
  port: number;
  commands: string[];
  close: () => Promise<void>;
}

function startMockSmtp(opts: MockSmtpOptions = {}): Promise<MockSmtp> {
  const ehloReply =
    opts.ehloReply ?? "250-mock.example greets you\r\n250-PIPELINING\r\n250-8BITMIME\r\n250 STARTTLS\r\n";
  const starttlsReply = opts.starttlsReply ?? "220 2.0.0 Ready to start TLS\r\n";
  const commands: string[] = [];

  const server = net.createServer((sock) => {
    const send = (text: string) => {
      if (opts.fragment) {
        for (const ch of text) {
          sock.write(ch);
        }
      } else {
        sock.write(text);
      }
    };

    send("220 mock.example ESMTP certpeek-test\r\n");
    let buf = "";
    const onData = (chunk: Buffer) => {
      buf += chunk.toString("utf8");
      let nl: number;
      while ((nl = buf.indexOf("\r\n")) !== -1) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        commands.push(line);
        if (line.toUpperCase().startsWith("EHLO")) {
          send(ehloReply);
        } else if (line.toUpperCase() === "STARTTLS") {
          send(starttlsReply);
          if (starttlsReply.startsWith("220")) {
            sock.off("data", onData);
            const secure = new tls.TLSSocket(sock, { isServer: true, key: KEY, cert: CERT });
            secure.on("error", () => {
              /* client hangs up after peeking; ignore */
            });
          }
        }
      }
    };
    sock.on("data", onData);
    sock.on("error", () => {
      /* ignore client resets */
    });
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as net.AddressInfo;
      resolve({
        port,
        commands,
        close: () =>
          new Promise<void>((done) => {
            server.close(() => done());
          }),
      });
    });
  });
}

/** A raw TCP server for misbehaving-server tests; returns its port and a closer. */
function startRawServer(
  onConnection: (sock: net.Socket) => void,
): Promise<{ port: number; close: () => Promise<void> }> {
  const server = net.createServer((sock) => {
    sock.on("error", () => {
      /* ignore client resets */
    });
    onConnection(sock);
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as net.AddressInfo;
      resolve({
        port,
        close: () =>
          new Promise<void>((done) => {
            server.close(() => done());
          }),
      });
    });
  });
}

describe("fetchCertChain with starttls: smtp", () => {
  let mock: MockSmtp | undefined;
  afterEach(async () => {
    await mock?.close();
    mock = undefined;
  });

  it("negotiates STARTTLS, upgrades the socket, and reads the certificate", async () => {
    mock = await startMockSmtp();
    const chain = await fetchCertChain("127.0.0.1", mock.port, { starttls: "smtp", servername: "localhost" });

    expect(chain.certs.length).toBeGreaterThanOrEqual(1);
    expect(chain.certs[0]!.subject).toContain("CN=localhost");
    expect(chain.authorized).toBe(false); // self-signed
    // The client spoke proper SMTP before the handshake.
    expect(mock.commands).toEqual(["EHLO certpeek.local", "STARTTLS"]);
  });

  it("reassembles replies that arrive fragmented", async () => {
    mock = await startMockSmtp({ fragment: true });
    const chain = await fetchCertChain("127.0.0.1", mock.port, { starttls: "smtp", servername: "localhost" });
    expect(chain.certs[0]!.subject).toContain("CN=localhost");
  });

  it("fails clearly when the server does not advertise STARTTLS", async () => {
    mock = await startMockSmtp({ ehloReply: "250-mock.example greets you\r\n250 8BITMIME\r\n" });
    await expect(fetchCertChain("127.0.0.1", mock.port, { starttls: "smtp" })).rejects.toThrow(
      /does not advertise STARTTLS/,
    );
    expect(mock.commands).toEqual(["EHLO certpeek.local"]); // never sent STARTTLS
  });

  it("fails when the server refuses STARTTLS", async () => {
    mock = await startMockSmtp({ starttlsReply: "454 4.7.0 TLS not available due to temporary reason\r\n" });
    await expect(fetchCertChain("127.0.0.1", mock.port, { starttls: "smtp" })).rejects.toThrow(
      /STARTTLS rejected .*454/,
    );
  });

  it("enforces the overall deadline against a server that drips lines forever", async () => {
    // Continuation lines every 50 ms reset the idle timer indefinitely; only
    // the overall negotiation deadline can end this fetch.
    let drip: NodeJS.Timeout | undefined;
    let markClosed!: () => void;
    const serverSawClose = new Promise<void>((resolve) => {
      markClosed = resolve;
    });
    const raw = await startRawServer((sock) => {
      sock.on("close", () => {
        clearInterval(drip);
        markClosed();
      });
      sock.write("220-mock.example dripping greeting\r\n");
      drip = setInterval(() => sock.write("220-still dripping\r\n"), 50);
    });
    try {
      const started = Date.now();
      await expect(
        fetchCertChain("127.0.0.1", raw.port, { starttls: "smtp", timeoutMs: 400 }),
      ).rejects.toThrow(/STARTTLS negotiation .* timed out/);
      // Settles around timeoutMs, not after some multiple of it.
      expect(Date.now() - started).toBeLessThan(1500);
      // The client destroyed its socket (no leak): the server observes the close.
      await serverSawClose;
    } finally {
      clearInterval(drip);
      await raw.close();
    }
  });

  it("caps the accumulated negotiation reply size", async () => {
    // Eight ~10 KB continuation lines (~80 KB total) never complete a reply.
    const raw = await startRawServer((sock) => {
      sock.write(`220-${"x".repeat(10_000)}\r\n`.repeat(8));
    });
    try {
      await expect(fetchCertChain("127.0.0.1", raw.port, { starttls: "smtp" })).rejects.toThrow(
        /exceeded 65536 bytes of replies/,
      );
    } finally {
      await raw.close();
    }
  });

  it("caps the number of negotiation reply lines", async () => {
    // 150 short continuation lines stay far under the byte cap but blow the line cap.
    const raw = await startRawServer((sock) => {
      sock.write("220-flood\r\n".repeat(150));
    });
    try {
      await expect(fetchCertChain("127.0.0.1", raw.port, { starttls: "smtp" })).rejects.toThrow(
        /exceeded 100 reply lines/,
      );
    } finally {
      await raw.close();
    }
  });

  it("fails on an unexpected greeting", async () => {
    const server = net.createServer((sock) => {
      sock.write("554 5.3.2 service not available\r\n");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as net.AddressInfo;
    try {
      await expect(fetchCertChain("127.0.0.1", port, { starttls: "smtp" })).rejects.toThrow(
        /unexpected SMTP greeting .*554/,
      );
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
