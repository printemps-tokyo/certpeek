#!/usr/bin/env node
import { parseArgs } from "node:util";
import { existsSync } from "node:fs";

import { parseTarget, looksLikeUrl } from "./target.js";
import { readCerts } from "./read.js";
import { fetchCertChain } from "./fetch.js";
import { inspectCert, chainSummary } from "./inspect.js";
import { certWarnings } from "./format.js";
import { renderJson, renderText, type Report } from "./render.js";

const HELP = `certpeek - inspect an X.509 / TLS certificate

Usage:
  certpeek <file>            Inspect a PEM/DER certificate file (or stdin)
  certpeek <host|url>        Inspect a live certificate over TLS
  certpeek --url <host|url>  Force live TLS inspection

Shows the subject, issuer, validity and expiry, SANs, key, fingerprint, and
(for a chain) each certificate. For a URL it connects and reports whether the
chain verifies. Offline for files; only --url/host mode uses the network.

Options:
  --url <target>      Inspect the live certificate at this host/URL
  --port <n>          Port for TLS (default: from the URL, else 443)
  --servername <name> SNI server name to send (default: the host)
  --timeout <ms>      TLS connection timeout (default: 8000)
  --warn-days <n>     Warn when the certificate expires within n days (default: 30)
  --json              Output JSON instead of text
  --no-color          Disable ANSI colors
  -h, --help          Show this help
  -v, --version       Show version

Examples:
  certpeek cert.pem
  certpeek example.com
  certpeek --url https://example.com:8443 --json
  cat fullchain.pem | certpeek
`;

async function readVersion(): Promise<string> {
  const { readFile } = await import("node:fs/promises");
  const { fileURLToPath } = await import("node:url");
  const { dirname, join } = await import("node:path");
  const here = dirname(fileURLToPath(import.meta.url));
  try {
    const raw = await readFile(join(here, "..", "package.json"), "utf8");
    return (JSON.parse(raw) as { version: string }).version;
  } catch {
    return "0.0.0";
  }
}

async function buildReport(
  values: Record<string, string | boolean | undefined>,
  positional: string | undefined,
  nowMs: number,
): Promise<Report> {
  const warnDays = values["warn-days"] ? Number(values["warn-days"]) : 30;

  // Decide file mode vs. URL mode.
  let urlTarget: string | undefined;
  if (typeof values.url === "string") {
    urlTarget = values.url;
  } else if (positional && !existsSync(positional) && (looksLikeUrl(positional) || /^[A-Za-z0-9.-]+(?::\d+)?$/.test(positional))) {
    urlTarget = positional;
  }

  if (urlTarget !== undefined) {
    const { host, port } = parseTarget(urlTarget);
    const finalPort = values.port ? Number(values.port) : port;
    const chain = await fetchCertChain(host, finalPort, {
      servername: typeof values.servername === "string" ? values.servername : undefined,
      timeoutMs: values.timeout ? Number(values.timeout) : undefined,
    });
    const info = inspectCert(chain.certs[0]!, nowMs);
    const warnings = certWarnings(info, warnDays);
    if (!chain.authorized) {
      warnings.unshift(`chain not verified${chain.authorizationError ? `: ${chain.authorizationError}` : ""}`);
    }
    return {
      info,
      warnings,
      chain: chainSummary(chain.certs),
      source: { kind: "url", host, port: finalPort, authorized: chain.authorized, authorizationError: chain.authorizationError },
    };
  }

  const certs = await readCerts(positional);
  const info = inspectCert(certs[0]!, nowMs);
  return { info, warnings: certWarnings(info, warnDays), chain: chainSummary(certs), source: { kind: "file" } };
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  if (argv.includes("-h") || argv.includes("--help")) {
    process.stdout.write(HELP);
    return 0;
  }
  if (argv.includes("-v") || argv.includes("--version")) {
    process.stdout.write((await readVersion()) + "\n");
    return 0;
  }

  let values;
  let positionals;
  try {
    const parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        url: { type: "string" },
        port: { type: "string" },
        servername: { type: "string" },
        timeout: { type: "string" },
        "warn-days": { type: "string" },
        json: { type: "boolean", default: false },
        "no-color": { type: "boolean", default: false },
      },
    });
    values = parsed.values;
    positionals = parsed.positionals;
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 1;
  }

  const positional = positionals[0];
  if (positional === undefined && values.url === undefined && process.stdin.isTTY) {
    process.stderr.write("error: give a file, a host/URL, or pipe a certificate on stdin\n\n" + HELP);
    return 1;
  }

  let report: Report;
  try {
    report = await buildReport(values, positional, Date.now());
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 1;
  }

  const color = !values["no-color"] && !process.env.NO_COLOR && process.stdout.isTTY === true;
  process.stdout.write(values.json ? renderJson(report) : renderText(report, color));

  const invalid = report.info.status !== "valid" || (report.source.kind === "url" && report.source.authorized === false);
  return invalid ? 1 : 0;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    process.exitCode = 1;
  });
