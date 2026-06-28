# certpeek

> Inspect an X.509 / TLS certificate offline from a file, or live from a URL. Zero-dependency CLI.

[![CI](https://github.com/printemps-tokyo/certpeek/actions/workflows/ci.yml/badge.svg)](https://github.com/printemps-tokyo/certpeek/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

`certpeek` tells you what's inside a certificate — subject, issuer, validity and
expiry, SANs, key, fingerprint — from a local PEM/DER file, or by connecting to
a host and reading its live certificate chain.

```console
$ certpeek example.com
Host: example.com:443  (chain verified)

Certificate
  Subject:    example.com
  Issuer:     Cloudflare TLS Issuing ECC CA 3
  Valid:      May 31 2026 GMT -> Aug 29 2026 GMT  [VALID]
  SANs:       example.com, *.example.com
  Key:        EC prime256v1
  SHA-256:    BE:AB:14:...

Chain
  1. example.com
  2. Cloudflare TLS Issuing ECC CA 3
  3. SSL.com TLS Transit ECC CA R2
  4. SSL.com TLS ECC Root CA 2022
```

It parses certificates with Node's built-in `crypto.X509Certificate`, so there
are no dependencies. File inspection is fully offline; only the URL/host mode
opens a network connection.

## Requirements

- Node.js >= 20

## Install

Not published to npm yet — install from source:

```bash
git clone https://github.com/printemps-tokyo/certpeek
cd certpeek
npm install && npm run build
npm link   # optional: puts the `certpeek` command on your PATH
```

Then run `certpeek …` (after `npm link`), or `node dist/cli.js …` from the clone.

## Usage

```bash
certpeek cert.pem                       # inspect a PEM/DER file
cat fullchain.pem | certpeek            # ...or from stdin (shows the chain)
certpeek example.com                    # inspect a live certificate over TLS
certpeek --url https://example.com:8443 # explicit host:port
certpeek github.com --json              # machine-readable
certpeek expired.example.com --warn-days 14
```

| Option | Description |
| --- | --- |
| `<file>` | A PEM/DER certificate file (or stdin) |
| `<host\|url>` | A host or URL to inspect live over TLS |
| `--url <target>` | Force live TLS inspection |
| `--match <hostname>` | Check whether the certificate covers this hostname (RFC 6125 wildcards) |
| `--pin <fingerprint>` | Assert the leaf matches this SHA-256/SHA-1 fingerprint (with or without colons) |
| `--port <n>` | TLS port (default: from the URL, else 443) |
| `--servername <name>` | SNI server name to send (default: the host) |
| `--timeout <ms>` | TLS connection timeout (default: 8000) |
| `--warn-days <n>` | Warn when the certificate expires within n days (default: 30) |
| `--json` | Output JSON instead of text |
| `--no-color` | Disable ANSI colors |

If the first argument is an existing file it is read as a certificate;
otherwise a host-shaped argument is inspected over TLS. The exit code is `1`
when the certificate is expired / not yet valid, or (in URL mode) when the chain
does not verify — so it fits a monitoring cron.

## What it shows

- Whether the certificate covers a given hostname (`--match`, with correct
  RFC 6125 wildcard rules) — shown automatically for the connected host in URL
  mode, and exiting non-zero when it does not cover the name.
- Whether the leaf matches an expected fingerprint (`--pin sha256:AB:CD:…`,
  colons optional) — for certificate pinning in CI / monitoring, exiting
  non-zero on a mismatch.
- Subject and issuer (Common Name), serial number, and SHA-256 fingerprint.
- Validity window with a `VALID` / `EXPIRED` / `NOT YET VALID` status and, as a
  warning, how soon it expires.
- Subject Alternative Names, public key type and size (RSA bits / EC curve), and
  OCSP / CA-issuer URLs when present.
- In URL mode: the full certificate chain and whether it verifies against the
  system trust store. Invalid certificates are still shown (the verification
  result is reported separately). Each chain certificate's validity is shown,
  and certpeek warns about a broken / out-of-order chain or an expired
  intermediate.

## Security

certpeek inspects metadata; for files it never leaves your machine, which is the
point — you can examine a certificate without uploading it anywhere. URL mode
makes a single outbound TLS connection to the host you name and nothing else.

## Programmatic API

```ts
import { inspectCert } from "@printemps-tokyo/certpeek";
import { X509Certificate } from "node:crypto";

const info = inspectCert(new X509Certificate(pem), Date.now());
console.log(info.subjectCN, info.status, info.daysRemaining);
```

`inspectCert` and the validity/format helpers are pure functions.

## License

[MIT](./LICENSE) (c) printemps.tokyo
