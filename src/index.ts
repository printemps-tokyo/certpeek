/**
 * Public API for certpeek.
 *
 * `certpeek` inspects an X.509 / TLS certificate either offline (from a PEM/DER
 * file or stdin) or live (by opening a TLS connection to a URL/host). Parsing,
 * validity evaluation, and rendering are pure given a parsed certificate and
 * the current time; only the file read and the TLS connection do IO.
 */

export type { Status } from "./format.js";
export { expiryStatus, humanizeDays, keyWarnings, certWarnings } from "./format.js";

export type { Target } from "./target.js";
export { parseTarget, looksLikeUrl } from "./target.js";

export { isPem, splitPemCerts } from "./pem.js";

export type { CertInfo, ChainEntry } from "./inspect.js";
export { inspectCert, chainSummary, chainIssues, parseSan, parseInfoAccess } from "./inspect.js";

export type { HostMatch } from "./match.js";
export { matchHost } from "./match.js";

export type { PinMatch } from "./pin.js";
export { matchPin } from "./pin.js";

export { certsFromBuffer, readCerts } from "./read.js";
export { fetchCertChain } from "./fetch.js";
export type { FetchedChain } from "./fetch.js";

export type { Report } from "./render.js";
export { renderText, renderJson } from "./render.js";
