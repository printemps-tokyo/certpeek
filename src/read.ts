/** Read certificates from a PEM/DER file or stdin (IO). */

import { readFile } from "node:fs/promises";
import { X509Certificate } from "node:crypto";
import { isPem, splitPemCerts } from "./pem.js";

async function readStdin(): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

/** Parse every certificate in a buffer: each PEM block, or a single DER cert. */
export function certsFromBuffer(buf: Buffer): X509Certificate[] {
  const text = buf.toString("utf8");
  if (isPem(text)) {
    return splitPemCerts(text).map((pem) => new X509Certificate(pem));
  }
  return [new X509Certificate(buf)];
}

/** Read certificates from `file` (or stdin when no file is given). */
export async function readCerts(file: string | undefined): Promise<X509Certificate[]> {
  const buf = file ? await readFile(file) : await readStdin();
  const certs = certsFromBuffer(buf);
  if (certs.length === 0) {
    throw new Error("no certificate found in input");
  }
  return certs;
}
