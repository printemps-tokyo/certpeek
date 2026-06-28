import { describe, expect, it } from "vitest";
import { X509Certificate } from "node:crypto";
import { inspectCert, chainSummary } from "../src/inspect.js";
import { renderText, renderJson, type Report } from "../src/render.js";
import { certWarnings } from "../src/format.js";

// A self-signed RSA-2048 fixture: CN=certpeek.test, SANs certpeek.test/www,
// valid 2026-06-28 .. 2036-06-25.
const FIXTURE = `-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgIUA2DB+HlO4IZ1zrLE0gZN0Vcb+K8wDQYJKoZIhvcNAQEL
BQAwMjEWMBQGA1UEAwwNY2VydHBlZWsudGVzdDEYMBYGA1UECgwPcHJpbnRlbXBz
LnRva3lvMB4XDTI2MDYyODA4MTIwOVoXDTM2MDYyNTA4MTIwOVowMjEWMBQGA1UE
AwwNY2VydHBlZWsudGVzdDEYMBYGA1UECgwPcHJpbnRlbXBzLnRva3lvMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1A+FRef1ZmFn4vDxS3PfDrjOoi0A
JTwRTlqOPYupsa2HpdbApEWsTpD9DGgZNMEn80T86ZMIEBAVmba3vIcJ7hypEj5Q
8/HFzQsljGSx7Oo0FiR4lHuB9PhDD4/g2kmQleQZlw1sjf4Olwve2o4IdbextIK6
uBGa7NWjo+GadCoIqT6r11UtASzTw2tQFI+T2ucSUko35sgUuJEWjeCM1RdAUfVn
RKQIEXmCbDV6KxZx8CpeMBUyEbhZtlFLBEWY9vcxNzwpQgJWgBxkM5fhL4eotkKY
CmruU7cwYszegITXqxWPdz2Y/2NOP4sR5NRs93GSb1vgO5Inf8oYuWULPwIDAQAB
o4GAMH4wHQYDVR0OBBYEFOdAgueWoZ/Bd1gKDhjJ6MY5V9qJMB8GA1UdIwQYMBaA
FOdAgueWoZ/Bd1gKDhjJ6MY5V9qJMA8GA1UdEwEB/wQFMAMBAf8wKwYDVR0RBCQw
IoINY2VydHBlZWsudGVzdIIRd3d3LmNlcnRwZWVrLnRlc3QwDQYJKoZIhvcNAQEL
BQADggEBAMR3Y7JQmoXIxO71DWg7lt5q92amBmQ1eYi5CM4W6a1PqPTAB5/nAM+2
MMolDq6Aq7cLadBFWDFdzHYVAnkK+cfHci5n/kfVZA3kDTmYoC2wpF6tcdZsL/BE
njgMbdPU2Jjs4+zFT8dn9b0KkS+5i1+0VW17XJnDxsWCeq2Z2Itn1vrahkiCmCti
1yVFbzfpR57IBc8PANxoQX5DBLgM59baxpC4TkilTqftESK/B8RQrE1xiT9fEp/e
AFl+mSCYlN4cSt5H/Yf5mzk2ijKpqbLjq9SGnopLGwS3DoMZTAvaKWwXFHfaEXeR
gdG97Frvw/lWiM6WR9xzqtbQX/eeOuo=
-----END CERTIFICATE-----`;

const cert = new X509Certificate(FIXTURE);
const validFromMs = Date.parse(cert.validFrom);
const validToMs = Date.parse(cert.validTo);

describe("inspectCert", () => {
  it("extracts the subject, SANs, key, and validity", () => {
    const info = inspectCert(cert, validFromMs + 86_400_000);
    expect(info.subjectCN).toBe("certpeek.test");
    expect(info.issuerCN).toBe("certpeek.test");
    expect(info.san).toEqual(["certpeek.test", "www.certpeek.test"]);
    expect(info.keyType).toBe("rsa");
    expect(info.keySize).toBe(2048);
    expect(info.ca).toBe(true);
    expect(info.fingerprintSha256).toMatch(/^[0-9A-F:]+$/);
    expect(info.status).toBe("valid");
  });

  it("reports expiry once past validTo", () => {
    expect(inspectCert(cert, validToMs + 86_400_000).status).toBe("expired");
  });
});

describe("chainSummary", () => {
  it("marks a self-signed certificate", () => {
    expect(chainSummary([cert])[0]?.selfSigned).toBe(true);
  });
});

describe("render", () => {
  const info = inspectCert(cert, validFromMs + 86_400_000);
  const report: Report = { info, warnings: certWarnings(info, 30), chain: chainSummary([cert]), source: { kind: "file" } };

  it("renders text with the key fields (no color)", () => {
    const out = renderText(report, false);
    expect(out).toContain("Subject:    certpeek.test");
    expect(out).toContain("[VALID]");
    expect(out).toContain("RSA 2048-bit");
    expect(out).not.toContain("\x1b[");
  });

  it("renders a host header and verification verdict for url mode", () => {
    const urlReport: Report = { ...report, source: { kind: "url", host: "certpeek.test", port: 443, authorized: false, authorizationError: "self signed certificate" } };
    expect(renderText(urlReport, false)).toContain("chain NOT verified: self signed certificate");
  });

  it("renders JSON", () => {
    const parsed = JSON.parse(renderJson(report));
    expect(parsed.info.subjectCN).toBe("certpeek.test");
    expect(parsed.source.kind).toBe("file");
  });
});
