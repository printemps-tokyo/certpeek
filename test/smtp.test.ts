import { describe, expect, it } from "vitest";
import { takeSmtpReply, advertisesStartTls, parseStartTlsProto, replySummary } from "../src/smtp.js";
import { parseTarget } from "../src/target.js";

describe("takeSmtpReply", () => {
  it("parses a single-line greeting", () => {
    const taken = takeSmtpReply("220 mail.example.com ESMTP Postfix\r\n");
    expect(taken).toEqual({
      reply: { code: 220, lines: ["mail.example.com ESMTP Postfix"] },
      rest: "",
    });
  });

  it("returns null while the reply is incomplete", () => {
    expect(takeSmtpReply("")).toBeNull();
    expect(takeSmtpReply("220 mail.example.com ESM")).toBeNull();
    // A continuation line alone is not a complete reply either.
    expect(takeSmtpReply("250-mail.example.com\r\n250-PIPELINING\r\n")).toBeNull();
  });

  it("parses a multi-line 250 EHLO reply", () => {
    const raw = "250-mail.example.com greets certpeek.local\r\n250-PIPELINING\r\n250-8BITMIME\r\n250 STARTTLS\r\n";
    const taken = takeSmtpReply(raw);
    expect(taken?.reply.code).toBe(250);
    expect(taken?.reply.lines).toEqual([
      "mail.example.com greets certpeek.local",
      "PIPELINING",
      "8BITMIME",
      "STARTTLS",
    ]);
    expect(taken?.rest).toBe("");
  });

  it("leaves unconsumed data in rest", () => {
    const taken = takeSmtpReply("220 ready\r\n250 next reply\r\n");
    expect(taken?.reply.code).toBe(220);
    expect(taken?.rest).toBe("250 next reply\r\n");
  });

  it("accepts bare LF and a code with no text", () => {
    expect(takeSmtpReply("220\n")?.reply).toEqual({ code: 220, lines: [""] });
    expect(takeSmtpReply("250\r\n")?.reply).toEqual({ code: 250, lines: [""] });
  });

  it("parses error codes", () => {
    expect(takeSmtpReply("554 5.7.1 rejected\r\n")?.reply.code).toBe(554);
    expect(takeSmtpReply("454 4.7.0 TLS not available\r\n")?.reply.code).toBe(454);
  });

  it("throws on a malformed line", () => {
    expect(() => takeSmtpReply("hello world\r\n")).toThrow(/malformed SMTP reply line/);
  });

  it("requires a space, hyphen, or end-of-line right after the 3-digit code", () => {
    // Text glued to the code is not a valid reply, not code 250 with text "xyz".
    expect(() => takeSmtpReply("250xyz\r\n")).toThrow(/malformed SMTP reply line/);
    // A fourth digit is not a valid separator either (would loosely parse as 250 "0 hi").
    expect(() => takeSmtpReply("2500 hi\r\n")).toThrow(/malformed SMTP reply line/);
    expect(() => takeSmtpReply("250-ok\r\n250continuation\r\n")).toThrow(/malformed SMTP reply line/);
  });

  it("throws on inconsistent codes across a multi-line reply", () => {
    expect(() => takeSmtpReply("250-ok\r\n220 huh\r\n")).toThrow(/inconsistent SMTP reply codes/);
  });
});

describe("advertisesStartTls", () => {
  it("detects STARTTLS among EHLO keywords, case-insensitively", () => {
    expect(advertisesStartTls({ code: 250, lines: ["mail.example.com", "PIPELINING", "STARTTLS"] })).toBe(true);
    expect(advertisesStartTls({ code: 250, lines: ["mail.example.com", "starttls"] })).toBe(true);
  });

  it("does not match keywords that merely contain the word", () => {
    expect(advertisesStartTls({ code: 250, lines: ["mail.example.com", "SIZE 35882577", "8BITMIME"] })).toBe(false);
    expect(advertisesStartTls({ code: 250, lines: ["NOSTARTTLS"] })).toBe(false);
  });
});

describe("replySummary", () => {
  it("shows the code and first line", () => {
    expect(replySummary({ code: 250, lines: ["ok", "STARTTLS"] })).toBe("250 ok");
    expect(replySummary({ code: 220, lines: [] })).toBe("220");
  });
});

describe("parseStartTlsProto", () => {
  it("accepts smtp (trimmed, case-insensitive)", () => {
    expect(parseStartTlsProto("smtp")).toBe("smtp");
    expect(parseStartTlsProto(" SMTP ")).toBe("smtp");
  });

  it("rejects unsupported protocols with a clear message", () => {
    expect(() => parseStartTlsProto("imap")).toThrow(/unsupported --starttls protocol "imap" \(supported: smtp\)/);
    expect(() => parseStartTlsProto("")).toThrow(/unsupported --starttls protocol/);
  });
});

describe("parseTarget with a STARTTLS default port", () => {
  it("defaults a bare host to the given port", () => {
    expect(parseTarget("mx.example.com", 587)).toEqual({ host: "mx.example.com", port: 587 });
  });

  it("keeps an explicit port", () => {
    expect(parseTarget("mx.example.com:25", 587)).toEqual({ host: "mx.example.com", port: 25 });
  });

  it("still defaults to 443 when no default is given", () => {
    expect(parseTarget("example.com")).toEqual({ host: "example.com", port: 443 });
  });
});
