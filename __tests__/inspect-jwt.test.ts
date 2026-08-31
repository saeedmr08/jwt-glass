import { describe, expect, it } from "vitest";
import {
  createDemoTokens,
  inspectJwt,
  OVERSIZE_THRESHOLD,
} from "../lib/inspect-jwt";

/** Fixed “now” for deterministic expiry tests (2026-01-15T12:00:00Z). */
const NOW = 1768478400;

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj), "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function token(
  header: unknown,
  payload: unknown,
  sig = "c2lnbmF0dXJl"
): string {
  return `${b64url(header)}.${b64url(payload)}.${sig}`;
}

describe("inspectJwt", () => {
  it("decodes a valid 3-part token", () => {
    const raw = token(
      { alg: "HS256", typ: "JWT" },
      {
        iss: "https://issuer.example",
        sub: "user-42",
        aud: "api",
        iat: NOW - 60,
        exp: NOW + 3600,
      }
    );

    const result = inspectJwt(raw, { now: NOW });

    expect(result.ok).toBe(true);
    expect(result.header).toEqual({ alg: "HS256", typ: "JWT" });
    expect(result.payload?.sub).toBe("user-42");
    expect(result.payload?.iss).toBe("https://issuer.example");
    expect(result.claims.some((c) => c.key === "exp")).toBe(true);
    expect(result.claims.some((c) => c.key === "alg")).toBe(true);
    expect(result.displayToken).toContain("[REDACTED");
    expect(result.displayToken).not.toContain("c2lnbmF0dXJl");
  });

  it("flags a malformed token (not three parts)", () => {
    const result = inspectJwt("not.a.jwt.extra", { now: NOW });

    expect(result.ok).toBe(false);
    expect(result.warnings.some((w) => w.code === "not_three_parts")).toBe(
      true
    );
  });

  it("warns on alg=none", () => {
    const raw = token({ alg: "none", typ: "JWT" }, { sub: "x", iat: NOW }, "");

    const result = inspectJwt(raw, { now: NOW });

    expect(result.ok).toBe(true);
    const none = result.warnings.find((w) => w.code === "alg_none");
    expect(none).toBeDefined();
    expect(none?.severity).toBe("critical");
  });

  it("warns when token is already expired", () => {
    const raw = token(
      { alg: "HS256", typ: "JWT" },
      { sub: "x", iat: NOW - 7200, exp: NOW - 1 }
    );

    const result = inspectJwt(raw, { now: NOW });

    expect(result.ok).toBe(true);
    const expired = result.warnings.find((w) => w.code === "expired");
    expect(expired).toBeDefined();
    expect(expired?.severity).toBe("critical");
  });

  it("warns when exp is missing", () => {
    const raw = token({ alg: "HS256", typ: "JWT" }, { sub: "x", iat: NOW });

    const result = inspectJwt(raw, { now: NOW });

    expect(result.warnings.some((w) => w.code === "missing_exp")).toBe(true);
  });

  it("warns on far-future iat", () => {
    const raw = token(
      { alg: "HS256", typ: "JWT" },
      { sub: "x", iat: NOW + 60 * 60 * 24 * 400, exp: NOW + 60 * 60 * 24 * 401 }
    );

    const result = inspectJwt(raw, { now: NOW });

    expect(result.warnings.some((w) => w.code === "far_future_iat")).toBe(
      true
    );
  });

  it("warns on oversized tokens", () => {
    const fatPayload = { sub: "x", blob: "a".repeat(OVERSIZE_THRESHOLD) };
    const raw = token({ alg: "HS256", typ: "JWT" }, fatPayload);

    const result = inspectJwt(raw, { now: NOW });

    expect(result.warnings.some((w) => w.code === "oversized")).toBe(true);
  });
});

describe("createDemoTokens", () => {
  it("returns clearly labeled DEMO tokens that decode", () => {
    const demos = createDemoTokens(NOW);
    expect(demos.length).toBeGreaterThanOrEqual(2);
    for (const d of demos) {
      expect(d.badge).toBe("DEMO");
      const result = inspectJwt(d.token, { now: NOW });
      expect(result.ok).toBe(true);
    }
  });
});
