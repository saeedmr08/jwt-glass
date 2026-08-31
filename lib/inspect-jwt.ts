/**
 * JWT Glass — client-side JWT decode & inspect (no signature verification).
 * Synthetic / educational use only.
 */

export type JwtWarningCode =
  | "alg_none"
  | "missing_exp"
  | "expired"
  | "far_future_iat"
  | "oversized"
  | "malformed"
  | "invalid_json"
  | "not_three_parts";

export interface JwtWarning {
  code: JwtWarningCode;
  severity: "critical" | "warn" | "info";
  message: string;
}

export interface ClaimExplanation {
  key: string;
  label: string;
  value: unknown;
  explanation: string;
  formatted?: string;
}

export interface InspectResult {
  ok: boolean;
  raw: string;
  parts: {
    header: string | null;
    payload: string | null;
    signature: string | null;
  };
  header: Record<string, unknown> | null;
  payload: Record<string, unknown> | null;
  claims: ClaimExplanation[];
  warnings: JwtWarning[];
  /** Signature redacted token string for safe display */
  displayToken: string;
  sizeBytes: number;
}

const KNOWN_CLAIMS: Record<
  string,
  { label: string; explanation: string; isTime?: boolean }
> = {
  iss: {
    label: "Issuer",
    explanation:
      "Who created and signed the token (typically a URL or service identifier).",
  },
  sub: {
    label: "Subject",
    explanation:
      "Whom the token is about — usually a stable user or principal ID.",
  },
  aud: {
    label: "Audience",
    explanation:
      "Intended recipient(s). Verifiers should reject tokens not meant for them.",
  },
  exp: {
    label: "Expiration",
    explanation:
      "Unix timestamp after which the token must be rejected.",
    isTime: true,
  },
  nbf: {
    label: "Not Before",
    explanation:
      "Unix timestamp before which the token must not be accepted.",
    isTime: true,
  },
  iat: {
    label: "Issued At",
    explanation: "Unix timestamp when the token was issued.",
    isTime: true,
  },
  alg: {
    label: "Algorithm",
    explanation:
      "Header claim naming the signing algorithm. Decode tools do not verify it.",
  },
  jti: {
    label: "JWT ID",
    explanation: "Unique identifier for this token instance.",
  },
  typ: {
    label: "Type",
    explanation: "Media type of the token; usually \"JWT\".",
  },
};

/** Soft limit for educational “oversized” warning (bytes of raw string). */
export const OVERSIZE_THRESHOLD = 8192;

/** iat more than this many seconds in the future is suspicious. */
export const FAR_FUTURE_IAT_SECONDS = 60 * 60 * 24 * 365; // 1 year

function base64UrlToUtf8(segment: string): string {
  // Browser-safe only (atob). Avoid Buffer / node:crypto so client bundles stay clean.
  const padded =
    segment.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (segment.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

function tryParseJson(text: string): { ok: true; value: Record<string, unknown> } | { ok: false; error: string } {
  try {
    const value = JSON.parse(text) as unknown;
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return { ok: false, error: "JSON root must be an object" };
    }
    return { ok: true, value: value as Record<string, unknown> };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "Invalid JSON" };
  }
}

function formatUnix(value: unknown): string | undefined {
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
  try {
    return new Date(value * 1000).toISOString();
  } catch {
    return undefined;
  }
}

function redactSignature(raw: string): string {
  const parts = raw.trim().split(".");
  if (parts.length < 3) return raw;
  const sig = parts[2] ?? "";
  if (!sig) return `${parts[0]}.${parts[1]}.[empty]`;
  return `${parts[0]}.${parts[1]}.[REDACTED ${sig.length} chars]`;
}

function buildClaims(
  header: Record<string, unknown> | null,
  payload: Record<string, unknown> | null
): ClaimExplanation[] {
  const claims: ClaimExplanation[] = [];
  const seen = new Set<string>();

  const pushFrom = (obj: Record<string, unknown> | null, preferKeys: string[]) => {
    if (!obj) return;
    for (const key of preferKeys) {
      if (!(key in obj) || seen.has(key)) continue;
      seen.add(key);
      const meta = KNOWN_CLAIMS[key];
      const value = obj[key];
      claims.push({
        key,
        label: meta?.label ?? key,
        value,
        explanation:
          meta?.explanation ??
          "Custom or application-specific claim — meaning depends on the issuer.",
        formatted: meta?.isTime ? formatUnix(value) : undefined,
      });
    }
    for (const key of Object.keys(obj)) {
      if (seen.has(key)) continue;
      seen.add(key);
      const meta = KNOWN_CLAIMS[key];
      const value = obj[key];
      claims.push({
        key,
        label: meta?.label ?? key,
        value,
        explanation:
          meta?.explanation ??
          "Custom or application-specific claim — meaning depends on the issuer.",
        formatted: meta?.isTime ? formatUnix(value) : undefined,
      });
    }
  };

  // alg lives in header; standard registered claims in payload
  pushFrom(header, ["alg", "typ", "kid"]);
  pushFrom(payload, ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]);

  return claims;
}

function collectWarnings(
  raw: string,
  header: Record<string, unknown> | null,
  payload: Record<string, unknown> | null,
  nowSeconds: number
): JwtWarning[] {
  const warnings: JwtWarning[] = [];

  if (raw.length > OVERSIZE_THRESHOLD) {
    warnings.push({
      code: "oversized",
      severity: "warn",
      message: `Token is ${raw.length} characters (over ${OVERSIZE_THRESHOLD}). Oversized JWTs can hurt clients and logs.`,
    });
  }

  if (header) {
    const alg = header.alg;
    if (alg === "none" || alg === "None" || alg === "NONE") {
      warnings.push({
        code: "alg_none",
        severity: "critical",
        message:
          'Algorithm is "none" — unsigned token. Never accept alg=none in production verifiers.',
      });
    }
  }

  if (payload) {
    if (!("exp" in payload)) {
      warnings.push({
        code: "missing_exp",
        severity: "warn",
        message:
          "No exp claim. Tokens without expiration can live forever if stolen.",
      });
    } else if (typeof payload.exp === "number") {
      if (payload.exp < nowSeconds) {
        warnings.push({
          code: "expired",
          severity: "critical",
          message: `Token expired at ${formatUnix(payload.exp) ?? payload.exp}.`,
        });
      }
    }

    if (typeof payload.iat === "number") {
      if (payload.iat - nowSeconds > FAR_FUTURE_IAT_SECONDS) {
        warnings.push({
          code: "far_future_iat",
          severity: "warn",
          message:
            "iat is more than a year in the future — clock skew, forgery, or a demo artifact.",
        });
      }
    }
  }

  return warnings;
}

/**
 * Decode and inspect a JWT string. Does not verify signatures.
 */
export function inspectJwt(
  input: string,
  options?: { now?: number; redactSignature?: boolean }
): InspectResult {
  const raw = input.trim();
  const nowSeconds =
    options?.now ?? Math.floor(Date.now() / 1000);
  const shouldRedact = options?.redactSignature !== false;

  const empty: InspectResult = {
    ok: false,
    raw,
    parts: { header: null, payload: null, signature: null },
    header: null,
    payload: null,
    claims: [],
    warnings: [],
    displayToken: shouldRedact ? redactSignature(raw) : raw,
    sizeBytes: new TextEncoder().encode(raw).length,
  };

  if (!raw) {
    return {
      ...empty,
      warnings: [
        {
          code: "malformed",
          severity: "info",
          message: "Paste a JWT to inspect.",
        },
      ],
    };
  }

  const segments = raw.split(".");
  if (segments.length !== 3) {
    return {
      ...empty,
      warnings: [
        {
          code: "not_three_parts",
          severity: "critical",
          message: `Expected 3 dot-separated parts (header.payload.signature); got ${segments.length}.`,
        },
      ],
    };
  }

  const [headerB64, payloadB64, signatureB64] = segments;
  let headerText: string;
  let payloadText: string;

  try {
    headerText = base64UrlToUtf8(headerB64);
    payloadText = base64UrlToUtf8(payloadB64);
  } catch {
    return {
      ...empty,
      parts: {
        header: headerB64,
        payload: payloadB64,
        signature: signatureB64,
      },
      warnings: [
        {
          code: "malformed",
          severity: "critical",
          message: "Failed to base64url-decode header or payload.",
        },
      ],
      displayToken: shouldRedact
        ? `${headerB64}.${payloadB64}.[REDACTED]`
        : raw,
    };
  }

  const headerParsed = tryParseJson(headerText);
  const payloadParsed = tryParseJson(payloadText);
  const warnings: JwtWarning[] = [];

  if (!headerParsed.ok) {
    warnings.push({
      code: "invalid_json",
      severity: "critical",
      message: `Header is not valid JSON: ${headerParsed.error}`,
    });
  }
  if (!payloadParsed.ok) {
    warnings.push({
      code: "invalid_json",
      severity: "critical",
      message: `Payload is not valid JSON: ${payloadParsed.error}`,
    });
  }

  const header = headerParsed.ok ? headerParsed.value : null;
  const payload = payloadParsed.ok ? payloadParsed.value : null;

  if (header || payload) {
    warnings.push(...collectWarnings(raw, header, payload, nowSeconds));
  }

  const ok = header !== null && payload !== null;

  return {
    ok,
    raw,
    parts: {
      header: headerB64,
      payload: payloadB64,
      signature: signatureB64,
    },
    header,
    payload,
    claims: buildClaims(header, payload),
    warnings,
    displayToken: shouldRedact
      ? `${headerB64}.${payloadB64}.[REDACTED ${(signatureB64 ?? "").length} chars]`
      : raw,
    sizeBytes: new TextEncoder().encode(raw).length,
  };
}

/** Encode object → base64url (browser-safe; no Buffer). */
export function base64UrlEncodeJson(obj: unknown): string {
  const json = JSON.stringify(obj);
  const bytes = new TextEncoder().encode(json);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export interface DemoToken {
  id: string;
  label: string;
  description: string;
  token: string;
  badge: "DEMO";
}

/**
 * Build synthetic unsigned/demo JWTs in-browser for learning.
 * Clearly not real credentials — signatures are placeholders or empty.
 */
export function createDemoTokens(nowSeconds = Math.floor(Date.now() / 1000)): DemoToken[] {
  const expired = {
    header: { alg: "HS256", typ: "JWT" },
    payload: {
      iss: "https://demo.jwt-glass.local",
      sub: "demo-user-001",
      aud: "jwt-glass-portfolio",
      iat: nowSeconds - 7200,
      exp: nowSeconds - 3600,
      name: "DEMO — expired session",
    },
  };

  const algNone = {
    header: { alg: "none", typ: "JWT" },
    payload: {
      iss: "https://demo.jwt-glass.local",
      sub: "demo-user-002",
      aud: "jwt-glass-portfolio",
      iat: nowSeconds,
      note: "DEMO — unsigned alg=none (never trust in production)",
    },
  };

  const healthy = {
    header: { alg: "RS256", typ: "JWT", kid: "demo-key-1" },
    payload: {
      iss: "https://demo.jwt-glass.local",
      sub: "demo-user-003",
      aud: ["jwt-glass-portfolio", "api.demo.local"],
      iat: nowSeconds,
      nbf: nowSeconds,
      exp: nowSeconds + 3600,
      jti: "demo-jti-not-real",
      role: "learner",
    },
  };

  return [
    {
      id: "expired",
      label: "Expired HS256-shaped demo",
      description:
        "Looks like a normal token but exp is in the past. Signature is a fake placeholder.",
      badge: "DEMO",
      token: [
        base64UrlEncodeJson(expired.header),
        base64UrlEncodeJson(expired.payload),
        "dG90YWxseS1mYWtlLXNpZ25hdHVyZS1kZW1vLW9ubHk",
      ].join("."),
    },
    {
      id: "alg-none",
      label: "Unsigned alg=none demo",
      description:
        "Classic misconfiguration: algorithm none with an empty signature segment.",
      badge: "DEMO",
      token: [
        base64UrlEncodeJson(algNone.header),
        base64UrlEncodeJson(algNone.payload),
        "",
      ].join("."),
    },
    {
      id: "healthy",
      label: "Fresh RS256-shaped demo",
      description:
        "Valid-looking claims for learning. Signature is synthetic and unverified.",
      badge: "DEMO",
      token: [
        base64UrlEncodeJson(healthy.header),
        base64UrlEncodeJson(healthy.payload),
        "c3ludGhldGljLXJzMjU2LXNpZy1ub3QtcmVhbC1kZW1v",
      ].join("."),
    },
  ];
}
