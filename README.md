# JWT Glass

Client-side JWT inspector for developers. Paste a token, decode the header and payload locally, and read plain-language explanations of common claims — without sending anything to a server.

**Portfolio demo by Saeed Rumaneh.** Not a production auth product.

## How to run

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

| Script | Purpose |
|--------|---------|
| `npm run dev` | Next.js dev server |
| `npm run build` | Production build |
| `npm start` | Serve production build |
| `npm test` | Vitest unit tests |
| `npm run typecheck` | TypeScript check |

## Example inputs

Use the three **DEMO** buttons in the UI, or paste:

1. **Expired HS256-shaped** — loads via “Expired HS256-shaped demo”; expect a critical `expired` warning.
2. **Unsigned alg=none** — loads via “Unsigned alg=none demo”; expect critical `alg_none`.
3. **Fresh RS256-shaped** — loads via “Fresh RS256-shaped demo”; valid-looking claims, signature still unverified.

All demos are generated in the browser (or hardcoded placeholders). Nothing is verified and nothing leaves the device.

## How it works

1. Paste a JWT or load a labeled **DEMO** token.
2. JWT Glass base64url-decodes header and payload in JavaScript (`lib/inspect-jwt.ts`).
3. Heuristic warnings: `alg=none`, missing/expired `exp`, far-future `iat`, oversized tokens.
4. Signature redacted in the UI by default.

**Client-only.** No API, no `node:crypto`, no Buffer in the client path.

## Complete product flows

1. Click **Expired HS256-shaped demo** — expect a critical expired warning. Decode stays local.
2. Click **Unsigned alg=none demo** — expect critical `alg_none`.
3. Toggle **Redact signature** off/on — the signature is hidden by default and nothing leaves the browser.

## Privacy

**Nothing leaves the browser.** This tool **does not verify signatures**. See `SECURITY.md`.

## Stack

- Next.js 15 (App Router) · React 19 · TypeScript · Vitest

## License

MIT © 2026 Saeed Rumaneh
