# Security Policy

## What JWT Glass does

JWT Glass is a **decode-only** educational tool. It base64url-decodes the header and payload of a JSON Web Token in the browser so you can inspect claims.

## What JWT Glass does **not** do

- It does **not** verify cryptographic signatures.
- It does **not** validate token authenticity against an issuer's keys.
- It does **not** implement authentication, authorization, or session management.
- It must **not** be used as an auth library or as a substitute for proper JWT verification on a trusted server.

## Privacy

All decoding happens client-side. Tokens are never sent to a server by this application. Prefer synthetic/demo tokens when sharing screenshots.

## Reporting issues

If you discover a security-relevant issue in this portfolio demo, open an issue in the portfolio repository or contact Saeed Rumaneh via the contact details on his public CV / portfolio site.
