# Repository Guidance

## Security invariants

- Never commit the upstream subscription URL, query Token, node plaintext, encryption key, or Ed25519 signing private key.
- Production credentials must only enter automation through GitHub Actions Secrets.
- Generated logs and errors must not print subscription contents or credential-bearing URLs.
- Public files must be generated atomically and verified before publication.
- The signing private key must never be embedded in Wocao Hub or this repository.

## Implementation constraints

- Do not use Go, Node.js, `.mjs`, Mihomo, Xray, or sing-box.
- Prefer a small Rust publishing tool with deterministic output and tests.
- Keep the public artifact format versioned and backward compatible.
- Do not add placeholder product pages or unrelated frontend content.

## Required verification

- Format, test, and lint the publishing tool before committing.
- Scan the repository for credential-bearing URLs and private-key material before every push.
