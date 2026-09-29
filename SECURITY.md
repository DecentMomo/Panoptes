# Security

This file records the threats Panoptes is built to resist and the control that
addresses each one. Later phases add the sections for uploads, cloning, and the
LLM. This section covers authentication.

## Authentication and access control

| Threat | Control |
| --- | --- |
| Stolen password database | Passwords are hashed with bcrypt (the `bcrypt` package directly, not passlib). A password longer than 72 bytes is rejected, because bcrypt would otherwise silently ignore the extra bytes. |
| Forged or confused JWT | Tokens are signed with HMAC-SHA256 via PyJWT. Verification passes an explicit algorithm allowlist (`algorithms=["HS256"]`), which rejects `alg: none` and tokens signed with a different algorithm. `python-jose` was not used: it has open algorithm-confusion vulnerabilities (CVE-2024-33663, CVE-2024-33664) and is unmaintained. |
| Token theft through XSS | The access token is an `HttpOnly` cookie, so page JavaScript cannot read it. |
| Cross-site request forgery | Because the cookie is sent automatically, unsafe requests must repeat a second cookie (`csrf_token`, not HttpOnly) in the `X-CSRF-Token` header. A cross-site page can trigger the cookie but cannot read it, so it cannot set the header. The comparison uses `secrets.compare_digest`. |
| Account enumeration by timing | A login for an unknown email still runs a bcrypt check against a dummy hash, and returns the same 401 body as a wrong password. |
| Broken object level authorization | Every project query goes through `get_owned_project` (or the list query), which filters on `owner_id`. Another user's project returns 404, so the id does not even confirm that a project exists. Covered by `test_bola.py`. |
| Placeholder signing key | The process logs a warning at startup if `SECRET_KEY` still starts with `change-me` or is shorter than 32 bytes. HMAC-SHA256 keys shorter than that are rejected by PyJWT as insecure. |

## Known limitations

- There is no rate limit on login yet. The spec adds rate limiting with scan creation and AI explanations. Until then, an attacker can attempt passwords as fast as bcrypt allows.
- Access tokens last 60 minutes and there is no refresh token. After expiry the user logs in again.
- There is no password reset or email verification.
- Login and registration do not require the CSRF header, because the user has no CSRF cookie yet. A site can submit a login form on the victim's behalf (login CSRF). The session cookie is `SameSite=Lax`, which blocks it from being sent on cross-site POSTs afterwards.
