# Security

This file records the threats Panoptes is built to resist and the control that
addresses each one. Later phases add the sections for git cloning and the LLM.

## Authentication and access control

| Threat | Control |
| --- | --- |
| Stolen password database | Passwords are hashed with bcrypt (the `bcrypt` package directly, not passlib). A password longer than 72 bytes is rejected, because bcrypt would otherwise silently ignore the extra bytes. |
| Forged or confused JWT | Tokens are signed with HMAC-SHA256 via PyJWT. Verification passes an explicit algorithm allowlist (`algorithms=["HS256"]`), which rejects `alg: none` and tokens signed with a different algorithm. `python-jose` was not used: it has open algorithm-confusion vulnerabilities (CVE-2024-33663, CVE-2024-33664) and is unmaintained. |
| Token theft through XSS | The access token is an `HttpOnly` cookie, so page JavaScript cannot read it. |
| Cross-site request forgery | Unsafe requests must repeat the `csrf_token` cookie (not HttpOnly) in the `X-CSRF-Token` header. A cross-site page can trigger the cookie but cannot read it, so it cannot set the header. The value is not a random string: it is a nonce plus an HMAC of the user id under `SECRET_KEY`. Matching cookie and header is not enough; `verify_csrf` checks the MAC against the user id in the access token (signature checked, expiry ignored so logout still works after the access token expires). An attacker who can write cookies for the domain can plant a pair, but cannot produce a MAC for the victim's user id. |
| Account enumeration by timing | A login for an unknown email still runs a bcrypt check against a dummy hash, and returns the same 401 body as a wrong password. |
| Broken object level authorization | Every project query goes through `get_owned_project`, and every scan query through `get_owned_scan`, which joins to the owning user. Another user's project or scan returns 404, so the id does not even confirm that it exists. Covered by `test_bola.py`. |
| Placeholder signing key | The process logs a warning at startup if `SECRET_KEY` still starts with `change-me` or is shorter than 32 bytes. HMAC-SHA256 keys shorter than that are rejected by PyJWT as insecure. |

## Uploads

| Threat | Control |
| --- | --- |
| Zip Slip (paths with `..` or an absolute path) | Member names are rejected before anything is written. After the destination path is joined, `assert_within` resolves it and refuses it unless it is still inside the scan directory. The same check runs before a snippet is read back. |
| Zip symlink escape | A zip entry whose Unix mode is a symlink is rejected. `assert_within` also follows symlinks on disk, so a link that points outside the scan directory fails. |
| Zip bomb | The declared uncompressed size is checked first. Each member is then streamed to disk in 64 KB chunks while the real bytes are counted, and the partial file is deleted if the running total passes the cap (default 100 MB uncompressed, 20 MB upload, 5,000 files). The cap is a disk cap: one chunk is in memory at a time, not a second copy of the member. Headers are not trusted on their own. |
| Uploading something other than source | Extensions outside the allowlist are skipped. They do not fail the scan. The allowlist is deliberately wide: `.py`/`.js` and friends, `.md`, shell scripts, `.pem`/`.key`/`.crt`, Terraform `.tfvars`, any `.env*` name (so `.env.local` and `.env.production` are kept), and extensionless `Dockerfile` and `Makefile`. A scanner cannot flag a secret in a file that was never extracted, and a clean result for that reason would be worse than skipping the scanner. Traversal is not skipped: it rejects the whole archive. |
| A scanner or a snippet reading outside the scan directory | `assert_within` is the check, and the temp directory is deleted in a `finally` block after the scan. |

## Subprocess execution

| Threat | Control |
| --- | --- |
| Command injection | Scanners are started with a list of arguments and `shell=False`. `run_tool` refuses a string. The path it receives is the scan directory the server created, not a string from the upload name. |
| A scanner that hangs | `subprocess.run` has a timeout (default 120 seconds). A timeout is stored on that scanner's row and the scan is marked failed with a generic message. Bandit is run with `--exit-zero`, so a nonzero exit means the tool failed, not that it found issues. |

## Rate limiting

| Threat | Control |
| --- | --- |
| Scan-creation flood | An in-memory sliding window allows 5 scan creations per user per minute, then returns 429. It is per process and resets on restart, which matches a single uvicorn worker. |
| Password guessing | Login is limited twice: 10 attempts per minute per client IP, and 20 per minute per submitted email. Either bucket returning full is a 429 with the same message. The IP limit is the tighter one so a single host is blocked before it can use up a known account's email bucket and lock the real owner out. The email bucket is what stops the same account being sprayed from many addresses. |

## Known limitations

- Login and scan rate limits are not shared across processes and are forgotten on restart. The AI explanation endpoint is limited when it is added.
- The login IP is `request.client.host`. `X-Forwarded-For` is not trusted. Behind a reverse proxy every request would look like one address until trusted-proxy handling is added, and the per-IP bucket would then be shared by everyone.
- An attacker who can overwrite the `access_token` cookie (subdomain takeover, or a plaintext-HTTP man-in-the-middle, since cookie scope ignores scheme and port) can substitute their own session. That is a stolen session of their own user, not a CSRF bypass for the victim: the CSRF MAC is checked against the user id inside that token.
- Access tokens last 60 minutes and there is no refresh token. After expiry the user logs in again.
- There is no password reset or email verification.
- Login and registration do not require the CSRF header, because the user has no CSRF cookie yet. A site can submit a login form on the victim's behalf (login CSRF). The session cookie is `SameSite=Lax`, which blocks it from being sent on cross-site POSTs afterwards.
