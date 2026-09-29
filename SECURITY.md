# Security

This file records the threats Panoptes is built to resist and the control that
addresses each one. Later phases add the sections for git cloning and the LLM.

## Authentication and access control

| Threat | Control |
| --- | --- |
| Stolen password database | Passwords are hashed with bcrypt (the `bcrypt` package directly, not passlib). A password longer than 72 bytes is rejected, because bcrypt would otherwise silently ignore the extra bytes. |
| Forged or confused JWT | Tokens are signed with HMAC-SHA256 via PyJWT. Verification passes an explicit algorithm allowlist (`algorithms=["HS256"]`), which rejects `alg: none` and tokens signed with a different algorithm. `python-jose` was not used: it has open algorithm-confusion vulnerabilities (CVE-2024-33663, CVE-2024-33664) and is unmaintained. |
| Token theft through XSS | The access token is an `HttpOnly` cookie, so page JavaScript cannot read it. |
| Cross-site request forgery | Because the cookie is sent automatically, unsafe requests must repeat a second cookie (`csrf_token`, not HttpOnly) in the `X-CSRF-Token` header. A cross-site page can trigger the cookie but cannot read it, so it cannot set the header. The comparison uses `secrets.compare_digest`. |
| Account enumeration by timing | A login for an unknown email still runs a bcrypt check against a dummy hash, and returns the same 401 body as a wrong password. |
| Broken object level authorization | Every project query goes through `get_owned_project`, and every scan query through `get_owned_scan`, which joins to the owning user. Another user's project or scan returns 404, so the id does not even confirm that it exists. Covered by `test_bola.py`. |
| Placeholder signing key | The process logs a warning at startup if `SECRET_KEY` still starts with `change-me` or is shorter than 32 bytes. HMAC-SHA256 keys shorter than that are rejected by PyJWT as insecure. |

## Uploads

| Threat | Control |
| --- | --- |
| Zip Slip (paths with `..` or an absolute path) | Member names are rejected before anything is written. After the destination path is joined, `assert_within` resolves it and refuses it unless it is still inside the scan directory. The same check runs before a snippet is read back. |
| Zip symlink escape | A zip entry whose Unix mode is a symlink is rejected. `assert_within` also follows symlinks on disk, so a link that points outside the scan directory fails. |
| Zip bomb | The declared uncompressed size is checked first. While each member is read, the actual bytes are counted and the extract stops past the cap (default 100 MB uncompressed, 20 MB upload, 5,000 files). Headers are not trusted on their own. |
| Uploading something other than source | Extensions outside the allowlist are skipped. They do not fail the scan, because real archives contain READMEs and images. Traversal is not skipped: it rejects the whole archive. |
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

## Known limitations

- There is no rate limit on login yet. Scan creation is limited. The AI explanation endpoint is limited when it is added. Until then, an attacker can attempt passwords as fast as bcrypt allows.
- The scan rate limit is not shared across processes and is forgotten on restart.
- Access tokens last 60 minutes and there is no refresh token. After expiry the user logs in again.
- There is no password reset or email verification.
- Login and registration do not require the CSRF header, because the user has no CSRF cookie yet. A site can submit a login form on the victim's behalf (login CSRF). The session cookie is `SameSite=Lax`, which blocks it from being sent on cross-site POSTs afterwards.
