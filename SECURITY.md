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
| Zip symlink escape | A zip entry whose Unix mode is a symlink is rejected. After a git clone, the tree is walked with `lstat` and any symlink fails the scan the same way. `assert_within` also follows symlinks on disk, so a link that points outside the scan directory fails before a snippet is read. |
| Zip bomb | The declared uncompressed size is checked first. Each member is then streamed to disk in 64 KB chunks while the real bytes are counted, and the partial file is deleted if the running total passes the cap (default 100 MB uncompressed, 20 MB upload, 5,000 files). The cap is a disk cap: one chunk is in memory at a time, not a second copy of the member. Headers are not trusted on their own. |
| Uploading something other than source | Extensions outside the allowlist are skipped. They do not fail the scan. The allowlist is deliberately wide: `.py`/`.js` and friends, `.md`, shell scripts, `.pem`/`.key`/`.crt`, Terraform `.tfvars`, any `.env*` name (so `.env.local` and `.env.production` are kept), and extensionless `Dockerfile` and `Makefile`. A scanner cannot flag a secret in a file that was never extracted, and a clean result for that reason would be worse than skipping the scanner. Traversal is not skipped: it rejects the whole archive. |
| A scanner or a snippet reading outside the scan directory | `assert_within` is the check, and the temp directory is deleted in a `finally` block after the scan. |

## Subprocess execution

| Threat | Control |
| --- | --- |
| Command injection | Scanners are started with a list of arguments and `shell=False`. `run_tool` refuses a string. The path it receives is the scan directory the server created, not a string from the upload name. |
| A scanner that hangs | `subprocess.run` has a per-tool timeout (Bandit 120s, Semgrep 300s, Gitleaks 60s, git clone 60s). A timeout or a failure is stored on that scanner's row. The scan is `partial` if at least one tool finished, and `failed` only if none did. Bandit is run with `--exit-zero`, so a nonzero exit means the tool failed, not that it found issues. |
| Semgrep phoning home | Semgrep is run with `--metrics=off` and `--disable-version-check`, and `SEMGREP_SEND_METRICS=off`. The `p/security-audit` and `p/owasp-top-ten` rules are downloaded when the image is built and read from `/opt/semgrep-rules`. A scan does not contact the Semgrep registry. When the image is built, each downloaded ruleset is checked against a pinned SHA256 (`SEMGREP_SECURITY_AUDIT_SHA256`, `SEMGREP_OWASP_TOP_TEN_SHA256`). A changed ruleset fails the build until the hash is updated on purpose. The `p/...` URLs are not versioned, so an earlier ruleset cannot be fetched again: a rebuild either gets the same bytes or fails. The hash proves the file is unchanged, not that the rules are good. |
| A secret landing in the database or a log | Gitleaks runs as `gitleaks dir` with `--redact`. The stored snippet is that redacted match, truncated to 120 characters, and the report file is deleted after it is parsed. If the match is not redacted, it is replaced with `REDACTED` and not stored. Any other tool's snippet that covers the same line is masked on that span. Scanner stdout is not written to the log. |

## Git clone

| Threat | Control |
| --- | --- |
| Cloning an unexpected host | `urlsplit` must see scheme `https` and a netloc that is exactly `github.com` or `gitlab.com`. That single comparison rejects userinfo (`https://evil@github.com`, `https://github.com@evil.com`), a lookalike host, a port, and a trailing dot. The path allows `owner/repo` plus up to two GitLab subgroup levels, and rejects `.`, `..`, `%`, and backslashes. |
| SSRF to a private address | The hostname is resolved with `getaddrinfo` and every address must be a public unicast address, for IPv4 and IPv6. Mapped IPv4 (`::ffff:127.0.0.1`) is unwrapped and checked as IPv4. The check runs again in the worker immediately before `git` starts. |
| Git features that escape the clone | The clone is `git -c protocol.allow=never -c protocol.https.allow=always -c http.followRedirects=false -c core.symlinks=false -c core.hooksPath=/dev/null -c credential.helper= clone --depth 1 --no-recurse-submodules --single-branch -- <url> <dest>`. The environment is only `PATH`, a scan-local `HOME`, `GIT_TERMINAL_PROMPT=0`, `GIT_CONFIG_NOSYSTEM=1`, and `GIT_CONFIG_GLOBAL=/dev/null`. `--` stops the URL being read as an option. |
| A cloned tree that is too big, or a symlink a scanner would follow | `.git` is deleted so history and pack files are not scanned. The same file-count and uncompressed-size caps as zip extraction are applied, and files outside the allowlist are removed. A symlink fails the scan. |

What this does not do:

- Git resolves the hostname again itself. With the host restricted to github.com and gitlab.com, reaching a private address that way requires a resolver that lies about one of those two names. That residual DNS-rebinding risk is small, and it is real.
- The size cap is applied after the clone. During the clone, only the 60 second timeout bounds how much is downloaded.
- `http.followRedirects=false` means a renamed repository fails instead of being followed. That is intentional: a redirect would be a host we did not check.

## AI explanations

| Threat | Control |
| --- | --- |
| Prompt injection in scanned source | The prompt labels the code as untrusted data, encloses it in explicit delimiters, and says never to follow instructions inside it. Delimiter text found in the source is replaced before prompting. Ollama's JSON is validated with Pydantic before any text is stored. |
| The model changing the scanner's verdict | The model is only asked for explanation and fix text. The `ai_explanations` table has no severity, CWE, OWASP, finding-status, or vulnerability-verdict columns, so even a hostile valid response has nowhere to persist those values. |
| Sending a discovered secret to another component | Findings reported by Gitleaks never call Ollama, even though their stored preview is redacted. The API returns fixed scanner guidance instead. |
| Stale output after a prompt change | The cache key is `(fingerprint, model_name, prompt_version)`. A new prompt version cannot reuse an explanation produced by an older prompt. |
| Ollama failure breaking the scanner | AI work uses a dedicated one-worker executor and a `queued`/`running`/`completed`/`failed` lifecycle. Connection errors, timeouts, and invalid responses become short public reason codes. Scanning and finding access do not depend on Ollama. |
| AI request flood | Explanation creation uses an in-memory per-user sliding window, separate from scan rate limiting. Only one model call runs at once by default because concurrent 7B inference on a CPU would compete for memory and make both calls slower. |

## Rate limiting

| Threat | Control |
| --- | --- |
| Scan-creation flood | An in-memory sliding window allows 5 scan creations per user per minute, then returns 429. It is per process and resets on restart, which matches a single uvicorn worker. |
| Too many scans at once | At most 2 scans run, on a `ThreadPoolExecutor` that is separate from the API's worker threads. If 8 scans are already `queued`, a new one is refused with 429. The count is a database count, so it survives a restart. Two requests can both pass the check and exceed the cap by one. |
| Password guessing | Login is limited twice: 10 attempts per minute per client IP, and 20 per minute per submitted email. Either bucket returning full is a 429 with the same message. The IP limit is the tighter one so a single host is blocked before it can use up a known account's email bucket and lock the real owner out. The email bucket is what stops the same account being sprayed from many addresses. |

## Known limitations

- Login, scan, and AI explanation rate limits are not shared across processes and are forgotten on restart.
- The login IP is `request.client.host`. `X-Forwarded-For` is not trusted. Behind a reverse proxy every request would look like one address until trusted-proxy handling is added, and the per-IP bucket would then be shared by everyone.
- An attacker who can overwrite the `access_token` cookie (subdomain takeover, or a plaintext-HTTP man-in-the-middle, since cookie scope ignores scheme and port) can substitute their own session. That is a stolen session of their own user, not a CSRF bypass for the victim: the CSRF MAC is checked against the user id inside that token.
- Access tokens last 60 minutes and there is no refresh token. After expiry the user logs in again.
- There is no password reset or email verification.
- Login and registration do not require the CSRF header, because the user has no CSRF cookie yet. A site can submit a login form on the victim's behalf (login CSRF). The session cookie is `SameSite=Lax`, which blocks it from being sent on cross-site POSTs afterwards.
