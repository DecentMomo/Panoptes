# Demo script (about three minutes)

Warm the cache first. A cold explanation takes about a minute on this machine
and would stall the talk. Run the seed, then **open every finding you will show
once** and wait until the explanation is `completed` before you start the clock.

```bash
docker compose up --build
docker compose exec ollama ollama pull qwen2.5-coder:7b
python scripts/seed_demo.py
```

Log in as `demo@panoptes.dev` / `password123`. The seed zips the sample without
`secrets.py`, scans it, requests three explanations, marks `calc.py` as a false
positive, then uploads a second zip with `calc.py` fixed and `leftover.py` added.

If Ollama is down, skip the explanation panel and use the failure state instead:
the rest of the product still works, and that is worth showing.

## 0:00 Dashboard

Projects page: counts, including average AI latency. Open the Demo project, then
the first scan. Point at severity cards, the CWE bar chart, and the OWASP pie.

## 0:40 Finding and explanation

Open the prompt-injection `eval` finding. Code is highlighted, CWE/OWASP badges
are links, the amber **AI-generated, requires review** banner is visible, and
the suggested fix is a line diff rendered as text. Say plainly: the model
explains; it does not change severity, CWE, or whether this is a finding.

## 1:20 False positive

On `calc.py` / B307, mark false positive and type a reason. Show the history
row. Without a reason, Save stays disabled.

## 1:45 Fix then rescan

The second scan is already in the seed (`demo-fixed.zip`). Open **Compare scans**.
`calc.py` is **Fixed**, `leftover.py` is **New**, the rest are **Still Open**.
Those buckets are fingerprint set difference, not line numbers.

## 2:20 Carry-over

Go back to the second scan's `calc.py` if it is still present as suppressed, or
open the carried false positive on an unchanged file from a third scan if you
rescanned the original zip live. The history says **carried over from scan N**,
attributed to the original user, not a fresh decision. Changing the flagged
line would have produced a new fingerprint and an `open` finding.

## 2:45 Security notes

One slide or the [SECURITY.md](../SECURITY.md) table: HttpOnly access cookie,
CSRF MAC bound to the user id, Zip Slip and zip-bomb caps, scanners as argv
lists, Gitleaks never sent to the model, suppressions audited.

If you have seconds left, stop Ollama and hit Retry on an unexplained finding to
show `model_unavailable` without taking the app down.
