# Panoptes

AI-assisted code vulnerability scanner. You can register, create a project, and
either upload a zip or clone a public GitHub or GitLab repository. Panoptes runs
Bandit, Semgrep, and Gitleaks, merges duplicate findings, and labels them with
CWE and OWASP Top 10:2025. A local Ollama model explains findings and suggests
fixes on demand; scanning still works when the model is unavailable.

## Run

```bash
cp .env.example .env
docker compose up --build
```

- API: http://localhost:8000/health
- UI: http://localhost:5173
- Ollama: http://localhost:11434

The Ollama model is not pulled automatically because it is several gigabytes.
Pull it once with:

```bash
docker compose exec ollama ollama pull qwen2.5-coder:7b
```

## How a scan runs

A scan is queued, then picked up by a pool of two worker threads. The code is
extracted or cloned into a temporary directory, and the three scanners run one
after another. If one of them times out or crashes, its row is marked and the
scan finishes as `partial` with whatever the others found. The scan is `failed`
only when none of them finish, or when the archive or the URL is rejected.
OWASP labels come from a static CWE table for the 2025 edition (`A05:2025 -
Injection`, never a bare `A05`). A CWE that is not in that table stays
unlabelled.

Bandit and Semgrep findings are merged when they share a file, a starting line,
and a CWE. Gitleaks findings are never merged. If the two tools disagree about
the CWE, both findings stay: dropping one would hide a result, and merging them
would claim they are the same bug.

## Fingerprinting

A finding's identity is `sha256(relative path + rule id + snippet + occurrence)`.
The line number is not included, so adding an import does not make every finding
look new. The snippet has its whitespace removed, so reformatting does not
either. `occurrence` is the Nth identical snippet in that file (the first is 0).
Without it, two copies of the same line would share one fingerprint and one
would be dropped. Order is by line, so the index stays stable when the file
shifts.

## AI explanations

Opening a finding queues one explanation on a dedicated single-worker executor.
The API returns immediately with `202`, and the page polls every two seconds
until the row is `completed` or `failed`. A cached result with the same finding
fingerprint, model name, and prompt version returns immediately with `200`.
Explanations are generated only when opened: sending every result from a
150-finding scan to a local model would make the scan unusable.

Source code is untrusted prompt data. Panoptes places it between explicit
delimiters, tells the model never to obey instructions inside it, and validates
the JSON response before storing it. The explanation table can hold explanation
and suggested-code text but has no columns for scanner severity, CWE, OWASP
category, finding status, or vulnerability verdict. Gitleaks findings never
reach Ollama and receive fixed guidance instead.

If Ollama is down, times out, or returns invalid JSON, the finding remains fully
available and the page offers Retry. Each successful call records latency,
prompt tokens, and completion tokens. On this development machine,
`qwen2.5-coder:7b` took 67.4 seconds for the prompt-injection sample (231 prompt
tokens, 200 completion tokens) and 52.1 seconds for a second finding (219 prompt
tokens, 193 completion tokens): 59.8 seconds average across the two calls. These
are small local measurements, not a benchmark. With Ollama stopped, the request
failed as `model_unavailable` while the project, scan, and finding APIs continued
to return normally; retrying after restart completed successfully.

## Dashboard and finding status

The scan page shows severity counts, findings by CWE and OWASP category, and a
table that can be filtered by severity, tool, status, and file path. Opening a
finding shows the code with the flagged lines marked, the official CWE and
OWASP references, and the suggested fix as a line diff. Model output is rendered
as text. A finding can be marked open, fixed, false positive, or accepted risk.
A false positive requires a reason, and every change is stored with the user and
the time. There is no way to edit or delete that history.

## Layout

- `backend/` — FastAPI application
- `frontend/` — React + Vite application
- `docker-compose.yml` — db, backend, frontend, ollama
