# Panoptes

AI-assisted code vulnerability scanner. You can register, create a project, and
either upload a zip or clone a public GitHub or GitLab repository. Panoptes runs
Bandit, Semgrep, and Gitleaks, merges duplicate findings, and labels them with
CWE and OWASP Top 10:2025. Explanations come in a later phase.

## Run

```bash
cp .env.example .env
docker compose up --build
```

- API: http://localhost:8000/health
- UI: http://localhost:5173
- Ollama: http://localhost:11434

The Ollama model is not pulled automatically (it is several gigabytes). When
explanations are added, pull it with:

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

## Layout

- `backend/` — FastAPI application
- `frontend/` — React + Vite application
- `docker-compose.yml` — db, backend, frontend, ollama
