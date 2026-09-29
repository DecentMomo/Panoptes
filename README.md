# Panoptes

AI-assisted code vulnerability scanner. You can register, create a project, and
upload a zip. Panoptes runs Bandit on the code and lists the findings.
Explanations come in a later phase.

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
