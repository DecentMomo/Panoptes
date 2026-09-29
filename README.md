# Panoptes

AI-assisted code vulnerability scanner. Phase 1 adds registration, login, and
projects that belong to the logged-in user. Scanning and explanations come in
later phases.

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

## Layout

- `backend/` — FastAPI application
- `frontend/` — React + Vite application
- `docker-compose.yml` — db, backend, frontend, ollama
