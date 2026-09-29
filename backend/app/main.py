import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.auth import router as auth_router
from app.api.projects import router as projects_router
from app.core.config import settings

logger = logging.getLogger("panoptes")


def create_app() -> FastAPI:
    if settings.secret_key.startswith("change-me") or len(settings.secret_key.encode()) < 32:
        logger.warning(
            "SECRET_KEY is still a placeholder or shorter than 32 bytes. "
            "Set a real value before sharing this deployment."
        )

    app = FastAPI(title="Panoptes")
    app.include_router(auth_router)
    app.include_router(projects_router)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
