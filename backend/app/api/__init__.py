from app.api.assets import router as assets_router
from app.api.health import router as health_router
from app.api.policies import router as policies_router
from app.api.readiness import router as readiness_router
from app.api.recovery import router as recovery_router
from app.api.shares import router as shares_router
from app.api.trustees import router as trustees_router


__all__ = [
    "assets_router",
    "health_router",
    "policies_router",
    "readiness_router",
    "recovery_router",
    "shares_router",
    "trustees_router",
]