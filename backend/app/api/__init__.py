from app.api.health import router as health_router
from app.api.policies import router as policies_router
from app.api.trustees import router as trustees_router
from app.api.recovery import router as recovery_router
from app.api.readiness import router as readiness_router

__all__ = [
    "health_router",
    "policies_router",
    "trustees_router",
    "recovery_router",
    "readiness_router",
]