
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    actor_user_id: str | None
    action: str
    route: str
    status_code: int
    ip_address: str | None
    user_agent: str | None
    request_id: str
    created_at: datetime
