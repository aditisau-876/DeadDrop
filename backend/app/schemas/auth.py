from pydantic import BaseModel, Field, field_validator
import re

def validate_email(value: str) -> str:
    value = value.strip().lower()
    if len(value) > 255 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        raise ValueError("A valid email address is required.")
    return value

class RegisterRequest(BaseModel):
    email: str
    password: str = Field(min_length=12, max_length=256)
    full_name: str = Field(min_length=1, max_length=120)
    _email = field_validator("email")(validate_email)

class LoginRequest(BaseModel):
    email: str
    password: str = Field(min_length=1, max_length=256)
    _email = field_validator("email")(validate_email)

class AdminUserCreate(BaseModel):
    email: str
    password: str = Field(min_length=12, max_length=256)
    full_name: str = Field(min_length=1, max_length=120)
    role: str = Field(pattern="^(owner|trustee|admin)$")
    trustee_id: str | None = None
    _email = field_validator("email")(validate_email)

class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse
