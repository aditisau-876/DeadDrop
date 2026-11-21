from __future__ import annotations
import base64, hashlib, hmac, json, secrets, time
from datetime import datetime, timedelta, timezone
from typing import Any
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from app.core.config import settings
from app.db.database import get_db
from app.models.user import User

bearer_scheme = HTTPBearer(auto_error=False)
ROLES = {"admin", "owner", "trustee"}

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=64)
    return f"scrypt${_b64(salt)}${_b64(derived)}"

def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, salt_text, hash_text = encoded.split("$", 2)
        if scheme != "scrypt": return False
        expected = _unb64(hash_text)
        actual = hashlib.scrypt(password.encode("utf-8"), salt=_unb64(salt_text), n=2**14, r=8, p=1, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False

def create_access_token(user: User) -> str:
    now = int(time.time())
    header = _b64(json.dumps({"alg":"HS256","typ":"JWT"}, separators=(",", ":")).encode())
    payload = _b64(json.dumps({"sub":user.id,"role":user.role,"iat":now,"exp":now + settings.access_token_expire_minutes*60}, separators=(",", ":")).encode())
    message = f"{header}.{payload}"
    secret = settings.jwt_secret_key.encode("utf-8")
    signature = _b64(hmac.new(secret, message.encode(), hashlib.sha256).digest())
    return f"{message}.{signature}"

def decode_access_token(token: str) -> dict[str, Any]:
    try:
        header, payload, signature = token.split(".")
        message = f"{header}.{payload}"
        expected = _b64(hmac.new(settings.jwt_secret_key.encode(), message.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected): raise ValueError("Invalid signature")
        claims = json.loads(_unb64(payload))
        if claims.get("exp", 0) <= int(time.time()): raise ValueError("Expired token")
        if not claims.get("sub"): raise ValueError("Missing subject")
        return claims
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired access token.", headers={"WWW-Authenticate":"Bearer"}) from exc

def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme), db: Session = Depends(get_db)) -> User:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Authentication required.", headers={"WWW-Authenticate":"Bearer"})
    claims = decode_access_token(credentials.credentials)
    user = db.get(User, claims["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User account is unavailable.")
    return user

def require_roles(*roles: str):
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="You do not have permission to perform this action.")
        return user
    return dependency

def ensure_owner_or_admin(user: User, owner_user_id: str | None) -> None:
    # Unowned legacy records are deliberately admin-only until explicitly assigned.
    if user.role != "admin" and (owner_user_id is None or owner_user_id != user.id):
        raise HTTPException(status_code=404, detail="Resource not found.")

def generate_random_bytes(length: int) -> bytes:
    if length <= 0: raise ValueError("Length must be greater than zero.")
    return secrets.token_bytes(length)

def generate_nonce(length: int = 32) -> str:
    if length <= 0: raise ValueError("Length must be greater than zero.")
    return secrets.token_hex(length)

def sha256_hex(data: bytes) -> str: return hashlib.sha256(data).hexdigest()
def sha256_bytes(data: bytes) -> bytes: return hashlib.sha256(data).digest()
def secure_compare(left: str, right: str) -> bool: return hmac.compare_digest(left, right)
def generate_identifier() -> str: return secrets.token_urlsafe(24)
