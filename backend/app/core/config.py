from __future__ import annotations
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ENV = BACKEND_DIR / ".env"
ROOT_ENV = PROJECT_ROOT / ".env"
ENV_FILE = BACKEND_ENV if BACKEND_ENV.is_file() else (ROOT_ENV if ROOT_ENV.is_file() else BACKEND_ENV)
class Settings(BaseSettings):
    app_name: str = "DeadDrop"
    app_env: str = "development"
    debug: bool = True
    database_url: str
    jwt_secret_key: str = "CHANGE_THIS_DEVELOPMENT_SECRET_TO_A_RANDOM_64_CHAR_VALUE"
    access_token_expire_minutes: int = 30
    allow_public_registration: bool = True
    blockchain_rpc_url: str = "http://127.0.0.1:8545"
    blockchain_chain_id: int = 31337
    blockchain_verifying_contract_address: str = "0x0000000000000000000000000000000000000000"
    model_config = SettingsConfigDict(env_file=str(ENV_FILE), env_file_encoding="utf-8", case_sensitive=False, extra="ignore")
settings = Settings()
if settings.app_env.lower() == "production" and (len(settings.jwt_secret_key) < 48 or settings.jwt_secret_key.startswith("CHANGE_THIS")):
    raise RuntimeError("Set a strong JWT_SECRET_KEY (at least 48 characters) in production.")
