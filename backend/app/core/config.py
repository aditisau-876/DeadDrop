
from __future__ import annotations

import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


# config.py:
# backend/app/core/config.py
#
# parents[2] = backend/
# parents[3] = project root/

BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = Path(__file__).resolve().parents[3]

BACKEND_ENV = BACKEND_DIR / ".env"
ROOT_ENV = PROJECT_ROOT / ".env"

# Prefer backend/.env, otherwise use project-root/.env.
if BACKEND_ENV.is_file():
    ENV_FILE = BACKEND_ENV
elif ROOT_ENV.is_file():
    ENV_FILE = ROOT_ENV
else:
    ENV_FILE = BACKEND_ENV


class Settings(BaseSettings):
    app_name: str = "DeadDrop"
    app_env: str = "development"
    debug: bool = True

    database_url: str

    blockchain_rpc_url: str = "http://127.0.0.1:8545"
    blockchain_chain_id: int = 31337

    blockchain_verifying_contract_address: str = (
        "0x0000000000000000000000000000000000000000"
    )

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


settings = Settings()
