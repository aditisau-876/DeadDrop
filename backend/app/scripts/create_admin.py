from __future__ import annotations
import os, getpass
from sqlalchemy import select
from app.core.security import hash_password, generate_identifier
from app.db.database import SessionLocal
from app.models.user import User

def main() -> None:
    email = os.getenv("ADMIN_EMAIL", "").strip().lower() or input("Admin email: ").strip().lower()
    full_name = os.getenv("ADMIN_FULL_NAME", "").strip() or input("Admin full name: ").strip()
    password = os.getenv("ADMIN_PASSWORD") or getpass.getpass("Admin password (minimum 12 characters): ")
    if len(password) < 12: raise SystemExit("Password must contain at least 12 characters.")
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.email == email)):
            raise SystemExit("An account with this email already exists.")
        user = User(id=generate_identifier(), email=email, full_name=full_name, password_hash=hash_password(password), role="admin", is_active=True)
        db.add(user); db.commit()
    print(f"Administrator account created: {email}")
if __name__ == "__main__": main()
