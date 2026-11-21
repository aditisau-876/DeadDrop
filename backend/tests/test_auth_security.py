from app.core.security import (
    create_access_token, decode_access_token, hash_password, verify_password,
)
from app.models.user import User

def test_scrypt_password_hashing():
    password = "Correct-Horse-Battery-2026!"
    encoded = hash_password(password)
    assert encoded.startswith("scrypt$")
    assert verify_password(password, encoded)
    assert not verify_password("not-the-password", encoded)

def test_access_token_contains_subject_and_role():
    user = User(
        id="test-user-id", email="owner@example.com",
        password_hash="unused", full_name="Test Owner",
        role="owner", is_active=True,
    )
    token = create_access_token(user)
    claims = decode_access_token(token)
    assert claims["sub"] == "test-user-id"
    assert claims["role"] == "owner"

def test_tampered_access_token_is_rejected():
    user = User(
        id="test-user-id", email="owner@example.com",
        password_hash="unused", full_name="Test Owner",
        role="owner", is_active=True,
    )
    token = create_access_token(user)
    parts = token.split(".")
    parts[1] = parts[1][:-1] + ("A" if parts[1][-1] != "A" else "B")
    try:
        decode_access_token(".".join(parts))
    except Exception:
        return
    raise AssertionError("Tampered JWT was accepted")
