from app.crypto.encryption import (
    decrypt,
    encrypt,
    generate_key,
)


def test_encrypt_decrypt():
    key = generate_key()

    plaintext = b"DeadDrop emergency secret"

    payload = encrypt(
        plaintext,
        key,
    )

    recovered = decrypt(
        payload,
        key,
    )

    assert recovered == plaintext


def test_tampered_ciphertext_fails():
    key = generate_key()

    payload = encrypt(
        b"secret",
        key,
    )

    import base64

    raw = bytearray(
        base64.b64decode(payload.ciphertext)
    )

    raw[0] ^= 1

    tampered = payload.__class__(
        ciphertext=base64.b64encode(raw).decode(),
        nonce=payload.nonce,
        aad=payload.aad,
    )

    try:
        decrypt(tampered, key)
        assert False
    except ValueError:
        assert True