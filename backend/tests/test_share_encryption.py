from app.crypto.share_encryption import (
    decrypt_share,
    encrypt_share_for_trustee,
    generate_trustee_key_pair,
)


def test_share_encryption_round_trip():
    key_pair = generate_trustee_key_pair()

    original_share = (
        "test-secret-share"
    )

    encrypted = encrypt_share_for_trustee(
        original_share,
        trustee_public_key=key_pair.public_key,
        policy_id="policy-1",
        trustee_id="trustee-1",
        epoch=1,
    )

    decrypted = decrypt_share(
        encrypted,
        trustee_private_key=key_pair.private_key,
    )

    assert decrypted == original_share