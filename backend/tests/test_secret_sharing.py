from app.crypto.secret_sharing import (
    reconstruct_secret,
    split_secret,
)


def test_threshold_reconstruction():
    secret = b"DeadDrop test secret"

    result = split_secret(
        secret,
        threshold=3,
        share_count=5,
    )

    recovered = reconstruct_secret(
        result.shares[:3]
    )

    assert recovered == secret


def test_all_shares_reconstruct():
    secret = b"another secret"

    result = split_secret(
        secret,
        threshold=3,
        share_count=5,
    )

    recovered = reconstruct_secret(
        result.shares
    )

    assert recovered == secret