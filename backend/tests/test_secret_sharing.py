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
    secret = b"another secret!!"

    result = split_secret(
        secret,
        threshold=3,
        share_count=5,
    )

    recovered = reconstruct_secret(
        result.shares, threshold=result.threshold,
    )

    assert recovered == secret

def test_browser_gf256_shares_reconstruct_in_backend():
    from app.crypto.secret_sharing import split_secret_gf256

    secret = bytes(range(32))
    shares = split_secret_gf256(secret, threshold=3, share_count=5)

    assert reconstruct_secret(shares[:3], threshold=3) == secret
    assert reconstruct_secret([shares[0], shares[2], shares[4]], threshold=3) == secret


def test_browser_gf256_rejects_duplicate_coordinates():
    import pytest
    from app.crypto.secret_sharing import split_secret_gf256

    shares = split_secret_gf256(b"a sufficiently long test key", threshold=2, share_count=3)
    with pytest.raises(ValueError, match="Duplicate"):
        reconstruct_secret([shares[0], shares[0]], threshold=2)
