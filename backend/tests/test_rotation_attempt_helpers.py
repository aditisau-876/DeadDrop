
import pytest
from fastapi import HTTPException

from app.api.share_rotation import (
    _normalize_rotation_tx_hash,
    _rotation_payload_matches,
)


def test_transaction_hash_without_prefix_is_normalized():
    tx_hash = "a" * 64

    assert _normalize_rotation_tx_hash(tx_hash) == "0x" + tx_hash


def test_transaction_hash_with_prefix_is_preserved():
    tx_hash = "0x" + "b" * 64

    assert _normalize_rotation_tx_hash(tx_hash) == tx_hash


def test_invalid_transaction_hash_is_rejected():
    with pytest.raises(HTTPException) as exc:
        _normalize_rotation_tx_hash("0x1234")

    assert exc.value.status_code == 422


def test_rotation_payload_must_match_saved_payload():
    saved = {
        "expected_epoch": 2,
        "assets": [
            {
                "asset_id": "asset-1",
                "shares": [],
            }
        ],
    }

    assert _rotation_payload_matches(saved, saved)

    changed = {
        **saved,
        "expected_epoch": 3,
    }

    assert not _rotation_payload_matches(saved, changed)
