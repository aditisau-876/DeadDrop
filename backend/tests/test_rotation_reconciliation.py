
from app.blockchain.rotation_reconciliation import (
    _epoch_mismatch,
)


def test_matching_epochs_have_no_mismatch():
    result = _epoch_mismatch(
        entity_type="policy",
        entity_id="policy-1",
        database_epoch=3,
        onchain_epoch=3,
    )

    assert result is None


def test_policy_epoch_mismatch_is_reported():
    result = _epoch_mismatch(
        entity_type="policy",
        entity_id="policy-1",
        database_epoch=2,
        onchain_epoch=3,
    )

    assert result == {
        "type": "POLICY_EPOCH_MISMATCH",
        "entity_id": "policy-1",
        "database_epoch": 2,
        "onchain_epoch": 3,
    }


def test_asset_epoch_mismatch_is_reported():
    result = _epoch_mismatch(
        entity_type="asset",
        entity_id="asset-1",
        database_epoch=1,
        onchain_epoch=2,
    )

    assert result == {
        "type": "ASSET_EPOCH_MISMATCH",
        "entity_id": "asset-1",
        "database_epoch": 1,
        "onchain_epoch": 2,
    }


def test_epoch_values_are_compared_as_integers():
    result = _epoch_mismatch(
        entity_type="asset",
        entity_id="asset-1",
        database_epoch="4",
        onchain_epoch=4,
    )

    assert result is None
