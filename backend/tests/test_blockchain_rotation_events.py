
from app.blockchain.indexer import (
    EVENT_ABI,
    INDEXED_EVENT_NAMES,
    ROTATION_EVENTS,
)


def test_rotation_events_are_in_the_indexer_abi():
    events = {
        item["name"]: item
        for item in EVENT_ABI
        if item.get("type") == "event"
    }

    assert ROTATION_EVENTS <= set(events)
    assert ROTATION_EVENTS <= set(INDEXED_EVENT_NAMES)


def test_policy_epoch_rotation_event_has_expected_fields():
    event = next(
        item for item in EVENT_ABI
        if item.get("name") == "PolicyShareEpochRotated"
    )

    assert [
        (field["name"], field["type"], field["indexed"])
        for field in event["inputs"]
    ] == [
        ("policyKey", "bytes32", True),
        ("previousEpoch", "uint64", False),
        ("newEpoch", "uint64", False),
        ("assetCount", "uint256", False),
    ]


def test_asset_commitment_rotation_event_has_expected_fields():
    event = next(
        item for item in EVENT_ABI
        if item.get("name") == "AssetShareCommitmentsRotated"
    )

    assert [
        (field["name"], field["type"], field["indexed"])
        for field in event["inputs"]
    ] == [
        ("assetKey", "bytes32", True),
        ("policyKey", "bytes32", True),
        ("previousEpoch", "uint64", False),
        ("newEpoch", "uint64", False),
    ]
