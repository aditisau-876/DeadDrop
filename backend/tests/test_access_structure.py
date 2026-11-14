
import pytest

from app.services.access_structure import (
    evaluate,
    validate_policy_tree,
)


def leaf(trustee_id: str) -> dict:
    return {
        "type": "LEAF",
        "trustee_id": trustee_id,
    }


def test_and_policy_requires_all_trustees():
    tree = {
        "type": "AND",
        "children": [
            leaf("trustee-a"),
            leaf("trustee-b"),
        ],
    }

    validate_policy_tree(tree, {"trustee-a", "trustee-b"})

    assert evaluate(tree, {"trustee-a", "trustee-b"}) is True
    assert evaluate(tree, {"trustee-a"}) is False


def test_or_policy_requires_one_trustee():
    tree = {
        "type": "OR",
        "children": [
            leaf("trustee-a"),
            leaf("trustee-b"),
        ],
    }

    validate_policy_tree(tree, {"trustee-a", "trustee-b"})

    assert evaluate(tree, {"trustee-a"}) is True
    assert evaluate(tree, set()) is False


def test_threshold_policy():
    tree = {
        "type": "THRESHOLD",
        "threshold": 2,
        "children": [
            leaf("trustee-a"),
            leaf("trustee-b"),
            leaf("trustee-c"),
        ],
    }

    validate_policy_tree(
        tree,
        {"trustee-a", "trustee-b", "trustee-c"},
    )

    assert evaluate(tree, {"trustee-a", "trustee-b"}) is True
    assert evaluate(tree, {"trustee-a"}) is False


def test_composable_policy():
    # (A AND B) OR (C AND at least 2 of D, E, F)
    tree = {
        "type": "OR",
        "children": [
            {
                "type": "AND",
                "children": [
                    leaf("A"),
                    leaf("B"),
                ],
            },
            {
                "type": "AND",
                "children": [
                    leaf("C"),
                    {
                        "type": "THRESHOLD",
                        "threshold": 2,
                        "children": [
                            leaf("D"),
                            leaf("E"),
                            leaf("F"),
                        ],
                    },
                ],
            },
        ],
    }

    validate_policy_tree(
        tree,
        {"A", "B", "C", "D", "E", "F"},
    )

    assert evaluate(tree, {"A", "B"}) is True
    assert evaluate(tree, {"C", "D", "E"}) is True
    assert evaluate(tree, {"C", "D"}) is False
    assert evaluate(tree, {"A"}) is False


def test_rejects_unassigned_trustee():
    tree = leaf("unknown-trustee")

    with pytest.raises(ValueError):
        validate_policy_tree(tree, {"trustee-a"})


def test_rejects_invalid_threshold():
    tree = {
        "type": "THRESHOLD",
        "threshold": 4,
        "children": [
            leaf("A"),
            leaf("B"),
        ],
    }

    with pytest.raises(ValueError):
        validate_policy_tree(tree, {"A", "B"})


def test_rejects_duplicate_trustee():
    tree = {
        "type": "AND",
        "children": [
            leaf("A"),
            leaf("A"),
        ],
    }

    with pytest.raises(ValueError):
        validate_policy_tree(tree, {"A"})
