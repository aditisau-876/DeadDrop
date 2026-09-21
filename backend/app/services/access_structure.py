from __future__ import annotations

from typing import Any


class PolicyEvaluationError(ValueError):
    """Raised when an access structure is invalid."""


def evaluate(
    node: dict[str, Any],
    approved_trustees: set[str],
) -> bool:
    """
    Evaluate a DeadDrop access-structure tree.

    Supported node types:

    leaf
        A single trustee.

    THRESHOLD
        At least `threshold` children must be satisfied.

    AND
        Every child must be satisfied.

    OR
        At least one child must be satisfied.

    Example:

        {
            "type": "THRESHOLD",
            "threshold": 2,
            "children": [
                {"type": "leaf", "trustee_id": "T1"},
                {"type": "leaf", "trustee_id": "T2"},
                {"type": "leaf", "trustee_id": "T3"},
            ],
        }

    With:

        {"T1", "T3"}

    the policy is satisfied.
    """

    if not isinstance(node, dict):
        raise PolicyEvaluationError(
            "Access-structure node must be an object."
        )

    node_type = node.get("type")

    if not isinstance(node_type, str):
        raise PolicyEvaluationError(
            "Access-structure node is missing 'type'."
        )

    node_type = node_type.upper()

    # ---------------------------------------------------------
    # LEAF
    # ---------------------------------------------------------

    if node_type == "LEAF":
        trustee_id = node.get("trustee_id")

        if not isinstance(trustee_id, str) or not trustee_id:
            raise PolicyEvaluationError(
                "Leaf node requires a trustee_id."
            )

        return trustee_id in approved_trustees

    # ---------------------------------------------------------
    # Composite nodes
    # ---------------------------------------------------------

    children = node.get("children")

    if not isinstance(children, list) or not children:
        raise PolicyEvaluationError(
            f"{node_type} node requires a non-empty children list."
        )

    # Recursively evaluate every child.

    results = [
        evaluate(child, approved_trustees)
        for child in children
    ]

    # ---------------------------------------------------------
    # AND
    # ---------------------------------------------------------

    if node_type == "AND":
        return all(results)

    # ---------------------------------------------------------
    # OR
    # ---------------------------------------------------------

    if node_type == "OR":
        return any(results)

    # ---------------------------------------------------------
    # THRESHOLD
    # ---------------------------------------------------------

    if node_type == "THRESHOLD":
        threshold = node.get("threshold")

        if not isinstance(threshold, int):
            raise PolicyEvaluationError(
                "THRESHOLD node requires an integer threshold."
            )

        if threshold < 1:
            raise PolicyEvaluationError(
                "Threshold must be at least 1."
            )

        if threshold > len(children):
            raise PolicyEvaluationError(
                "Threshold cannot exceed the number of children."
            )

        satisfied_children = sum(results)

        return satisfied_children >= threshold

    raise PolicyEvaluationError(
        f"Unsupported access-structure node type: {node_type}"
    )