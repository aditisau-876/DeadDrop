
from __future__ import annotations

from typing import Any


MAX_POLICY_DEPTH = 12
MAX_POLICY_NODES = 100
MAX_CHILDREN = 20


def validate_policy_tree(
    node: dict[str, Any],
    allowed_trustees: set[str],
) -> None:
    """Validate a policy tree and ensure it references assigned trustees."""

    if not isinstance(node, dict):
        raise ValueError("Policy node must be an object.")

    node_count = 0
    seen_trustees: set[str] = set()

    def walk(current: dict[str, Any], depth: int) -> None:
        nonlocal node_count

        node_count += 1

        if node_count > MAX_POLICY_NODES:
            raise ValueError("Policy tree contains too many nodes.")

        if depth > MAX_POLICY_DEPTH:
            raise ValueError("Policy tree is too deeply nested.")

        if not isinstance(current, dict):
            raise ValueError("Every policy node must be an object.")

        node_type = current.get("type")

        if node_type == "LEAF":
            trustee_id = current.get("trustee_id")

            if not isinstance(trustee_id, str) or not trustee_id:
                raise ValueError("LEAF nodes require a trustee_id.")

            if trustee_id not in allowed_trustees:
                raise ValueError(
                    f"Trustee {trustee_id} is not assigned to this policy."
                )

            if trustee_id in seen_trustees:
                raise ValueError(
                    f"Trustee {trustee_id} appears more than once."
                )

            seen_trustees.add(trustee_id)
            return

        if node_type not in {"AND", "OR", "THRESHOLD"}:
            raise ValueError(f"Unsupported policy node type: {node_type}")

        children = current.get("children")

        if not isinstance(children, list) or not children:
            raise ValueError(f"{node_type} requires a non-empty children list.")

        if len(children) > MAX_CHILDREN:
            raise ValueError("A policy node has too many children.")

        if node_type == "THRESHOLD":
            threshold = current.get("threshold")

            if (
                not isinstance(threshold, int)
                or isinstance(threshold, bool)
                or threshold < 1
                or threshold > len(children)
            ):
                raise ValueError(
                    "THRESHOLD must be between 1 and the number of children."
                )

        for child in children:
            walk(child, depth + 1)

    walk(node, 1)


def evaluate(
    node: dict[str, Any],
    approved_trustees: set[str],
) -> bool:
    """Evaluate a validated policy tree against approved trustees."""

    if not isinstance(node, dict):
        raise ValueError("Invalid policy node.")

    node_type = node.get("type")

    if node_type == "LEAF":
        trustee_id = node.get("trustee_id")

        if not isinstance(trustee_id, str):
            raise ValueError("Invalid LEAF node.")

        return trustee_id in approved_trustees

    children = node.get("children")

    if not isinstance(children, list) or not children:
        raise ValueError("Invalid policy children.")

    results = [evaluate(child, approved_trustees) for child in children]

    if node_type == "AND":
        return all(results)

    if node_type == "OR":
        return any(results)

    if node_type == "THRESHOLD":
        threshold = node.get("threshold")

        if (
            not isinstance(threshold, int)
            or isinstance(threshold, bool)
            or threshold < 1
            or threshold > len(results)
        ):
            raise ValueError("Invalid threshold.")

        return sum(results) >= threshold

    raise ValueError(f"Unsupported policy node type: {node_type}")
