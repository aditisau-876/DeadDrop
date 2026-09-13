from __future__ import annotations

import hashlib


def create_share_commitment(
    share: str,
    *,
    policy_id: str,
    trustee_id: str,
    epoch: int,
) -> str:
    """
    Create a deterministic commitment to a trustee share.

    Context binding prevents the same share value from being
    interpreted as belonging to a different policy/trustee/epoch.
    """
    if not share:
        raise ValueError("Share cannot be empty.")

    if not policy_id:
        raise ValueError("Policy ID cannot be empty.")

    if not trustee_id:
        raise ValueError("Trustee ID cannot be empty.")

    if epoch < 0:
        raise ValueError("Epoch cannot be negative.")

    material = (
        f"deaddrop:v1|"
        f"policy:{policy_id}|"
        f"trustee:{trustee_id}|"
        f"epoch:{epoch}|"
        f"share:{share}"
    ).encode("utf-8")

    return hashlib.sha256(material).hexdigest()