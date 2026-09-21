
from app.crypto.commitments import (
    create_share_commitment,
)
from app.crypto.verification import (
    verify_share_commitment,
)


def test_commitment_matches():

    share = "example-share"

    commitment = create_share_commitment(
        share,
        policy_id="policy-1",
        trustee_id="trustee-1",
        epoch=1,
    )

    assert verify_share_commitment(
        share=share,
        expected_commitment=commitment,
        policy_id="policy-1",
        trustee_id="trustee-1",
        epoch=1,
    )


def test_wrong_share_fails():

    commitment = create_share_commitment(
        "correct-share",
        policy_id="policy-1",
        trustee_id="trustee-1",
        epoch=1,
    )

    assert not verify_share_commitment(
        share="wrong-share",
        expected_commitment=commitment,
        policy_id="policy-1",
        trustee_id="trustee-1",
        epoch=1,
    )


def test_wrong_epoch_fails():

    commitment = create_share_commitment(
        "correct-share",
        policy_id="policy-1",
        trustee_id="trustee-1",
        epoch=1,
    )

    assert not verify_share_commitment(
        share="correct-share",
        expected_commitment=commitment,
        policy_id="policy-1",
        trustee_id="trustee-1",
        epoch=2,
    )