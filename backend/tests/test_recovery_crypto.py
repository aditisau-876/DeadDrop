from app.crypto.recovery import (
    prepare_recovery_material,
)
from app.crypto.secret_sharing import (
    SecretShare,
    reconstruct_secret,
)
from app.crypto.share_encryption import (
    decrypt_share,
    generate_trustee_key_pair,
)


def test_complete_recovery_crypto_flow():

    trustees = []

    key_pairs = {}

    for index in range(5):
        trustee_id = f"trustee-{index + 1}"

        key_pair = generate_trustee_key_pair()

        key_pairs[trustee_id] = key_pair

        trustees.append(
            {
                "id": trustee_id,
                "public_key": key_pair.public_key,
            }
        )

    secret = (
    b"DeadDrop confidential payload!"
)

    result = prepare_recovery_material(
        secret,
        threshold=3,
        trustees=trustees,
        policy_id="policy-1",
        epoch=1,
    )

    assert len(result.shares) == 5

    decrypted_shares = []

    for prepared_share in result.shares[:3]:

        private_key = key_pairs[
            prepared_share.trustee_id
        ].private_key

        share_value = decrypt_share(
            prepared_share.encrypted_share,
            trustee_private_key=private_key,
        )

        decrypted_shares.append(
            SecretShare(
                index=prepared_share.share_index,
                value=share_value,
            )
        )

    recovered = reconstruct_secret(
        decrypted_shares,
        threshold=3,
    )

    assert recovered == secret