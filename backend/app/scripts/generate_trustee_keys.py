from __future__ import annotations

import getpass

from app.crypto.share_encryption import generate_trustee_key_pair


def main() -> None:
    pair = generate_trustee_key_pair()
    print("\nDeadDrop trustee X25519 key pair generated.\n")
    print("PUBLIC KEY (paste into the trustee record in Administration):")
    print(pair.public_key)
    print("\nPRIVATE KEY (give only to the trustee; never upload it or store it in DeadDrop):")
    print(pair.private_key)
    print("\nThe private key is shown once in this terminal. Store it in a secure password manager or offline secret store.")
    getpass.getpass("Press Enter to close this output...")


if __name__ == "__main__":
    main()
