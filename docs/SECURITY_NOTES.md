# Threat model
Rogue admin -> governance quorum + timelock.
Backend compromise -> no plaintext key/share material.
Replay -> request ID/nonce/expiry/chain binding.
Corrupted share -> commitment verification before interpolation.
Below-threshold collusion -> threshold assumption.
Mobile adversary -> true proactive refresh across epochs.
Endpoint compromise -> plaintext can be exposed after legitimate local decryption.
