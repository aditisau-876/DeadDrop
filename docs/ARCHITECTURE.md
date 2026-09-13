# Architecture
Recovery Client: encrypts payload, evaluates access tree, verifies shares, reconstructs locally.
Blockchain: immutable policy anchor, commitments, epoch, approval/recovery state and audit evidence.
Backend: coordination and encrypted artifacts/metadata only; never reconstructs plaintext.
Trustees: approve exact recovery requests and provide encrypted share artifacts.
