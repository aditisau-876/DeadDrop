# Core entities
Policy: id, hash, version, epoch, access tree, trustees, timelock, expiry, active.
Trustee: id, wallet, role, encryption public key, active, last verified epoch.
ShareArtifact: policy, trustee, epoch, encrypted share, commitment, proof reference.
RecoveryRequest: request id, policy version, incident hash, reason hash, nonce, expiry, state.
AuditEvent: event id, request id, type, actor, tx hash, artifact hash, timestamp.
