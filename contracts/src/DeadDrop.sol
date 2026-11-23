// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title DeadDrop
/// @notice On-chain governance registry and recovery authorization state machine.
/// @dev The contract stores policy hashes, share commitments and authorization
///      metadata only. It never stores plaintext secrets or encrypted shares.
contract DeadDrop {
    enum RecoveryState { None, Requested, Executed, Cancelled }

    struct Policy {
        bytes32 policyHash;
        uint64 version;
        uint64 epoch;
        uint64 timelockDuration;
        uint16 quorum;
        bool active;
    }

    struct Recovery {
        bytes32 policyKey;
        bytes32 incidentHash;
        address requester;
        uint64 policyVersion;
        uint64 policyEpoch;
        uint64 requestedAt;
        uint64 executeAfter;
        uint64 expiresAt;
        uint16 approvals;
        RecoveryState state;
    }

    address public owner;
    mapping(bytes32 => Policy) public policies;
    mapping(bytes32 => Recovery) public recoveries;
    mapping(bytes32 => mapping(address => bool)) public trustees;
    mapping(bytes32 => mapping(address => bool)) public approved;
    mapping(bytes32 => bytes32[]) private commitments;
    mapping(bytes32 => uint256) public trusteeCount;

    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant APPROVAL_TYPEHASH = keccak256(
        "RecoveryApproval(string recoveryId,string policyId,string trusteeId,string incidentHash,uint256 policyVersion,uint256 policyEpoch)"
    );
    bytes32 private constant NAME_HASH = keccak256("DeadDrop");
    bytes32 private constant VERSION_HASH = keccak256("1");

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event PolicyRegistered(bytes32 indexed policyKey, bytes32 policyHash, uint64 version, uint64 epoch);
    event PolicyStatusChanged(bytes32 indexed policyKey, bool active);
    event ShareCommitmentsUpdated(bytes32 indexed policyKey, uint64 epoch);
    event RecoveryRequested(bytes32 indexed recoveryKey, bytes32 indexed policyKey, address indexed requester, uint64 executeAfter, uint64 expiresAt);
    event ApprovalSubmitted(bytes32 indexed recoveryKey, address indexed trustee, uint16 approvals);
    event RecoveryExecuted(bytes32 indexed recoveryKey, bytes32 artifactHash);
    event RecoveryCancelled(bytes32 indexed recoveryKey, address indexed cancelledBy);

    modifier onlyOwner() {
        require(msg.sender == owner, "OWNER_ONLY");
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ZERO_OWNER");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function registerPolicy(
        string calldata policyId,
        bytes32 policyHash,
        address[] calldata trusteeWallets,
        bytes32[] calldata shareCommitments,
        uint16 quorum,
        uint64 timelockDuration
    ) external onlyOwner {
        bytes32 key = keccak256(bytes(policyId));
        require(key != bytes32(0), "EMPTY_POLICY_ID");
        require(policies[key].policyHash == bytes32(0), "POLICY_EXISTS");
        require(policyHash != bytes32(0), "EMPTY_POLICY_HASH");
        require(trusteeWallets.length > 0, "NO_TRUSTEES");
        require(trusteeWallets.length == shareCommitments.length, "LENGTH_MISMATCH");
        require(quorum > 0 && quorum <= trusteeWallets.length, "INVALID_QUORUM");

        for (uint256 i = 0; i < trusteeWallets.length; i++) {
            address wallet = trusteeWallets[i];
            require(wallet != address(0), "ZERO_TRUSTEE");
            require(!trustees[key][wallet], "DUPLICATE_TRUSTEE");
            require(shareCommitments[i] != bytes32(0), "EMPTY_COMMITMENT");
            trustees[key][wallet] = true;
            commitments[key].push(shareCommitments[i]);
        }

        trusteeCount[key] = trusteeWallets.length;
        policies[key] = Policy({
            policyHash: policyHash,
            version: 1,
            epoch: 1,
            timelockDuration: timelockDuration,
            quorum: quorum,
            active: true
        });
        emit PolicyRegistered(key, policyHash, 1, 1);
    }

    function setPolicyActive(string calldata policyId, bool active) external onlyOwner {
        bytes32 key = keccak256(bytes(policyId));
        require(policies[key].policyHash != bytes32(0), "POLICY_NOT_FOUND");
        policies[key].active = active;
        policies[key].version += 1;
        emit PolicyStatusChanged(key, active);
    }

    /// @notice Replace commitments after a client-side share rotation.
    /// @dev Incrementing the epoch does not itself perform proactive refresh.
    function updateShareCommitments(
        string calldata policyId,
        uint64 newEpoch,
        bytes32[] calldata newCommitments
    ) external onlyOwner {
        bytes32 key = keccak256(bytes(policyId));
        Policy storage policy = policies[key];
        require(policy.active, "POLICY_INACTIVE");
        require(newEpoch > policy.epoch, "EPOCH_NOT_INCREASING");
        require(newCommitments.length == trusteeCount[key], "COMMITMENT_COUNT_MISMATCH");
        for (uint256 i = 0; i < newCommitments.length; i++) {
            require(newCommitments[i] != bytes32(0), "EMPTY_COMMITMENT");
        }
        delete commitments[key];
        for (uint256 i = 0; i < newCommitments.length; i++) {
            commitments[key].push(newCommitments[i]);
        }
        policy.epoch = newEpoch;
        policy.version += 1;
        emit ShareCommitmentsUpdated(key, newEpoch);
    }

    function requestRecovery(
        string calldata recoveryId,
        string calldata policyId,
        bytes32 incidentHash,
        uint64 expiresAt
    ) external {
        bytes32 recoveryKey = keccak256(bytes(recoveryId));
        bytes32 policyKey = keccak256(bytes(policyId));
        Recovery storage recovery = recoveries[recoveryKey];
        Policy storage policy = policies[policyKey];
        require(bytes(recoveryId).length > 0, "EMPTY_RECOVERY_ID");
        require(bytes(policyId).length > 0, "EMPTY_POLICY_ID");
        require(policy.active, "POLICY_INACTIVE");
        require(recoveryKey != bytes32(0), "EMPTY_RECOVERY_ID");
        require(recoveries[recoveryKey].state == RecoveryState.None, "RECOVERY_EXISTS");
        require(incidentHash != bytes32(0), "EMPTY_INCIDENT_HASH");
        require(expiresAt > block.timestamp + policy.timelockDuration, "INVALID_EXPIRY");

        uint64 executeAfter = uint64(block.timestamp) + policy.timelockDuration;
        recoveries[recoveryKey] = Recovery({
            policyKey: policyKey,
            incidentHash: incidentHash,
            requester: msg.sender,
            policyVersion: policy.version,
            policyEpoch: policy.epoch,
            requestedAt: uint64(block.timestamp),
            executeAfter: executeAfter,
            expiresAt: expiresAt,
            approvals: 0,
            state: RecoveryState.Requested
        });
        emit RecoveryRequested(recoveryKey, policyKey, msg.sender, executeAfter, expiresAt);
    }

    /// @notice Submit an EIP-712 approval. Anyone may relay the signature;
    ///         the recovered signer must be an assigned trustee.
    function submitApproval(
        string calldata recoveryId,
        string calldata policyId,
        string calldata trusteeId,
        string calldata incidentHash,
        bytes calldata signature
    ) external {
        bytes32 recoveryKey = keccak256(bytes(recoveryId));
        bytes32 policyKey = keccak256(bytes(policyId));
        Recovery storage recovery = recoveries[recoveryKey];
        Policy storage policy = policies[policyKey];
        require(recovery.state == RecoveryState.Requested, "NOT_PENDING");
        require(recovery.policyKey == policyKey, "POLICY_MISMATCH");
        require(block.timestamp < recovery.expiresAt, "RECOVERY_EXPIRED");
        require(policy.active, "POLICY_INACTIVE");
        require(policy.version == recovery.policyVersion && policy.epoch == recovery.policyEpoch, "POLICY_CHANGED");
        require(keccak256(bytes(incidentHash)) == recovery.incidentHash, "INCIDENT_MISMATCH");

        bytes32 digest = _approvalDigest(
            recoveryId,
            policyId,
            trusteeId,
            incidentHash,
            recovery.policyVersion,
            recovery.policyEpoch
        );
        address signer = _recover(digest, signature);
        require(signer != address(0) && trustees[policyKey][signer], "NOT_A_TRUSTEE");
        require(!approved[recoveryKey][signer], "ALREADY_APPROVED");

        approved[recoveryKey][signer] = true;
        recovery.approvals += 1;
        emit ApprovalSubmitted(recoveryKey, signer, recovery.approvals);
    }

    function cancelRecovery(string calldata recoveryId) external {
        bytes32 key = keccak256(bytes(recoveryId));
        Recovery storage recovery = recoveries[key];
        require(recovery.state == RecoveryState.Requested, "NOT_PENDING");
        require(msg.sender == recovery.requester || msg.sender == owner, "NOT_AUTHORIZED");
        recovery.state = RecoveryState.Cancelled;
        emit RecoveryCancelled(key, msg.sender);
    }

    function executeRecovery(string calldata recoveryId, bytes32 artifactHash) external {
        bytes32 key = keccak256(bytes(recoveryId));
        Recovery storage recovery = recoveries[key];
        Policy storage policy = policies[recovery.policyKey];
        require(recovery.state == RecoveryState.Requested, "NOT_PENDING");
        require(block.timestamp >= recovery.executeAfter, "TIMELOCK_ACTIVE");
        require(block.timestamp < recovery.expiresAt, "RECOVERY_EXPIRED");
        require(policy.active, "POLICY_INACTIVE");
        require(policy.version == recovery.policyVersion && policy.epoch == recovery.policyEpoch, "POLICY_CHANGED");
        require(recovery.approvals >= policy.quorum, "QUORUM_NOT_MET");
        require(artifactHash != bytes32(0), "EMPTY_ARTIFACT_HASH");
        recovery.state = RecoveryState.Executed;
        emit RecoveryExecuted(key, artifactHash);
    }

    function getCommitments(string calldata policyId) external view returns (bytes32[] memory) {
        return commitments[keccak256(bytes(policyId))];
    }

    function _approvalDigest(
        string calldata recoveryId,
        string calldata policyId,
        string calldata trusteeId,
        string calldata incidentHash,
        uint256 policyVersion,
        uint256 policyEpoch
    ) private view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(
            APPROVAL_TYPEHASH,
            keccak256(bytes(recoveryId)),
            keccak256(bytes(policyId)),
            keccak256(bytes(trusteeId)),
            keccak256(bytes(incidentHash)),
            policyVersion,
            policyEpoch
        ));
        bytes32 domainSeparator = keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            NAME_HASH,
            VERSION_HASH,
            block.chainid,
            address(this)
        ));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address) {
        require(signature.length == 65, "BAD_SIGNATURE_LENGTH");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        // Reject malleable signatures (s must be in lower half-order).
        if (uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0) return address(0);
        return ecrecover(digest, v, r, s);
    }
}
