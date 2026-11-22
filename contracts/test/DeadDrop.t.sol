
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DeadDrop} from "../src/DeadDrop.sol";

interface VmSecurity {
    function addr(uint256 privateKey) external returns (address);

    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);

    function prank(address sender) external;

    function warp(uint256 timestamp) external;
}

contract DeadDropSecurityTest {
    VmSecurity private constant vm =
        VmSecurity(
            address(uint160(uint256(keccak256("hevm cheat code"))))
        );

    uint256 private constant TRUSTEE_KEY = 0xA11CE;
    uint256 private constant ATTACKER_KEY = 0xB0B;

    uint256 private constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 private constant APPROVAL_TYPEHASH = keccak256(
        "RecoveryApproval(string recoveryId,string policyId,string trusteeId,string incidentHash,uint256 policyVersion,uint256 policyEpoch)"
    );

    DeadDrop private deadDrop;
    address private trustee;

    function setUp() public {
        deadDrop = new DeadDrop();
        trustee = vm.addr(TRUSTEE_KEY);
    }

    function _registerAndRequest(
        uint64 timelock,
        uint64 expiryOffset
    ) internal {
        address[] memory wallets = new address[](1);
        wallets[0] = trustee;

        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = keccak256("security-test-commitment");

        deadDrop.registerPolicy(
            "security-policy",
            keccak256("security-policy-hash"),
            wallets,
            commitments,
            1,
            timelock
        );

        deadDrop.requestRecovery(
            "security-recovery",
            "security-policy",
            keccak256(bytes("security-incident")),
            uint64(block.timestamp + expiryOffset)
        );
    }

    function _digest() internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                APPROVAL_TYPEHASH,
                keccak256(bytes("security-recovery")),
                keccak256(bytes("security-policy")),
                keccak256(bytes("trustee-1")),
                keccak256(bytes("security-incident")),
                uint256(1),
                uint256(1)
            )
        );

        bytes32 domainSeparator = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256("DeadDrop"),
                keccak256("1"),
                block.chainid,
                address(deadDrop)
            )
        );

        return keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );
    }

    function _sign(uint256 privateKey)
        internal
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            privateKey,
            _digest()
        );

        return abi.encodePacked(r, s, v);
    }

    function _approve(bytes memory signature) internal {
        deadDrop.submitApproval(
            "security-recovery",
            "security-policy",
            "trustee-1",
            "security-incident",
            signature
        );
    }

    function testRejectsUnassignedTrusteeSignature() public {
        _registerAndRequest(0, 1 days);

        bytes memory signature = _sign(ATTACKER_KEY);

        (bool success,) = address(deadDrop).call(
            abi.encodeCall(
                deadDrop.submitApproval,
                (
                    "security-recovery",
                    "security-policy",
                    "trustee-1",
                    "security-incident",
                    signature
                )
            )
        );

        require(!success, "UNASSIGNED_TRUSTEE_APPROVED");
    }

    function testRejectsDuplicateApproval() public {
        _registerAndRequest(0, 1 days);

        bytes memory signature = _sign(TRUSTEE_KEY);

        _approve(signature);

        (bool success,) = address(deadDrop).call(
            abi.encodeCall(
                deadDrop.submitApproval,
                (
                    "security-recovery",
                    "security-policy",
                    "trustee-1",
                    "security-incident",
                    signature
                )
            )
        );

        require(!success, "DUPLICATE_APPROVAL_ACCEPTED");
    }

    function testRejectsExpiredApproval() public {
        _registerAndRequest(0, 100);

        vm.warp(block.timestamp + 101);

        bytes memory signature = _sign(TRUSTEE_KEY);

        (bool success,) = address(deadDrop).call(
            abi.encodeCall(
                deadDrop.submitApproval,
                (
                    "security-recovery",
                    "security-policy",
                    "trustee-1",
                    "security-incident",
                    signature
                )
            )
        );

        require(!success, "EXPIRED_APPROVAL_ACCEPTED");
    }

    function testPolicyDeactivationInvalidatesApproval() public {
        _registerAndRequest(0, 1 days);

        deadDrop.setPolicyActive(
            "security-policy",
            false
        );

        bytes memory signature = _sign(TRUSTEE_KEY);

        (bool success,) = address(deadDrop).call(
            abi.encodeCall(
                deadDrop.submitApproval,
                (
                    "security-recovery",
                    "security-policy",
                    "trustee-1",
                    "security-incident",
                    signature
                )
            )
        );

        require(!success, "APPROVAL_ACCEPTED_FOR_INACTIVE_POLICY");
    }

    function testRejectsUnauthorizedCancellation() public {
        _registerAndRequest(0, 1 days);

        address attacker = vm.addr(ATTACKER_KEY);

        vm.prank(attacker);

        (bool success,) = address(deadDrop).call(
            abi.encodeCall(
                deadDrop.cancelRecovery,
                ("security-recovery")
            )
        );

        require(!success, "UNAUTHORIZED_CANCELLATION_ACCEPTED");
    }

    function testRejectsMalleableHighSSignature() public {
        _registerAndRequest(0, 1 days);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            TRUSTEE_KEY,
            _digest()
        );

        bytes32 highS = bytes32(
            SECP256K1_N - uint256(s)
        );

        uint8 alternateV = v == 27 ? 28 : 27;

        bytes memory signature = abi.encodePacked(
            r,
            highS,
            alternateV
        );

        (bool success,) = address(deadDrop).call(
            abi.encodeCall(
                deadDrop.submitApproval,
                (
                    "security-recovery",
                    "security-policy",
                    "trustee-1",
                    "security-incident",
                    signature
                )
            )
        );

        require(!success, "MALLEABLE_SIGNATURE_ACCEPTED");
    }

    function testRejectsExecutionAfterExpiry() public {
        _registerAndRequest(0, 100);

        _approve(_sign(TRUSTEE_KEY));

        vm.warp(block.timestamp + 101);

        (bool success,) = address(deadDrop).call(
            abi.encodeCall(
                deadDrop.executeRecovery,
                (
                    "security-recovery",
                    keccak256("artifact")
                )
            )
        );

        require(!success, "EXPIRED_RECOVERY_EXECUTED");
    }

    function testRejectsZeroArtifactHash() public {
        _registerAndRequest(0, 1 days);

        _approve(_sign(TRUSTEE_KEY));

        (bool success,) = address(deadDrop).call(
            abi.encodeCall(
                deadDrop.executeRecovery,
                (
                    "security-recovery",
                    bytes32(0)
                )
            )
        );

        require(!success, "ZERO_ARTIFACT_HASH_ACCEPTED");
    }

    function testRejectsDuplicateTrusteeWallets() public {
        address[] memory wallets = new address[](2);
        wallets[0] = trustee;
        wallets[1] = trustee;

        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = keccak256("commitment-1");
        commitments[1] = keccak256("commitment-2");

        (bool success,) = address(deadDrop).call(
            abi.encodeCall(
                deadDrop.registerPolicy,
                (
                    "duplicate-policy",
                    keccak256("policy-hash"),
                    wallets,
                    commitments,
                    1,
                    0
                )
            )
        );

        require(!success, "DUPLICATE_TRUSTEE_ACCEPTED");
    }

    function testRecoveryGetterReturnsStoredState() public {
        _registerAndRequest(0, 1 days);

        bytes32 key = keccak256(
            bytes("security-recovery")
        );

        (
            bytes32 policyKey,
            bytes32 incidentHash,
            address requester,
            uint64 policyVersion,
            uint64 policyEpoch,
            uint64 requestedAt,
            uint64 executeAfter,
            uint64 expiresAt,
            uint16 approvals,
            DeadDrop.RecoveryState state
        ) = deadDrop.recoveries(key);

        require(
            policyKey == keccak256(bytes("security-policy")),
            "WRONG_POLICY_KEY"
        );

        require(
            incidentHash == keccak256(bytes("security-incident")),
            "WRONG_INCIDENT"
        );

        require(requester == address(this), "WRONG_REQUESTER");
        require(policyVersion == 1, "WRONG_VERSION");
        require(policyEpoch == 1, "WRONG_EPOCH");
        require(requestedAt > 0, "MISSING_REQUEST_TIME");
        require(executeAfter == requestedAt, "WRONG_EXECUTION_TIME");
        require(expiresAt > requestedAt, "WRONG_EXPIRY");
        require(approvals == 0, "UNEXPECTED_APPROVALS");
        require(
            state == DeadDrop.RecoveryState.Requested,
            "WRONG_RECOVERY_STATE"
        );
    }
}
