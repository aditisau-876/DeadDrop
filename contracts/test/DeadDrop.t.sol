// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DeadDrop} from "../src/DeadDrop.sol";

interface VmTest {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address sender) external;
    function warp(uint256 timestamp) external;
}

/// @notice Dependency-free Foundry tests for the current flat-quorum contract.
contract DeadDropTest {
    VmTest private constant vm =
        VmTest(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 private constant TRUSTEE_KEY = 0xA11CE;
    DeadDrop private deadDrop;
    address private trustee;

    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant APPROVAL_TYPEHASH = keccak256(
        "RecoveryApproval(string recoveryId,string policyId,string trusteeId,string incidentHash,uint256 policyVersion,uint256 policyEpoch)"
    );

    function setUp() public {
        deadDrop = new DeadDrop();
        trustee = vm.addr(TRUSTEE_KEY);
    }

    function testOwnerCanRegisterPolicy() public {
        address[] memory wallets = new address[](1);
        wallets[0] = trustee;
        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = keccak256("share-commitment-1");

        deadDrop.registerPolicy(
            "policy-1",
            keccak256("policy-tree-hash"),
            wallets,
            commitments,
            1,
            0
        );

        bytes32[] memory actual = deadDrop.getCommitments("policy-1");
        require(actual.length == 1, "COMMITMENT_NOT_STORED");
        require(actual[0] == commitments[0], "COMMITMENT_MISMATCH");
    }

    function testNonOwnerCannotRegisterPolicy() public {
        address[] memory wallets = new address[](1);
        wallets[0] = trustee;
        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = keccak256("commitment");

        vm.prank(trustee);
        (bool success,) = address(deadDrop).call(
            abi.encodeCall(
                deadDrop.registerPolicy,
                ("policy-1", keccak256("policy"), wallets, commitments, 1, 0)
            )
        );
        require(!success, "NON_OWNER_REGISTERED_POLICY");
    }

    function testTrusteeApprovalAndTimelockedExecution() public {
        address[] memory wallets = new address[](1);
        wallets[0] = trustee;
        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = keccak256("commitment");

        deadDrop.registerPolicy(
            "policy-1",
            keccak256("policy-tree-hash"),
            wallets,
            commitments,
            1,
            60
        );

        bytes32 incident = keccak256(bytes("incident-1"));
        deadDrop.requestRecovery(
            "recovery-1",
            "policy-1",
            incident,
            uint64(block.timestamp + 1 days)
        );

        bytes32 digest = _approvalDigest(
            "recovery-1", "policy-1", "trustee-1", "incident-1", 1, 1
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(TRUSTEE_KEY, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        deadDrop.submitApproval(
            "recovery-1",
            "policy-1",
            "trustee-1",
            "incident-1",
            signature
        );

        vm.warp(block.timestamp + 61);
        deadDrop.executeRecovery("recovery-1", keccak256("recovered-artifact"));
    }

    function testCannotExecuteBeforeTimelock() public {
        address[] memory wallets = new address[](1);
        wallets[0] = trustee;
        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = keccak256("commitment");
        deadDrop.registerPolicy(
            "policy-1", keccak256("policy"), wallets, commitments, 1, 3600
        );
        deadDrop.requestRecovery(
            "recovery-1",
            "policy-1",
            keccak256(bytes("incident-1")),
            uint64(block.timestamp + 2 days)
        );

        (bool success,) = address(deadDrop).call(
            abi.encodeCall(
                deadDrop.executeRecovery,
                ("recovery-1", keccak256("artifact"))
            )
        );
        require(!success, "EXECUTED_BEFORE_TIMELOCK");
    }

    function _approvalDigest(
        string memory recoveryId,
        string memory policyId,
        string memory trusteeId,
        string memory incidentHash,
        uint256 policyVersion,
        uint256 policyEpoch
    ) private view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                APPROVAL_TYPEHASH,
                keccak256(bytes(recoveryId)),
                keccak256(bytes(policyId)),
                keccak256(bytes(trusteeId)),
                keccak256(bytes(incidentHash)),
                policyVersion,
                policyEpoch
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
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
