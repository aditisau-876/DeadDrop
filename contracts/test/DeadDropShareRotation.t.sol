// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DeadDrop} from "../src/DeadDrop.sol";

interface VmRotation {
    function prank(address sender) external;
}

contract DeadDropShareRotationTest {
    VmRotation private constant vm = VmRotation(address(uint160(uint256(keccak256("hevm cheat code")))));

    DeadDrop private deadDrop;
    address private trusteeOne = address(0xA11CE);
    address private trusteeTwo = address(0xB0B);
    address private attacker = address(0xBAD);

    function setUp() public {
        deadDrop = new DeadDrop();
        address[] memory wallets = new address[](2);
        wallets[0] = trusteeOne;
        wallets[1] = trusteeTwo;

        deadDrop.registerPolicy("rotation-policy", keccak256("rotation-policy-hash"), wallets, 1, 0);

        _registerAsset("asset-one", keccak256("asset-one-hash"));
        _registerAsset("asset-two", keccak256("asset-two-hash"));
    }

    function _registerAsset(string memory assetId, bytes32 assetHash) internal {
        address[] memory wallets = new address[](2);
        wallets[0] = trusteeOne;
        wallets[1] = trusteeTwo;
        bytes32[] memory shares = new bytes32[](2);
        shares[0] = keccak256(abi.encodePacked(assetId, "-old-one"));
        shares[1] = keccak256(abi.encodePacked(assetId, "-old-two"));
        deadDrop.registerAssetCommitments(assetId, "rotation-policy", assetHash, 1, wallets, shares);
    }

    function _assetIds() internal pure returns (string[] memory ids) {
        ids = new string[](2);
        ids[0] = "asset-one";
        ids[1] = "asset-two";
    }

    function _trustees() internal view returns (address[] memory wallets) {
        wallets = new address[](2);
        wallets[0] = trusteeOne;
        wallets[1] = trusteeTwo;
    }

    function _newCommitments() internal pure returns (bytes32[][] memory values) {
        values = new bytes32[][](2);
        values[0] = new bytes32[](2);
        values[1] = new bytes32[](2);
        values[0][0] = keccak256("asset-one-new-one");
        values[0][1] = keccak256("asset-one-new-two");
        values[1][0] = keccak256("asset-two-new-one");
        values[1][1] = keccak256("asset-two-new-two");
    }

    function _rotate(string[] memory ids, address[] memory wallets, bytes32[][] memory values) internal {
        deadDrop.rotatePolicyAssetCommitments("rotation-policy", 1, 2, ids, wallets, values);
    }

    function testOwnerCanRotateEveryAssetAndTrusteeCommitment() public {
        bytes32 oldOne = deadDrop.getAssetCommitment("asset-one", trusteeOne);
        bytes32 oldTwo = deadDrop.getAssetCommitment("asset-two", trusteeTwo);

        _rotate(_assetIds(), _trustees(), _newCommitments());

        require(
            deadDrop.getAssetCommitment("asset-one", trusteeOne) == keccak256("asset-one-new-one"),
            "ASSET_ONE_NOT_ROTATED"
        );
        require(
            deadDrop.getAssetCommitment("asset-one", trusteeTwo) == keccak256("asset-one-new-two"),
            "ASSET_ONE_TRUSTEE_TWO_NOT_ROTATED"
        );
        require(
            deadDrop.getAssetCommitment("asset-two", trusteeOne) == keccak256("asset-two-new-one"),
            "ASSET_TWO_NOT_ROTATED"
        );
        require(
            deadDrop.getAssetCommitment("asset-two", trusteeTwo) == keccak256("asset-two-new-two"),
            "ASSET_TWO_TRUSTEE_TWO_NOT_ROTATED"
        );
        require(oldOne != deadDrop.getAssetCommitment("asset-one", trusteeOne), "OLD_COMMITMENT_RETAINED");
        require(oldTwo != deadDrop.getAssetCommitment("asset-two", trusteeTwo), "OLD_COMMITMENT_RETAINED");

        (,, uint64 policyEpoch,,,) = deadDrop.policies(keccak256(bytes("rotation-policy")));
        require(policyEpoch == 2, "POLICY_EPOCH_NOT_UPDATED");
        (,, uint64 firstEpoch,) = deadDrop.assets(keccak256(bytes("asset-one")));
        (,, uint64 secondEpoch,) = deadDrop.assets(keccak256(bytes("asset-two")));
        require(firstEpoch == 2 && secondEpoch == 2, "ASSET_EPOCHS_NOT_UPDATED");
        require(deadDrop.policyAssetCount(keccak256(bytes("rotation-policy"))) == 2, "ASSET_COUNT_CHANGED");
    }

    function testNonOwnerCannotRotate() public {
        vm.prank(attacker);
        (bool success,) = address(deadDrop)
            .call(
                abi.encodeCall(
                    deadDrop.rotatePolicyAssetCommitments,
                    ("rotation-policy", uint64(1), uint64(2), _assetIds(), _trustees(), _newCommitments())
                )
            );
        require(!success, "NON_OWNER_ROTATED_POLICY");
    }

    function testRotationRejectsStaleExpectedEpoch() public {
        (bool success,) = address(deadDrop)
            .call(
                abi.encodeCall(
                    deadDrop.rotatePolicyAssetCommitments,
                    ("rotation-policy", uint64(0), uint64(1), _assetIds(), _trustees(), _newCommitments())
                )
            );
        require(!success, "STALE_EPOCH_ACCEPTED");
    }

    function testRotationRejectsSkippedEpoch() public {
        (bool success,) = address(deadDrop)
            .call(
                abi.encodeCall(
                    deadDrop.rotatePolicyAssetCommitments,
                    ("rotation-policy", uint64(1), uint64(3), _assetIds(), _trustees(), _newCommitments())
                )
            );
        require(!success, "SKIPPED_EPOCH_ACCEPTED");
    }

    function testRotationRejectsIncompleteAssetSet() public {
        string[] memory ids = new string[](1);
        ids[0] = "asset-one";
        bytes32[][] memory values = new bytes32[][](1);
        values[0] = new bytes32[](2);
        values[0][0] = keccak256("new-one");
        values[0][1] = keccak256("new-two");

        (bool success,) = address(deadDrop)
            .call(
                abi.encodeCall(
                    deadDrop.rotatePolicyAssetCommitments,
                    ("rotation-policy", uint64(1), uint64(2), ids, _trustees(), values)
                )
            );
        require(!success, "INCOMPLETE_ASSET_SET_ACCEPTED");
    }

    function testRotationRejectsDuplicateAsset() public {
        string[] memory ids = new string[](2);
        ids[0] = "asset-one";
        ids[1] = "asset-one";

        (bool success,) = address(deadDrop)
            .call(
                abi.encodeCall(
                    deadDrop.rotatePolicyAssetCommitments,
                    ("rotation-policy", uint64(1), uint64(2), ids, _trustees(), _newCommitments())
                )
            );
        require(!success, "DUPLICATE_ASSET_ACCEPTED");
    }

    function testRotationRejectsDuplicateTrustee() public {
        address[] memory wallets = new address[](2);
        wallets[0] = trusteeOne;
        wallets[1] = trusteeOne;

        (bool success,) = address(deadDrop)
            .call(
                abi.encodeCall(
                    deadDrop.rotatePolicyAssetCommitments,
                    ("rotation-policy", uint64(1), uint64(2), _assetIds(), wallets, _newCommitments())
                )
            );
        require(!success, "DUPLICATE_TRUSTEE_ACCEPTED");
    }

    function testRotationRejectsUnassignedTrustee() public {
        address[] memory wallets = new address[](2);
        wallets[0] = trusteeOne;
        wallets[1] = attacker;

        (bool success,) = address(deadDrop)
            .call(
                abi.encodeCall(
                    deadDrop.rotatePolicyAssetCommitments,
                    ("rotation-policy", uint64(1), uint64(2), _assetIds(), wallets, _newCommitments())
                )
            );
        require(!success, "UNASSIGNED_TRUSTEE_ACCEPTED");
    }

    function testRotationRejectsZeroCommitment() public {
        bytes32[][] memory values = _newCommitments();
        values[1][0] = bytes32(0);

        (bool success,) = address(deadDrop)
            .call(
                abi.encodeCall(
                    deadDrop.rotatePolicyAssetCommitments,
                    ("rotation-policy", uint64(1), uint64(2), _assetIds(), _trustees(), values)
                )
            );
        require(!success, "ZERO_COMMITMENT_ACCEPTED");
    }

    function testFailedRotationLeavesAllStateUnchanged() public {
        bytes32 oldCommitment = deadDrop.getAssetCommitment("asset-one", trusteeOne);
        bytes32[][] memory values = _newCommitments();
        values[1][1] = bytes32(0);

        (bool success,) = address(deadDrop)
            .call(
                abi.encodeCall(
                    deadDrop.rotatePolicyAssetCommitments,
                    ("rotation-policy", uint64(1), uint64(2), _assetIds(), _trustees(), values)
                )
            );
        require(!success, "INVALID_ROTATION_SUCCEEDED");
        require(deadDrop.getAssetCommitment("asset-one", trusteeOne) == oldCommitment, "PARTIAL_COMMITMENT_UPDATE");
        (,, uint64 epoch,,,) = deadDrop.policies(keccak256(bytes("rotation-policy")));
        require(epoch == 1, "POLICY_EPOCH_PARTIALLY_UPDATED");
    }
}
