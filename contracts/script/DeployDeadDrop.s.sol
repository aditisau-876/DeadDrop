// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DeadDrop} from "../src/DeadDrop.sol";

interface VmDeploy {
    function envUint(string calldata name) external view returns (uint256);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
}

/// @notice Deploys the DeadDrop registry/state-machine contract.
/// @dev Set DEPLOYER_PRIVATE_KEY in the environment before running.
contract DeployDeadDrop {
    VmDeploy private constant vm = VmDeploy(address(uint160(uint256(keccak256("hevm cheat code")))));

    function run() external returns (DeadDrop deployed) {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(deployerKey);
        deployed = new DeadDrop();
        vm.stopBroadcast();
    }
}
