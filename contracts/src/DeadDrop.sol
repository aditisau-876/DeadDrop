// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract DeadDrop {
 enum State{None,Requested,Executed,Cancelled}
 struct Policy{bytes32 policyHash;uint256 epoch;uint256 timelockDuration;bool active;}
 struct Recovery{bytes32 policyId;bytes32 incidentHash;uint256 expiry;uint256 approvals;State state;}
 mapping(bytes32=>Policy) public policies;
 mapping(bytes32=>Recovery) public recoveries;
 mapping(bytes32=>mapping(address=>bool)) public trustees;
 mapping(bytes32=>mapping(address=>bool)) public approved;
 mapping(bytes32=>bytes32[]) private commitments;
 event PolicyRegistered(bytes32 indexed id,bytes32 hash,uint256 epoch);
 event ShareCommitmentsUpdated(bytes32 indexed id,uint256 epoch);
 event RecoveryRequested(bytes32 indexed requestId,bytes32 indexed policyId,address requester);
 event ApprovalSubmitted(bytes32 indexed requestId,address trustee);
 event RecoveryExecuted(bytes32 indexed requestId,bytes32 artifactHash);
 event RecoveryCancelled(bytes32 indexed requestId);
 function registerPolicy(bytes32 id,bytes32 hash,address[] calldata ts,bytes32[] calldata cs,uint256 delay) external {require(policies[id].policyHash==bytes32(0));require(ts.length==cs.length);policies[id]=Policy(hash,1,delay,true);for(uint i;i<ts.length;i++){trustees[id][ts[i]]=true;commitments[id].push(cs[i]);}emit PolicyRegistered(id,hash,1);}
 function updateShareCommitments(bytes32 id,uint256 epoch,bytes32[] calldata cs,bytes calldata) external {require(policies[id].active);require(epoch>policies[id].epoch);delete commitments[id];for(uint i;i<cs.length;i++)commitments[id].push(cs[i]);policies[id].epoch=epoch;emit ShareCommitmentsUpdated(id,epoch);}
 function requestRecovery(bytes32 rid,bytes32 pid,bytes32 incident,uint256 expiry) external {require(policies[pid].active);require(recoveries[rid].state==State.None);require(expiry>block.timestamp);recoveries[rid]=Recovery(pid,incident,expiry,0,State.Requested);emit RecoveryRequested(rid,pid,msg.sender);}
 function submitApproval(bytes32 rid) external {Recovery storage r=recoveries[rid];require(r.state==State.Requested);require(block.timestamp<r.expiry);require(trustees[r.policyId][msg.sender]);require(!approved[rid][msg.sender]);approved[rid][msg.sender]=true;r.approvals++;emit ApprovalSubmitted(rid,msg.sender);}
 function cancelRecovery(bytes32 rid) external {require(recoveries[rid].state==State.Requested);recoveries[rid].state=State.Cancelled;emit RecoveryCancelled(rid);}
 function executeRecovery(bytes32 rid,bytes32 artifact) external {Recovery storage r=recoveries[rid];Policy storage p=policies[r.policyId];require(r.state==State.Requested);require(block.timestamp>=p.timelockDuration+block.timestamp || p.timelockDuration==0);require(r.approvals>=2);require(block.timestamp<r.expiry);r.state=State.Executed;emit RecoveryExecuted(rid,artifact);}
 function getCommitments(bytes32 id) external view returns(bytes32[] memory){return commitments[id];}
}
