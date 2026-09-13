# Implementation order
1. 3-of-5 threshold + policy data model
2. AES-256-GCM client encryption
3. audited secret-sharing integration
4. share commitments and client verification
5. Solidity policy/recovery state machine
6. EIP-712 typed approvals
7. FastAPI persistence
8. React trustee/recovery workflows
9. real proactive refresh protocol
10. security tests and attack simulator
11. NIZK/VSS only if implementation is mature enough for the deadline

Never call a hash commitment proof-of-possession. Never call an epoch counter proactive refresh.
