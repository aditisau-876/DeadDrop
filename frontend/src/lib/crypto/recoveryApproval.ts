
import {
  BrowserProvider,
  type Eip1193Provider,
  type TypedDataDomain,
  type TypedDataField,
} from "ethers";

declare global {
  interface Window {
    ethereum?: Eip1193Provider;
  }
}

export interface RecoveryApprovalPayload {
  recoveryId: string;
  policyId: string;
  trusteeId: string;
  incidentHash: string;
  policyVersion: number;
  policyEpoch: number;
}

export interface RecoveryApprovalTypedData {
  types: Record<string, TypedDataField[]>;
  primaryType: string;
  domain: TypedDataDomain;
  message: {
    recoveryId: string;
    policyId: string;
    trusteeId: string;
    incidentHash: string;
    policyVersion: number;
    policyEpoch: number;
  };
}

export async function signRecoveryApproval(
  data: RecoveryApprovalPayload,
  expectedWallet: string,
): Promise<string> {
  if (!window.ethereum) {
    throw new Error("MetaMask was not detected.");
  }

  if (!expectedWallet) {
    throw new Error(
      "No wallet address is registered for this trustee.",
    );
  }

  const provider = new BrowserProvider(window.ethereum);

  await provider.send("eth_requestAccounts", []);

  const signer = await provider.getSigner();
  const connectedWallet = await signer.getAddress();

  if (
    connectedWallet.toLowerCase() !==
    expectedWallet.toLowerCase()
  ) {
    throw new Error(
      `Wrong MetaMask account. Connect the registered trustee wallet: ${expectedWallet}`,
    );
  }

  const typedData: RecoveryApprovalTypedData = {
    types: {
      EIP712Domain: [
        { name: "name", type: "string" },
        { name: "version", type: "string" },
        { name: "chainId", type: "uint256" },
        { name: "verifyingContract", type: "address" },
      ],
      RecoveryApproval: [
        { name: "recoveryId", type: "string" },
        { name: "policyId", type: "string" },
        { name: "trusteeId", type: "string" },
        { name: "incidentHash", type: "string" },
        { name: "policyVersion", type: "uint256" },
        { name: "policyEpoch", type: "uint256" },
      ],
    },

    primaryType: "RecoveryApproval",

    domain: {
      name: "DeadDrop",
      version: "1",
      chainId: Number(
        import.meta.env.VITE_BLOCKCHAIN_CHAIN_ID,
      ),
      verifyingContract:
        import.meta.env.VITE_BLOCKCHAIN_CONTRACT_ADDRESS,
    },

    message: {
      recoveryId: data.recoveryId,
      policyId: data.policyId,
      trusteeId: data.trusteeId,
      incidentHash: data.incidentHash,
      policyVersion: data.policyVersion,
      policyEpoch: data.policyEpoch,
    },
  };

  if (
    !typedData.domain.chainId ||
    !typedData.domain.verifyingContract
  ) {
    throw new Error(
      "Blockchain configuration is incomplete. Check the frontend environment variables.",
    );
  }

  const { EIP712Domain, ...signingTypes } =
    typedData.types;

  if (!EIP712Domain) {
    throw new Error("EIP-712 domain is missing.");
  }

  return signer.signTypedData(
    typedData.domain,
    signingTypes,
    typedData.message,
  );
}
