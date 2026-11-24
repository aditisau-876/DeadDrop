
import {
  BrowserProvider,
  type TypedDataDomain,
  type TypedDataField,
} from "ethers";


export interface ShareReleaseChallenge {
  challenge_id: string;
  expires_at: string;
  typed_data: {
    domain: TypedDataDomain;
    types: Record<string, TypedDataField[]>;
    primaryType: string;
    message: Record<string, string | number>;
  };
}

export async function signShareReleaseChallenge(
  challenge: ShareReleaseChallenge,
): Promise<{
  walletAddress: string;
  signature: string;
  challengeId: string;
  nonce: string;
}> {
  if (!window.ethereum) {
    throw new Error("MetaMask was not detected.");
  }

  if (
    new Date(challenge.expires_at).getTime() <= Date.now()
  ) {
    throw new Error("The share-release challenge has expired.");
  }

  const typedData = challenge.typed_data;

  if (typedData.primaryType !== "ShareRelease") {
    throw new Error("Unexpected EIP-712 message type.");
  }

  const nonce = typedData.message.nonce;
  const challengeId = typedData.message.challengeId;

  if (
    typeof nonce !== "string" ||
    typeof challengeId !== "string" ||
    challengeId !== challenge.challenge_id
  ) {
    throw new Error("Challenge data is incomplete or inconsistent.");
  }

  const provider = new BrowserProvider(window.ethereum);

  await provider.send("eth_requestAccounts", []);

  const signer = await provider.getSigner();
  const walletAddress = await signer.getAddress();

  const { EIP712Domain, ...types } = typedData.types;

  if (!EIP712Domain) {
    throw new Error("EIP-712 domain definition is missing.");
  }

  const signature = await signer.signTypedData(
    typedData.domain,
    types,
    typedData.message,
  );

  return {
    walletAddress,
    signature,
    challengeId,
    nonce,
  };
}
