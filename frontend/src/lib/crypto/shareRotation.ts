
const SHARE_ALGORITHM = "X25519-HKDF-SHA256-AES-256-GCM";
const encoder = new TextEncoder();

export interface RotationTrustee {
  id: string;
  public_key: string | null;
}

export interface RotationAssetInput {
  asset_id: string;
  aesKeyBytes: Uint8Array;
  threshold: number;
}

export interface RotatedShare {
  trustee_id: string;
  encrypted_share: string;
  commitment: string;
}

export interface RotatedAssetShares {
  asset_id: string;
  shares: RotatedShare[];
}

export interface PolicyRotationRequest {
  expected_epoch: number;
  assets: RotatedAssetShares[];
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function decodeBase64(value: string): Uint8Array {
  try {
    const binary = atob(value);
    const result = new Uint8Array(binary.length);

    for (let index = 0; index < binary.length; index++) {
      result[index] = binary.charCodeAt(index);
    }

    return result;
  } catch {
    throw new Error("Invalid Base64 public key.");
  }
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

function encodeHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function gfMultiply(a: number, b: number): number {
  let result = 0;
  let left = a & 0xff;
  let right = b & 0xff;

  while (right > 0) {
    if (right & 1) {
      result ^= left;
    }

    const high = left & 0x80;

    left = (left << 1) & 0xff;

    if (high) {
      left ^= 0x1b;
    }

    right >>>= 1;
  }

  return result & 0xff;
}

/**
 * Generate a fresh set of Shamir shares.
 *
 * New random polynomial coefficients are generated every time.
 * The original AES key remains unchanged.
 */
function splitSecret(
  secret: Uint8Array,
  threshold: number,
  shareCount: number,
): string[] {
  if (secret.length !== 32) {
    throw new Error("The AES-256 key must contain exactly 32 bytes.");
  }

  if (
    threshold < 2 ||
    threshold > shareCount ||
    shareCount > 16
  ) {
    throw new Error(
      "Invalid Shamir threshold or trustee count.",
    );
  }

  const coefficients = Array.from(
    { length: secret.length },
    () => {
      const random = crypto.getRandomValues(
        new Uint8Array(threshold - 1),
      );

      return Array.from(random);
    },
  );

  const shares: string[] = [];

  for (let x = 1; x <= shareCount; x++) {
    const y = new Uint8Array(secret.length);

    for (
      let byteIndex = 0;
      byteIndex < secret.length;
      byteIndex++
    ) {
      let value = secret[byteIndex];
      let power = x;

      for (
        let degree = 0;
        degree < threshold - 1;
        degree++
      ) {
        value ^= gfMultiply(
          coefficients[byteIndex][degree],
          power,
        );

        power = gfMultiply(power, x);
      }

      y[byteIndex] = value;
    }

    shares.push(
      JSON.stringify({
        scheme: "deaddrop-gf256-v1",
        x,
        y: encodeBase64(y),
      }),
    );
  }

  return shares;
}

/**
 * Encrypt a newly generated share for one trustee.
 *
 * Uses the same envelope format, X25519 key agreement,
 * HKDF parameters and AES-GCM context as the existing
 * DeadDrop asset-protection implementation.
 */
async function encryptShareForTrustee(
  shareValue: string,
  trustee: RotationTrustee,
  policyId: string,
  epoch: number,
): Promise<RotatedShare> {
  if (!trustee.public_key) {
    throw new Error(
      `Trustee ${trustee.id} has no registered public key.`,
    );
  }

  const publicBytes = decodeBase64(trustee.public_key);

  if (publicBytes.length !== 32) {
    throw new Error(
      `Trustee ${trustee.id} has an invalid X25519 public key.`,
    );
  }

  const trusteePublicKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(publicBytes),
    { name: "X25519" } as AlgorithmIdentifier,
    false,
    [],
  );

  const ephemeral = await crypto.subtle.generateKey(
    { name: "X25519" } as AlgorithmIdentifier,
    true,
    ["deriveBits"],
  ) as CryptoKeyPair;

  const sharedSecret = await crypto.subtle.deriveBits(
    {
      name: "X25519",
      public: trusteePublicKey,
    } as EcdhKeyDeriveParams,
    ephemeral.privateKey,
    256,
  );

  const context = encoder.encode(
    `${policyId}:${trustee.id}:${epoch}`,
  );

  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedSecret,
    "HKDF",
    false,
    ["deriveKey"],
  );

  const hkdfInfo = new Uint8Array([
    ...encoder.encode("DeadDrop/share-encryption/"),
    ...context,
  ]);

  const encryptionKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: toArrayBuffer(hkdfInfo),
    },
    hkdfKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt"],
  );

  const nonce = crypto.getRandomValues(
    new Uint8Array(12),
  );

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(nonce),
      additionalData: toArrayBuffer(context),
      tagLength: 128,
    },
    encryptionKey,
    encoder.encode(shareValue),
  );

  const ephemeralPublicKey = new Uint8Array(
    await crypto.subtle.exportKey(
      "raw",
      ephemeral.publicKey,
    ),
  );

  const envelope = {
    version: 1,
    algorithm: SHARE_ALGORITHM,
    ephemeral_public_key: encodeBase64(
      ephemeralPublicKey,
    ),
    nonce: encodeBase64(nonce),
    ciphertext: encodeBase64(
      new Uint8Array(ciphertext),
    ),
    policy_id: policyId,
    trustee_id: trustee.id,
    epoch,
  };

  const encryptedShare = encodeBase64(
    encoder.encode(JSON.stringify(envelope)),
  );

  // This must exactly match backend/app/crypto/commitments.py.
  const commitmentMaterial =
    `deaddrop:v1|` +
    `policy:${policyId}|` +
    `trustee:${trustee.id}|` +
    `epoch:${epoch}|` +
    `share:${shareValue}`;

  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(commitmentMaterial),
  );

  return {
    trustee_id: trustee.id,
    encrypted_share: encryptedShare,
    commitment: encodeHex(new Uint8Array(digest)),
  };
}

/**
 * Generate fresh encrypted shares for one protected asset.
 *
 * The caller must supply the recovered original AES key.
 * This function does not upload anything to the backend.
 */
export async function createRotatedAssetShares(input: {
  assetId: string;
  aesKeyBytes: Uint8Array;
  policyId: string;
  newEpoch: number;
  threshold: number;
  trustees: RotationTrustee[];
}): Promise<RotatedAssetShares> {
  if (!globalThis.crypto?.subtle) {
    throw new Error(
      "Web Crypto is unavailable. Use localhost or HTTPS.",
    );
  }

  if (!input.assetId.trim()) {
    throw new Error("Asset ID is required.");
  }

  if (!input.policyId.trim()) {
    throw new Error("Policy ID is required.");
  }

  if (
    !Number.isInteger(input.newEpoch) ||
    input.newEpoch < 2
  ) {
    throw new Error("Invalid new share epoch.");
  }

  if (input.aesKeyBytes.length !== 32) {
    throw new Error(
      "A valid recovered 32-byte AES key is required.",
    );
  }

  if (input.trustees.length < 2) {
    throw new Error(
      "At least two trustees are required.",
    );
  }

  const trusteeIds = input.trustees.map(
    (trustee) => trustee.id,
  );

  if (new Set(trusteeIds).size !== trusteeIds.length) {
    throw new Error("Duplicate trustees are not allowed.");
  }

  if (
    input.trustees.some(
      (trustee) => !trustee.public_key,
    )
  ) {
    throw new Error(
      "Every trustee must have a registered encryption public key.",
    );
  }

  const rawShares = splitSecret(
    input.aesKeyBytes,
    input.threshold,
    input.trustees.length,
  );

  const encryptedShares = await Promise.all(
    input.trustees.map((trustee, index) =>
      encryptShareForTrustee(
        rawShares[index],
        trustee,
        input.policyId,
        input.newEpoch,
      ),
    ),
  );

  return {
    asset_id: input.assetId,
    shares: encryptedShares,
  };
}

/**
 * Prepare the complete request expected by:
 *
 * POST /api/policies/{policy_id}/rotate-shares
 *
 * Every protected asset must be included exactly once.
 */
export async function createPolicyRotationRequest(input: {
  expectedEpoch: number;
  assets: Array<{
    assetId: string;
    aesKeyBytes: Uint8Array;
    threshold: number;
  }>;
  policyId: string;
  trustees: RotationTrustee[];
}): Promise<PolicyRotationRequest> {
  if (
    !Number.isInteger(input.expectedEpoch) ||
    input.expectedEpoch < 1
  ) {
    throw new Error("Invalid current policy epoch.");
  }

  if (input.assets.length === 0) {
    throw new Error(
      "At least one protected asset is required.",
    );
  }

  const assetIds = input.assets.map(
    (asset) => asset.assetId,
  );

  if (new Set(assetIds).size !== assetIds.length) {
    throw new Error(
      "Duplicate protected asset IDs are not allowed.",
    );
  }

  const newEpoch = input.expectedEpoch + 1;

  const rotatedAssets = await Promise.all(
    input.assets.map((asset) =>
      createRotatedAssetShares({
        assetId: asset.assetId,
        aesKeyBytes: asset.aesKeyBytes,
        policyId: input.policyId,
        newEpoch,
        threshold: asset.threshold,
        trustees: input.trustees,
      }),
    ),
  );

  return {
    expected_epoch: input.expectedEpoch,
    assets: rotatedAssets,
  };
}
