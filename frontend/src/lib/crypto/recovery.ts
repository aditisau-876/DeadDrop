
export interface EncryptedSharePackage {
  encrypted_share: string;
  commitment: string;
  policy_id: string;
  trustee_id: string;
  epoch: number;
}

export interface DecryptedShare {
  value: string;
  policyId: string;
  trusteeId: string;
  epoch: number;
}

export interface ProtectedPayload {
  ciphertext: string;
  nonce: string;
  aad?: string | null;
}

const SHARE_ALGORITHM =
  "X25519-HKDF-SHA256-AES-256-GCM";

const encoder = new TextEncoder();

function decodeBase64(value: string): Uint8Array {
  try {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
  } catch {
    throw new Error("Invalid Base64 data.");
  }
}

function encodeHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

function concatBytes(
  first: Uint8Array,
  second: Uint8Array,
): Uint8Array {
  const result = new Uint8Array(
    first.length + second.length,
  );

  result.set(first, 0);
  result.set(second, first.length);

  return result;
}

interface ShareEnvelope {
  version: number;
  algorithm: string;
  ephemeral_public_key: string;
  nonce: string;
  ciphertext: string;
  policy_id: string;
  trustee_id: string;
  epoch: number;
}

function parseShareEnvelope(
  encryptedShare: string,
): ShareEnvelope {
  let parsed: unknown;

  try {
    const raw = decodeBase64(encryptedShare);
    parsed = JSON.parse(
      new TextDecoder().decode(raw),
    );
  } catch {
    throw new Error(
      "Could not parse the encrypted share envelope.",
    );
  }

  if (
    typeof parsed !== "object" ||
    parsed === null
  ) {
    throw new Error("Invalid share envelope.");
  }

  const envelope = parsed as Partial<ShareEnvelope>;

  if (envelope.version !== 1) {
    throw new Error(
      "Unsupported encrypted share version.",
    );
  }

  if (envelope.algorithm !== SHARE_ALGORITHM) {
    throw new Error(
      "Unsupported share encryption algorithm.",
    );
  }

  if (
    typeof envelope.ephemeral_public_key !== "string" ||
    typeof envelope.nonce !== "string" ||
    typeof envelope.ciphertext !== "string" ||
    typeof envelope.policy_id !== "string" ||
    typeof envelope.trustee_id !== "string" ||
    typeof envelope.epoch !== "number" ||
    !Number.isInteger(envelope.epoch)
  ) {
    throw new Error(
      "Encrypted share envelope is missing required fields.",
    );
  }

  return envelope as ShareEnvelope;
}

function assertExpectedContext(
  envelope: ShareEnvelope,
  expected: {
    policyId: string;
    trusteeId: string;
    epoch: number;
  },
): void {
  if (envelope.policy_id !== expected.policyId) {
    throw new Error(
      "Share belongs to a different policy.",
    );
  }

  if (envelope.trustee_id !== expected.trusteeId) {
    throw new Error(
      "Share belongs to a different trustee.",
    );
  }

  if (envelope.epoch !== expected.epoch) {
    throw new Error(
      "Share belongs to a different recovery epoch.",
    );
  }
}

function privateKeyToPkcs8(
  rawPrivateKey: Uint8Array,
): Uint8Array {
  if (rawPrivateKey.length !== 32) {
    throw new Error(
      "X25519 private key must contain exactly 32 bytes.",
    );
  }

  // RFC 8410 PKCS#8 prefix for X25519.
  const prefix = new Uint8Array([
    0x30, 0x2e,
    0x02, 0x01, 0x00,
    0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x6e,
    0x04, 0x22,
    0x04, 0x20,
  ]);

  return concatBytes(prefix, rawPrivateKey);
}

async function deriveShareEncryptionKey(
  trusteePrivateKeyBase64: string,
  ephemeralPublicKeyBase64: string,
  context: Uint8Array,
): Promise<CryptoKey> {
  if (!globalThis.crypto?.subtle) {
    throw new Error(
      "Web Crypto is unavailable. Use HTTPS or localhost.",
    );
  }

  const privateBytes = decodeBase64(
    trusteePrivateKeyBase64,
  );

  const publicBytes = decodeBase64(
    ephemeralPublicKeyBase64,
  );

  if (publicBytes.length !== 32) {
    throw new Error(
      "Invalid X25519 ephemeral public key.",
    );
  }

  const privatePkcs8 = privateKeyToPkcs8(
    privateBytes,
  );

  let privateKey: CryptoKey;
  let ephemeralPublicKey: CryptoKey;

  try {
    privateKey = await crypto.subtle.importKey(
      "pkcs8",
      toArrayBuffer(privatePkcs8),
      { name: "X25519" } as AlgorithmIdentifier,
      false,
      ["deriveBits"],
    );

    ephemeralPublicKey = await crypto.subtle.importKey(
      "raw",
      toArrayBuffer(publicBytes),
      { name: "X25519" } as AlgorithmIdentifier,
      false,
      [],
    );
  } catch {
    throw new Error(
      "This browser does not support the required X25519 Web Crypto operation.",
    );
  }

  let sharedSecret: ArrayBuffer;

  try {
    sharedSecret = await crypto.subtle.deriveBits(
      {
        name: "X25519",
        public: ephemeralPublicKey,
      } as EcdhKeyDeriveParams,
      privateKey,
      256,
    );
  } catch {
    throw new Error(
      "X25519 key agreement failed. Check the trustee private key.",
    );
  }

  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedSecret,
    "HKDF",
    false,
    ["deriveKey"],
  );

  const hkdfInfo = concatBytes(
    encoder.encode("DeadDrop/share-encryption/"),
    context,
  );

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: toArrayBuffer(hkdfInfo),
    },
    hkdfKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["decrypt"],
  );
}

export async function decryptTrusteeShare(
  encryptedShare: string,
  trusteePrivateKeyBase64: string,
  expected: {
    policyId: string;
    trusteeId: string;
    epoch: number;
  },
): Promise<DecryptedShare> {
  const envelope = parseShareEnvelope(
    encryptedShare,
  );

  assertExpectedContext(envelope, expected);

  const context = encoder.encode(
    `${envelope.policy_id}:${envelope.trustee_id}:${envelope.epoch}`,
  );

  const key = await deriveShareEncryptionKey(
    trusteePrivateKeyBase64,
    envelope.ephemeral_public_key,
    context,
  );

  const nonce = decodeBase64(envelope.nonce);
  const ciphertext = decodeBase64(
    envelope.ciphertext,
  );

  if (nonce.length !== 12) {
    throw new Error("Invalid AES-GCM nonce.");
  }

  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: toArrayBuffer(nonce),
        additionalData: toArrayBuffer(context),
        tagLength: 128,
      },
      key,
      toArrayBuffer(ciphertext),
    );

    return {
      value: new TextDecoder().decode(plaintext),
      policyId: envelope.policy_id,
      trusteeId: envelope.trustee_id,
      epoch: envelope.epoch,
    };
  } catch {
    throw new Error(
      "Share decryption failed. The private key may be incorrect or the encrypted package may have been modified.",
    );
  }
}

export async function verifyShareCommitment(
  share: DecryptedShare,
  expectedCommitment: string,
): Promise<boolean> {
  if (!/^[0-9a-fA-F]{64}$/.test(expectedCommitment)) {
    throw new Error("Invalid SHA-256 commitment format.");
  }

  const material =
    `deaddrop:v1|` +
    `policy:${share.policyId}|` +
    `trustee:${share.trusteeId}|` +
    `epoch:${share.epoch}|` +
    `share:${share.value}`;

  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(material),
  );

  const actualCommitment = encodeHex(
    new Uint8Array(digest),
  );

  return actualCommitment === expectedCommitment.toLowerCase();
}

export async function decryptProtectedAsset(
  payload: ProtectedPayload,
  aesKeyBytes: Uint8Array,
): Promise<Uint8Array> {
  if (aesKeyBytes.length !== 32) {
    throw new Error(
      "Recovered AES-256 key must contain exactly 32 bytes.",
    );
  }

  const nonce = decodeBase64(payload.nonce);
  const ciphertext = decodeBase64(
    payload.ciphertext,
  );

  if (nonce.length !== 12) {
    throw new Error("Invalid asset encryption nonce.");
  }

  const key = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(aesKeyBytes),
    "AES-GCM",
    false,
    ["decrypt"],
  );

  const algorithm: AesGcmParams = {
    name: "AES-GCM",
    iv: toArrayBuffer(nonce),
    tagLength: 128,
  };

  if (payload.aad) {
    algorithm.additionalData = toArrayBuffer(
      decodeBase64(payload.aad),
    );
  }

  try {
    const plaintext = await crypto.subtle.decrypt(
      algorithm,
      key,
      toArrayBuffer(ciphertext),
    );

    return new Uint8Array(plaintext);
  } catch {
    throw new Error(
      "Asset decryption failed. The recovered key or encrypted payload is invalid.",
    );
  }
}
