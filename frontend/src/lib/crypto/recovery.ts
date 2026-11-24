
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
      salt: new Uint8Array(32),
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


function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function gfMultiply(a: number, b: number): number {
  let result = 0;
  let left = a & 0xff;
  let right = b & 0xff;
  while (right > 0) {
    if (right & 1) result ^= left;
    const high = left & 0x80;
    left = (left << 1) & 0xff;
    if (high) left ^= 0x1b;
    right >>>= 1;
  }
  return result & 0xff;
}

function gfPower(value: number, exponent: number): number {
  let result = 1;
  let base = value & 0xff;
  let power = exponent;
  while (power > 0) {
    if (power & 1) result = gfMultiply(result, base);
    base = gfMultiply(base, base);
    power >>>= 1;
  }
  return result;
}

function splitSecretGf256(
  secret: Uint8Array,
  threshold: number,
  shareCount: number,
): string[] {
  if (threshold < 2 || threshold > shareCount || shareCount > 16) {
    throw new Error("Invalid Shamir threshold or share count.");
  }
  const coefficients = Array.from({ length: secret.length }, () => {
    const bytes = crypto.getRandomValues(new Uint8Array(threshold - 1));
    return Array.from(bytes);
  });
  const shares: string[] = [];
  for (let x = 1; x <= shareCount; x++) {
    const y = new Uint8Array(secret.length);
    for (let byteIndex = 0; byteIndex < secret.length; byteIndex++) {
      let value = secret[byteIndex];
      let power = x;
      for (let degree = 0; degree < threshold - 1; degree++) {
        value ^= gfMultiply(coefficients[byteIndex][degree], power);
        power = gfMultiply(power, x);
      }
      y[byteIndex] = value;
    }
    shares.push(JSON.stringify({
      scheme: "deaddrop-gf256-v1",
      x,
      y: encodeBase64(y),
    }));
  }
  return shares;
}

export function reconstructSecretFromShares(values: string[]): Uint8Array {
  if (values.length < 2) throw new Error("At least two verified shares are required.");
  const parsed = values.map((value) => {
    let item: unknown;
    try { item = JSON.parse(value); } catch { throw new Error("A share does not use the DeadDrop GF(256) format."); }
    if (typeof item !== "object" || item === null) throw new Error("Invalid Shamir share.");
    const share = item as { scheme?: unknown; x?: unknown; y?: unknown };
    if (share.scheme !== "deaddrop-gf256-v1" || typeof share.x !== "number" || !Number.isInteger(share.x) || share.x < 1 || share.x > 255 || typeof share.y !== "string") {
      throw new Error("Invalid Shamir share format.");
    }
    return { x: share.x, y: decodeBase64(share.y) };
  });
  if (new Set(parsed.map((share) => share.x)).size !== parsed.length) throw new Error("Duplicate Shamir share coordinates were supplied.");
  const length = parsed[0].y.length;
  if (length === 0 || parsed.some((share) => share.y.length !== length)) throw new Error("Shamir share lengths do not match.");
  const selected = parsed.slice(0, Math.min(values.length, 16));
  const secret = new Uint8Array(length);
  for (let i = 0; i < selected.length; i++) {
    let coefficient = 1;
    for (let j = 0; j < selected.length; j++) {
      if (i === j) continue;
      const numerator = selected[j].x;
      const denominator = selected[i].x ^ selected[j].x;
      if (denominator === 0) throw new Error("Invalid duplicate Shamir coordinates.");
      coefficient = gfMultiply(coefficient, gfMultiply(numerator, gfPower(denominator, 254)));
    }
    for (let byteIndex = 0; byteIndex < length; byteIndex++) {
      secret[byteIndex] ^= gfMultiply(selected[i].y[byteIndex], coefficient);
    }
  }
  return secret;
}

async function encryptShareForTrustee(
  shareValue: string,
  trusteePublicKeyBase64: string,
  policyId: string,
  trusteeId: string,
  epoch: number,
): Promise<{ encrypted_share: string; commitment: string }> {
  const publicBytes = decodeBase64(trusteePublicKeyBase64);
  if (publicBytes.length !== 32) throw new Error(`Trustee ${trusteeId} has an invalid X25519 public key.`);
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
    { name: "X25519", public: trusteePublicKey } as EcdhKeyDeriveParams,
    ephemeral.privateKey,
    256,
  );
  const context = encoder.encode(`${policyId}:${trusteeId}:${epoch}`);
  const hkdfKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: toArrayBuffer(concatBytes(encoder.encode("DeadDrop/share-encryption/"), context)) },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(nonce), additionalData: toArrayBuffer(context), tagLength: 128 },
    key,
    encoder.encode(shareValue),
  );
  const ephemeralPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  const envelope = {
    version: 1,
    algorithm: SHARE_ALGORITHM,
    ephemeral_public_key: encodeBase64(ephemeralPublic),
    nonce: encodeBase64(nonce),
    ciphertext: encodeBase64(new Uint8Array(ciphertext)),
    policy_id: policyId,
    trustee_id: trusteeId,
    epoch,
  };
  const encrypted_share = encodeBase64(encoder.encode(JSON.stringify(envelope)));
  const material = `deaddrop:v1|policy:${policyId}|trustee:${trusteeId}|epoch:${epoch}|share:${shareValue}`;
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(material));
  return { encrypted_share, commitment: encodeHex(new Uint8Array(digest)) };
}

export interface AssetTrusteeInput {
  id: string;
  name: string;
  public_key: string | null;
}

export async function createProtectedAssetBundle(input: {
  plaintext: string;
  policyId: string;
  epoch: number;
  threshold: number;
  trustees: AssetTrusteeInput[];
}): Promise<{
  ciphertext: string;
  nonce: string;
  aad: string;
  threshold: number;
  shares: Array<{ trustee_id: string; encrypted_share: string; commitment: string; epoch: number }>;
}> {
  if (!globalThis.crypto?.subtle) throw new Error("Web Crypto is unavailable. Use localhost or HTTPS.");
  if (!input.plaintext) throw new Error("Enter the asset content to protect.");
  if (input.trustees.length < 2 || input.threshold < 2 || input.threshold > input.trustees.length) throw new Error("The threshold must be between 2 and the number of assigned trustees.");
  if (input.trustees.some((trustee) => !trustee.public_key)) throw new Error("Every assigned trustee must have an X25519 public key configured before protecting an asset.");

  const aesKeyBytes = crypto.getRandomValues(new Uint8Array(32));
  const aesKey = await crypto.subtle.importKey("raw", toArrayBuffer(aesKeyBytes), "AES-GCM", false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aad = encoder.encode(`deaddrop:asset:${input.policyId}:${input.epoch}`);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(nonce), additionalData: toArrayBuffer(aad), tagLength: 128 },
    aesKey,
    encoder.encode(input.plaintext),
  );

  const rawShares = splitSecretGf256(aesKeyBytes, input.threshold, input.trustees.length);
  const encryptedShares = await Promise.all(input.trustees.map(async (trustee, index) => {
    const encrypted = await encryptShareForTrustee(rawShares[index], trustee.public_key!, input.policyId, trustee.id, input.epoch);
    return {
      trustee_id: trustee.id,
      encrypted_share: encrypted.encrypted_share,
      commitment: encrypted.commitment,
      epoch: input.epoch,
    };
  }));
  return {
    ciphertext: encodeBase64(new Uint8Array(ciphertext)),
    nonce: encodeBase64(nonce),
    aad: encodeBase64(aad),
    threshold: input.threshold,
    shares: encryptedShares,
  };
}
