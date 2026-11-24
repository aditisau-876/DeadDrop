/**
 * In-memory vault for AES-256 keys recovered and authenticated in this tab.
 *
 * Keys are intentionally NOT written to localStorage, sessionStorage,
 * IndexedDB, or the backend. Reloading the page clears this vault.
 */
export interface RecoveredKeyEntry {
  policyId: string;
  assetId: string;
  epoch: number;
  key: Uint8Array;
}

const recoveredKeys = new Map<
  string,
  Map<string, RecoveredKeyEntry>
>();

export function storeRecoveredAssetKey(
  policyId: string,
  assetId: string,
  epoch: number,
  key: Uint8Array,
): void {
  if (!policyId.trim() || !assetId.trim()) {
    throw new Error("Policy ID and asset ID are required to cache a recovered key.");
  }
  if (!Number.isInteger(epoch) || epoch < 1) {
    throw new Error("The recovered asset key has an invalid epoch.");
  }
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    throw new Error("Only a recovered 32-byte AES-256 key can be cached.");
  }

  let policyKeys = recoveredKeys.get(policyId);
  if (!policyKeys) {
    policyKeys = new Map<string, RecoveredKeyEntry>();
    recoveredKeys.set(policyId, policyKeys);
  }

  const previous = policyKeys.get(assetId);
  previous?.key.fill(0);

  policyKeys.set(assetId, {
    policyId,
    assetId,
    epoch,
    key: new Uint8Array(key),
  });
}

export function getRecoveredAssetEntries(
  policyId: string,
): RecoveredKeyEntry[] {
  const entries = recoveredKeys.get(policyId);
  if (!entries) return [];

  return Array.from(entries.values()).map((entry) => ({
    ...entry,
    key: new Uint8Array(entry.key),
  }));
}

export function getRecoveredAssetKeys(
  policyId: string,
): Map<string, Uint8Array> {
  const result = new Map<string, Uint8Array>();
  const entries = recoveredKeys.get(policyId);

  if (!entries) return result;

  for (const [assetId, entry] of entries) {
    result.set(assetId, new Uint8Array(entry.key));
  }

  return result;
}

export function clearRecoveredAssetKeys(policyId?: string): void {
  if (policyId) {
    const entries = recoveredKeys.get(policyId);
    if (!entries) return;

    for (const entry of entries.values()) {
      entry.key.fill(0);
    }
    recoveredKeys.delete(policyId);
    return;
  }

  for (const entries of recoveredKeys.values()) {
    for (const entry of entries.values()) {
      entry.key.fill(0);
    }
  }
  recoveredKeys.clear();
}