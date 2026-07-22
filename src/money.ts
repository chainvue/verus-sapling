/**
 * Money helpers, kept LOCAL and dependency-free so the browser-reachable core
 * (wallet orchestration) bundles without pulling @chainvue/verus-sdk — whose
 * published `dist/bundle.js` bundles @bitgo/utxo-lib and Node builtins
 * (`crypto`/`buffer`/`os`), which don't belong in a browser extension.
 *
 * These mirror the SDK's semantics exactly (same money invariant): satoshi
 * amounts are `bigint` end to end; `toSafeNumber` is the ONLY checked crossing
 * into a float64 boundary. Node consumers who already have the SDK can keep
 * using its versions — these exist so the shielded package stays self-contained.
 */

/** Verus consensus branch id for the ZIP-243 sighash / binding sig (0x76b809bb). */
export const CONSENSUS_BRANCH_ID = 0x76b809bb; // 1991772603

const SATS_PER_COIN = 100_000_000n;
const MAX_DECIMALS = 8;

/**
 * Exact decimal-string → satoshi `bigint`. No float math (no `coins * 1e8`).
 * Rejects malformed input and more than 8 fractional digits.
 */
export function parseSats(amount: string): bigint {
  const s = amount.trim();
  if (!/^\d+(\.\d+)?$/.test(s)) throw new Error(`invalid amount: "${amount}"`);
  const [intPart, fracPart = ''] = s.split('.');
  if (fracPart.length > MAX_DECIMALS) {
    throw new Error(`amount "${amount}" has more than ${MAX_DECIMALS} decimals`);
  }
  const frac = (fracPart + '00000000').slice(0, MAX_DECIMALS);
  return BigInt(intPart!) * SATS_PER_COIN + BigInt(frac);
}

/**
 * Checked crossing from `bigint` satoshis into a JS `number` (the only place a
 * satoshi value becomes float64). Throws outside `[0, 2^53)`.
 */
export function toSafeNumber(sats: bigint): number {
  if (sats < 0n || sats > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`satoshi value ${sats} outside safe range [0, 2^53)`);
  }
  return Number(sats);
}
