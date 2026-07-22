import { describe, expect, it } from 'vitest';

import { CONSENSUS_BRANCH_ID, parseSats, toSafeNumber } from '../src/money.js';

describe('parseSats', () => {
  it('parses whole and fractional VRSC to satoshi bigints (no float math)', () => {
    expect(parseSats('1')).toBe(100_000_000n);
    expect(parseSats('1.0')).toBe(100_000_000n);
    expect(parseSats('0.0001')).toBe(10_000n);
    expect(parseSats('0')).toBe(0n);
    expect(parseSats('10.5')).toBe(1_050_000_000n);
    expect(parseSats('1.23456789')).toBe(123_456_789n);
    expect(parseSats(' 2.5 ')).toBe(250_000_000n); // trims
  });

  it('is exact where float math would drift (0.1 + 0.2 territory)', () => {
    expect(parseSats('0.1')).toBe(10_000_000n);
    expect(parseSats('0.29999999')).toBe(29_999_999n);
  });

  it('rejects malformed amounts', () => {
    for (const bad of ['abc', '1.2.3', '-1', '', '1.', '.5', '1e8', '0x10']) {
      expect(() => parseSats(bad), bad).toThrow();
    }
  });

  it('rejects more than 8 decimals', () => {
    expect(() => parseSats('1.234567891')).toThrow(/decimals/);
  });
});

describe('toSafeNumber', () => {
  it('converts within [0, 2^53)', () => {
    expect(toSafeNumber(0n)).toBe(0);
    expect(toSafeNumber(10_000n)).toBe(10_000);
    expect(toSafeNumber(BigInt(Number.MAX_SAFE_INTEGER))).toBe(Number.MAX_SAFE_INTEGER);
  });

  it('throws outside the safe range (the only checked float64 crossing)', () => {
    expect(() => toSafeNumber(-1n)).toThrow(/safe range/);
    expect(() => toSafeNumber(BigInt(Number.MAX_SAFE_INTEGER) + 1n)).toThrow(/safe range/);
  });
});

describe('CONSENSUS_BRANCH_ID', () => {
  it('is the Verus Sapling branch id 0x76b809bb', () => {
    expect(CONSENSUS_BRANCH_ID).toBe(0x76b809bb);
    expect(CONSENSUS_BRANCH_ID).toBe(1_991_772_603);
  });
});
