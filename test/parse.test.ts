import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';

import { parseSaplingOutput, parseTreeState } from '../src/parse.js';

/**
 * Golden vectors captured from a live Verus testnet lightwalletd: the raw v4 tx
 * that created the note spent by the on-chain-accepted z→z (txid 07e3b38e…f996),
 * and the commitment-tree finalState at its block − 1. The `expected*` fields
 * were produced by the reference byte-parsers whose output built that accepted
 * transaction — so matching them pins the wire layout to consensus reality.
 */
const fixture = JSON.parse(
  readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), 'vectors', 'parse_fixture.json'),
    'utf8',
  ),
) as {
  output_index: number;
  rawTxHex: string;
  expectedOutput: { cv: string; cmu: string; epk: string; enc: string; ct: string; proof: string };
  treeFinalStateHex: string;
  expectedTree: { left: string | null; right: string | null; parents: (string | null)[] };
};

describe('parseSaplingOutput', () => {
  it('extracts the full Sapling output description at the note index', () => {
    const raw = Uint8Array.from(Buffer.from(fixture.rawTxHex, 'hex'));
    const out = parseSaplingOutput(raw, fixture.output_index);
    expect(out).toEqual(fixture.expectedOutput);
  });

  it('produces correctly-sized fields (948-byte description split)', () => {
    const out = parseSaplingOutput(Uint8Array.from(Buffer.from(fixture.rawTxHex, 'hex')), fixture.output_index);
    expect(out.cv).toHaveLength(64);
    expect(out.cmu).toHaveLength(64);
    expect(out.epk).toHaveLength(64);
    expect(out.enc).toHaveLength(1160); // 580 bytes
    expect(out.ct).toHaveLength(160); // 80 bytes
    expect(out.proof).toHaveLength(384); // 192 bytes
  });

  it('throws for an out-of-range shielded output index', () => {
    const raw = Uint8Array.from(Buffer.from(fixture.rawTxHex, 'hex'));
    expect(() => parseSaplingOutput(raw, 99)).toThrow(/out of range/);
  });
});

describe('parseTreeState', () => {
  it('parses the commitment-tree finalState into left/right/parents', () => {
    expect(parseTreeState(fixture.treeFinalStateHex)).toEqual(fixture.expectedTree);
  });

  it('handles an empty tree (all-empty finalState)', () => {
    // left=0, right=0, parents=[] → "000000"
    expect(parseTreeState('000000')).toEqual({ left: null, right: null, parents: [] });
  });
});
