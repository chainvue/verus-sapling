import { describe, expect, it } from 'vitest';

import { ShieldedInputError } from '../src/errors.js';
import { bytesToHex, hexToBytes, reverseBytes } from '../src/hex.js';
import type { CompactBlock, LightwalletdTransport, TreeState } from '../src/lightwalletd.js';
import { buildShieldedSpend, detectNotes, type DetectedNoteRaw } from '../src/wallet.js';

const NF_UNSPENT = 'aa'.repeat(32);
const NF_SPENT = 'bb'.repeat(32);
const TXID_INTERNAL = '11'.repeat(32);

/** A transport whose one block spends nullifier B and carries two outputs. */
function fakeTransport(overrides: Partial<LightwalletdTransport> = {}): LightwalletdTransport {
  const block: CompactBlock = {
    height: '100',
    hash: new Uint8Array(32),
    vtx: [
      {
        index: '0',
        hash: hexToBytes(TXID_INTERNAL),
        spends: [{ nf: hexToBytes(NF_SPENT) }], // note B has been spent in-range
        outputs: [
          { cmu: new Uint8Array(32), epk: new Uint8Array(32), ciphertext: new Uint8Array(52) },
          { cmu: new Uint8Array(32), epk: new Uint8Array(32), ciphertext: new Uint8Array(52) },
        ],
      },
    ],
  };
  const tree: TreeState = { network: 'test', height: '99', hash: '', time: 0, tree: '000000' };
  return {
    getLatestHeight: async () => 100,
    getTreeState: async () => tree,
    getTransaction: async () => ({ data: new Uint8Array(), height: '0' }),
    async *getBlockRange() {
      yield block;
    },
    sendTransaction: async () => ({ errorCode: 0, errorMessage: '' }),
    ...overrides,
  };
}

describe('detectNotes', () => {
  const twoNotes: DetectedNoteRaw[] = [
    { height: 100, tx_index: 0, output_index: 0, position: 0, value: 100_000_000, recipient_hex: 'ab'.repeat(21) + 'cd', nullifier_hex: NF_UNSPENT },
    { height: 100, tx_index: 0, output_index: 1, position: 1, value: 5, recipient_hex: 'ef'.repeat(21) + '01', nullifier_hex: NF_SPENT },
  ];

  it('excludes notes whose nullifier is spent within the scanned range', async () => {
    const notes = await detectNotes(fakeTransport(), () => twoNotes, {
      key: { extskHex: 'deadbeef' },
      fromHeight: 100,
    });
    expect(notes).toHaveLength(1);
    expect(notes[0]!.nullifierHex).toBe(NF_UNSPENT);
  });

  it('maps value→bigint and resolves the display txid from the block', async () => {
    const notes = await detectNotes(fakeTransport(), () => [twoNotes[0]!], {
      key: { extskHex: 'deadbeef' },
      fromHeight: 100,
    });
    expect(notes[0]!.valueSats).toBe(100_000_000n);
    expect(notes[0]!.txid).toBe(bytesToHex(reverseBytes(hexToBytes(TXID_INTERNAL))));
  });

  it('passes the key through to the prover spec (extsk_hex, not extskHex)', async () => {
    let seen = '';
    await detectNotes(fakeTransport(), (spec) => {
      seen = spec;
      return [];
    }, { key: { extskHex: 'cafe' }, fromHeight: 100 });
    expect(JSON.parse(seen).extsk_hex).toBe('cafe');
    expect(JSON.parse(seen).extskHex).toBeUndefined();
  });

  it('returns [] when toHeight < fromHeight', async () => {
    const notes = await detectNotes(fakeTransport(), () => twoNotes, {
      key: { extskHex: 'x' },
      fromHeight: 200,
      toHeight: 100,
    });
    expect(notes).toEqual([]);
  });

  it('throws on a server-supplied note value that is not a safe integer', async () => {
    const bad: DetectedNoteRaw[] = [{ ...twoNotes[0]!, value: 2 ** 53 + 1 }];
    await expect(
      detectNotes(fakeTransport(), () => bad, { key: { extskHex: 'x' }, fromHeight: 100 }),
    ).rejects.toThrow(/not a safe integer/);
  });

  it('throws when a detected note has no matching block tx (scan/transport mismatch)', async () => {
    const orphan: DetectedNoteRaw[] = [{ ...twoNotes[0]!, height: 999, tx_index: 7 }];
    await expect(
      detectNotes(fakeTransport(), () => orphan, { key: { extskHex: 'x' }, fromHeight: 100 }),
    ).rejects.toThrow(/no matching block tx/);
  });
});

describe('buildShieldedSpend validation (money invariant at the boundary)', () => {
  const note = { txid: TXID_INTERNAL, outputIndex: 0, extskHex: 'deadbeef', valueSats: 100_000_000n };

  it('rejects a spend with no outputs', async () => {
    await expect(
      buildShieldedSpend(fakeTransport(), async () => '', { note, feeSats: 10_000n, shieldedOutputs: [] }),
    ).rejects.toBeInstanceOf(ShieldedInputError);
  });

  it('rejects a negative output value', async () => {
    await expect(
      buildShieldedSpend(fakeTransport(), async () => '', {
        note,
        feeSats: 10_000n,
        shieldedOutputs: [{ address: 'zs1abc', valueSats: -1n }],
      }),
    ).rejects.toThrow(/>= 0/);
  });

  it('rejects a spend that does not conserve value (forgotten change output)', async () => {
    // note 1.0, sends 0.01, fee 0.0001 → 0.9899 unaccounted → would be burned.
    await expect(
      buildShieldedSpend(fakeTransport(), async () => '', {
        note,
        feeSats: 10_000n,
        shieldedOutputs: [{ address: 'zs1abc', valueSats: 1_000_000n }],
      }),
    ).rejects.toThrow(/value conservation failed/);
  });

  it('rejects an implausibly large fee above maxFeeSats', async () => {
    await expect(
      buildShieldedSpend(fakeTransport(), async () => '', {
        note,
        feeSats: 90_000_000n, // 0.9 coin fee — over the 0.1 default cap
        shieldedOutputs: [{ address: 'zs1abc', valueSats: 10_000_000n }],
      }),
    ).rejects.toThrow(/exceeds maxFeeSats/);
  });

  it('passes conservation + fee-cap validation (fails later, not on those checks)', async () => {
    // 0.8 out + 0.2 fee == 1.0 note, and maxFeeSats raised to allow it. The call
    // still rejects downstream on the empty fake getTransaction — proving that
    // conservation/fee/negativity validation did NOT reject.
    await expect(
      buildShieldedSpend(fakeTransport(), async () => 'ok', {
        note,
        feeSats: 20_000_000n,
        maxFeeSats: 50_000_000n,
        shieldedOutputs: [{ address: 'zs1abc', valueSats: 80_000_000n }],
      }),
    ).rejects.not.toThrow(/conservation|maxFeeSats|>= 0/);
  });
});
