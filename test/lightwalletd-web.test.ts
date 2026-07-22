import { describe, expect, it } from 'vitest';

import { bytesToHex, hexToBytes, reverseBytes } from '../src/hex.js';
import {
  blockTxid,
  decodeCompactBlock,
  decodeCompactOutput,
  decodeCompactTx,
} from '../src/browser/lightwalletd-web.js';
import { ProtoWriter } from '../src/browser/protobuf.js';

// Hand-encode CompactTxStreamer messages at their REAL lightwalletd field
// numbers, including decoy fields the decoder must skip (protoVersion, prevHash,
// time, fee). A self-consistent round-trip would pass even with an off-by-one
// field number; the decoys make this test assert the actual wire mapping.

const b = (...n: number[]) => Uint8Array.from(n);

/** CompactSaplingOutput { cmu=1, epk=2, ciphertext=3 } */
function encOutput(cmu: Uint8Array, epk: Uint8Array, ct: Uint8Array): Uint8Array {
  return new ProtoWriter().bytesField(1, cmu).bytesField(2, epk).bytesField(3, ct).finish();
}

/** CompactSaplingSpend { nf=1 } */
function encSpend(nf: Uint8Array): Uint8Array {
  return new ProtoWriter().bytesField(1, nf).finish();
}

/** CompactTx { index=1, hash=2, fee=3(decoy), spends=4, outputs=5 } */
function encTx(opts: {
  index: number;
  hash: Uint8Array;
  spends?: Uint8Array[];
  outputs?: Uint8Array[];
}): Uint8Array {
  const w = new ProtoWriter().varintField(1, opts.index).bytesField(2, opts.hash);
  w.varintField(3, 999); // fee — decoy, must be skipped
  for (const s of opts.spends ?? []) w.messageField(4, encSpend(s));
  for (const o of opts.outputs ?? []) w.messageField(5, o);
  return w.finish();
}

describe('decodeCompactOutput', () => {
  it('maps cmu/epk/ciphertext to fields 1/2/3', () => {
    const cmu = b(0x11, 0x22);
    const epk = b(0x33, 0x44);
    const ct = b(0xaa, 0xbb, 0xcc);
    const out = decodeCompactOutput(encOutput(cmu, epk, ct));
    expect([...out.cmu]).toEqual([...cmu]);
    expect([...out.epk]).toEqual([...epk]);
    expect([...out.ciphertext]).toEqual([...ct]);
  });
});

describe('decodeCompactTx', () => {
  it('decodes index/hash and nested spends + outputs, skipping the fee', () => {
    const hash = new Uint8Array(32).fill(0x77);
    const nf = new Uint8Array(32).fill(0x88);
    const out = encOutput(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), b(0xde, 0xad));
    const tx = decodeCompactTx(encTx({ index: 3, hash, spends: [nf], outputs: [out] }));

    expect(tx.index).toBe('3');
    expect([...tx.hash]).toEqual([...hash]);
    expect(tx.spends).toHaveLength(1);
    expect([...tx.spends[0]!.nf]).toEqual([...nf]);
    expect(tx.outputs).toHaveLength(1);
    expect([...tx.outputs[0]!.ciphertext]).toEqual([0xde, 0xad]);
  });

  it('yields empty spend/output arrays for a shielded-free tx', () => {
    const tx = decodeCompactTx(encTx({ index: 0, hash: new Uint8Array(32) }));
    expect(tx.spends).toEqual([]);
    expect(tx.outputs).toEqual([]);
  });

  it('preserves order and count of multiple outputs', () => {
    const o0 = encOutput(new Uint8Array(32), new Uint8Array(32), b(1));
    const o1 = encOutput(new Uint8Array(32), new Uint8Array(32), b(2));
    const tx = decodeCompactTx(encTx({ index: 1, hash: new Uint8Array(32), outputs: [o0, o1] }));
    expect(tx.outputs).toHaveLength(2);
    expect([...tx.outputs[0]!.ciphertext]).toEqual([1]);
    expect([...tx.outputs[1]!.ciphertext]).toEqual([2]);
  });
});

describe('decodeCompactBlock', () => {
  /** CompactBlock { protoVersion=1(decoy), height=2, hash=3, prevHash=4(decoy), time=5(decoy), vtx=7 } */
  function encBlock(height: number, hash: Uint8Array, vtx: Uint8Array[]): Uint8Array {
    const w = new ProtoWriter().varintField(1, 1); // protoVersion — decoy
    w.varintField(2, height).bytesField(3, hash);
    w.bytesField(4, new Uint8Array(32).fill(0xee)); // prevHash — decoy
    w.varintField(5, 1_700_000_000); // time — decoy
    for (const t of vtx) w.messageField(7, t);
    return w.finish();
  }

  it('reads height from field 2 and hash from field 3, skipping decoys', () => {
    const hash = new Uint8Array(32).fill(0x5e);
    const block = decodeCompactBlock(encBlock(1_157_800, hash, []));
    expect(block.height).toBe('1157800');
    expect([...block.hash]).toEqual([...hash]);
    expect(block.vtx).toEqual([]);
  });

  it('decodes vtx from field 7 in order', () => {
    const txA = encTx({ index: 0, hash: new Uint8Array(32).fill(0xa1) });
    const txB = encTx({
      index: 1,
      hash: new Uint8Array(32).fill(0xb2),
      spends: [new Uint8Array(32).fill(0x99)],
    });
    const block = decodeCompactBlock(encBlock(100, new Uint8Array(32), [txA, txB]));
    expect(block.vtx).toHaveLength(2);
    expect(block.vtx[0]!.index).toBe('0');
    expect(block.vtx[1]!.index).toBe('1');
    expect(block.vtx[1]!.spends).toHaveLength(1);
  });

  it('skips an unknown length-delimited field without corrupting the stream', () => {
    // Inject an unknown field 99 (bytes) before the real height field.
    const w = new ProtoWriter().bytesField(99, b(1, 2, 3, 4)).varintField(2, 42);
    const block = decodeCompactBlock(w.finish());
    expect(block.height).toBe('42');
  });
});

describe('blockTxid', () => {
  it('returns the display (byte-reversed) txid hex', () => {
    const internal = hexToBytes('00'.repeat(31) + 'ff');
    expect(blockTxid({ index: '0', hash: internal, spends: [], outputs: [] })).toBe(
      bytesToHex(reverseBytes(internal)),
    );
    expect(blockTxid({ index: '0', hash: internal, spends: [], outputs: [] })).toMatch(/^ff0+$/);
  });
});
