import { describe, expect, it } from 'vitest';

import { ProtoReader, ProtoWriter } from '../src/browser/protobuf.js';

describe('protobuf varint', () => {
  it('round-trips boundary values', () => {
    for (const n of [0, 1, 127, 128, 16_383, 16_384, 2_097_151, 1_991_772_603, 2 ** 40]) {
      const w = new ProtoWriter().varintField(1, n).finish();
      const r = new ProtoReader(w);
      const { field, wire } = r.tag();
      expect(field).toBe(1);
      expect(wire).toBe(0);
      expect(r.varint()).toBe(n);
    }
  });

  it('throws on a varint beyond the safe-integer range (no silent float rounding)', () => {
    // 8-byte varint ≈ 2^56, well past 2^53 — server could craft this in a value field.
    const overflow = Uint8Array.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);
    expect(() => new ProtoReader(overflow).varint()).toThrow(/safe integer/);
  });
});

describe('protobuf message round-trips', () => {
  it('encodes/decodes a BlockID { height=1 } exactly as GetTreeState expects', () => {
    const msg = new ProtoWriter().varintField(1, 1_157_536).finish();
    const r = new ProtoReader(msg);
    let height = 0;
    while (!r.done) {
      const { field, wire } = r.tag();
      if (field === 1 && wire === 0) height = r.varint();
      else r.skip(wire);
    }
    expect(height).toBe(1_157_536);
  });

  it('encodes/decodes a nested BlockRange { start, end }', () => {
    const start = new ProtoWriter().varintField(1, 100).finish();
    const end = new ProtoWriter().varintField(1, 200).finish();
    const range = new ProtoWriter().messageField(1, start).messageField(2, end).finish();

    const r = new ProtoReader(range);
    const heights: Record<number, number> = {};
    while (!r.done) {
      const { field, wire } = r.tag();
      if (wire === 2) {
        const inner = new ProtoReader(r.bytes());
        const t = inner.tag();
        heights[field] = inner.varint();
        expect(t.field).toBe(1);
      } else r.skip(wire);
    }
    expect(heights).toEqual({ 1: 100, 2: 200 });
  });

  it('round-trips bytes and string fields', () => {
    const data = Uint8Array.from([0xde, 0xad, 0xbe, 0xef]);
    const msg = new ProtoWriter().bytesField(1, data).varintField(2, 0).finish();
    const r = new ProtoReader(msg);
    let got: Uint8Array | undefined;
    let h = -1;
    while (!r.done) {
      const { field, wire } = r.tag();
      if (field === 1 && wire === 2) got = Uint8Array.from(r.bytes());
      else if (field === 2 && wire === 0) h = r.varint();
      else r.skip(wire);
    }
    expect(got).toEqual(data);
    expect(h).toBe(0);
  });

  it('skips unknown fields without corrupting the stream', () => {
    const msg = new ProtoWriter()
      .varintField(3, 42) // unknown to the reader below
      .bytesField(1, Uint8Array.from([1, 2, 3]))
      .finish();
    const r = new ProtoReader(msg);
    let payload: Uint8Array | undefined;
    while (!r.done) {
      const { field, wire } = r.tag();
      if (field === 1 && wire === 2) payload = Uint8Array.from(r.bytes());
      else r.skip(wire);
    }
    expect(payload).toEqual(Uint8Array.from([1, 2, 3]));
  });
});
