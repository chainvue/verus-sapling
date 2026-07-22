import { describe, expect, it } from 'vitest';

import { encodeFrame, FrameParser } from '../src/browser/grpcweb.js';

describe('gRPC-web framing', () => {
  it('encodeFrame prefixes a 5-byte header (flag + big-endian length)', () => {
    const msg = Uint8Array.from([1, 2, 3, 4]);
    const frame = encodeFrame(msg);
    expect(frame.length).toBe(9);
    expect(frame[0]).toBe(0x00); // data frame
    expect([...frame.subarray(1, 5)]).toEqual([0, 0, 0, 4]); // BE length
    expect([...frame.subarray(5)]).toEqual([1, 2, 3, 4]);
  });

  it('FrameParser recovers a single frame', () => {
    const msg = Uint8Array.from([9, 8, 7]);
    const frames = new FrameParser().push(encodeFrame(msg));
    expect(frames).toHaveLength(1);
    expect(frames[0]!.trailer).toBe(false);
    expect([...frames[0]!.payload]).toEqual([9, 8, 7]);
  });

  it('reassembles a frame split across chunk boundaries', () => {
    const full = encodeFrame(Uint8Array.from([10, 20, 30, 40, 50]));
    const parser = new FrameParser();
    expect(parser.push(full.subarray(0, 3))).toHaveLength(0); // header incomplete
    expect(parser.push(full.subarray(3, 7))).toHaveLength(0); // body incomplete
    const frames = parser.push(full.subarray(7));
    expect(frames).toHaveLength(1);
    expect([...frames[0]!.payload]).toEqual([10, 20, 30, 40, 50]);
  });

  it('yields multiple frames from one buffer and flags the trailer', () => {
    const data = encodeFrame(Uint8Array.from([1]));
    const trailer = new Uint8Array(5 + 3);
    trailer[0] = 0x80; // trailer flag
    new DataView(trailer.buffer).setUint32(1, 3, false);
    trailer.set(Uint8Array.from([0x61, 0x62, 0x63]), 5); // "abc"
    const frames = new FrameParser().push(new Uint8Array([...data, ...trailer]));
    expect(frames).toHaveLength(2);
    expect(frames[0]!.trailer).toBe(false);
    expect(frames[1]!.trailer).toBe(true);
    expect([...frames[1]!.payload]).toEqual([0x61, 0x62, 0x63]);
  });
});
