/**
 * Minimal protobuf3 reader/writer — just the wire-format primitives the
 * lightwalletd message codecs need (varint, length-delimited bytes/strings,
 * embedded messages). Zero dependency, to keep the browser transport as light as
 * the rest of the package.
 *
 * Only wire types 0 (varint) and 2 (length-delimited) are used by the
 * CompactTxStreamer messages we touch; unknown fields are skipped. Field values
 * stay within 2^53 (heights, zatoshi), so plain `number` varints are safe here.
 */

const WIRE_VARINT = 0;
const WIRE_I64 = 1;
const WIRE_LEN = 2;
const WIRE_I32 = 5;

/** Sequential reader over a protobuf message body. */
export class ProtoReader {
  private off = 0;
  constructor(private readonly buf: Uint8Array) {}

  get done(): boolean {
    return this.off >= this.buf.length;
  }

  varint(): number {
    let shift = 0;
    let result = 0;
    for (;;) {
      if (this.off >= this.buf.length) throw new RangeError('protobuf: varint past end');
      const b = this.buf[this.off++]!;
      result += (b & 0x7f) * 2 ** shift;
      if ((b & 0x80) === 0) break;
      shift += 7;
      if (shift > 49) throw new RangeError('protobuf: varint too long');
    }
    // Values are server-controlled; above 2^53 float64 rounds silently. Reject
    // rather than return an imprecise number (guards the money/height crossing).
    if (result > Number.MAX_SAFE_INTEGER) {
      throw new RangeError('protobuf: varint exceeds safe integer range');
    }
    return result;
  }

  bytes(): Uint8Array {
    const len = this.varint();
    if (this.off + len > this.buf.length) throw new RangeError('protobuf: bytes past end');
    const out = this.buf.subarray(this.off, this.off + len);
    this.off += len;
    return out;
  }

  string(): string {
    return new TextDecoder().decode(this.bytes());
  }

  /** Read a field tag → { field, wire }. */
  tag(): { field: number; wire: number } {
    const key = this.varint();
    return { field: key >>> 3, wire: key & 0x7 };
  }

  /** Skip a field of the given wire type (unknown fields). */
  skip(wire: number): void {
    switch (wire) {
      case WIRE_VARINT:
        this.varint();
        break;
      case WIRE_LEN:
        this.bytes();
        break;
      case WIRE_I64:
        this.off += 8;
        break;
      case WIRE_I32:
        this.off += 4;
        break;
      default:
        throw new RangeError(`protobuf: unknown wire type ${wire}`);
    }
  }
}

/** Accumulating writer for a protobuf message body. */
export class ProtoWriter {
  private readonly chunks: number[] = [];

  private pushVarint(n: number): void {
    let v = n;
    while (v > 0x7f) {
      this.chunks.push((v & 0x7f) | 0x80);
      v = Math.floor(v / 128);
    }
    this.chunks.push(v & 0x7f);
  }

  private tag(field: number, wire: number): void {
    this.pushVarint(field * 8 + wire);
  }

  varintField(field: number, value: number): this {
    this.tag(field, WIRE_VARINT);
    this.pushVarint(value);
    return this;
  }

  bytesField(field: number, value: Uint8Array): this {
    this.tag(field, WIRE_LEN);
    this.pushVarint(value.length);
    for (const b of value) this.chunks.push(b);
    return this;
  }

  /** Embed a nested message (its already-serialized bytes) as a length-delimited field. */
  messageField(field: number, value: Uint8Array): this {
    return this.bytesField(field, value);
  }

  finish(): Uint8Array {
    return Uint8Array.from(this.chunks);
  }
}
