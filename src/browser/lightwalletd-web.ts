/**
 * Browser lightwalletd client — a `LightwalletdTransport` over gRPC-web (`fetch`)
 * instead of Node `@grpc/grpc-js`. Point it at a gRPC-web proxy (grpcwebproxy /
 * Envoy) in front of lightwalletd; over an SSH forward that is
 * `http://localhost:8080`, in production a TLS tunnel hostname.
 *
 * Same interface as the Node `LightwalletdClient`, so `../wallet`'s
 * `detectNotes` / `buildShieldedSpend` work unchanged in the extension. Message
 * (de)serialization is hand-coded against the CompactTxStreamer protobuf field
 * numbers with the minimal `./protobuf` codec — no protobuf runtime dependency.
 */

import { bytesToHex, hexToBytes, reverseBytes } from '../hex.js';
import type {
  CompactBlock,
  CompactOutput,
  CompactTx,
  LightwalletdTransport,
  TreeState,
} from '../lightwalletd.js';
import { ProtoReader, ProtoWriter } from './protobuf.js';
import { serverStream, unary } from './grpcweb.js';

const EMPTY = new Uint8Array(0);

/** BlockID { height=1 } — request for GetTreeState / nested in BlockRange. */
function blockId(height: number): Uint8Array {
  return new ProtoWriter().varintField(1, height).finish();
}

/** Browser (gRPC-web) implementation of the lightwalletd transport. */
export class LightwalletdWebClient implements LightwalletdTransport {
  /** @param baseUrl gRPC-web proxy origin, e.g. "http://localhost:8080". */
  constructor(private readonly baseUrl: string) {}

  async getLatestHeight(): Promise<number> {
    // GetLatestBlock(ChainSpec{}) -> BlockID{ height=1 }
    const res = await unary(this.baseUrl, 'GetLatestBlock', EMPTY);
    const r = new ProtoReader(res);
    let height = 0;
    while (!r.done) {
      const { field, wire } = r.tag();
      if (field === 1 && wire === 0) height = r.varint();
      else r.skip(wire);
    }
    return height;
  }

  async getTreeState(height: number): Promise<TreeState> {
    // GetTreeState(BlockID{height}) -> TreeState{ network=1,height=2,hash=3,time=4,tree=5 }
    const res = await unary(this.baseUrl, 'GetTreeState', blockId(height));
    const r = new ProtoReader(res);
    const out: TreeState = { network: '', height: '0', hash: '', time: 0, tree: '' };
    while (!r.done) {
      const { field, wire } = r.tag();
      if (field === 1 && wire === 2) out.network = r.string();
      else if (field === 2 && wire === 0) out.height = String(r.varint());
      else if (field === 3 && wire === 2) out.hash = r.string();
      else if (field === 4 && wire === 0) out.time = r.varint();
      else if (field === 5 && wire === 2) out.tree = r.string();
      else r.skip(wire);
    }
    return out;
  }

  async getTransaction(txidDisplayHex: string): Promise<{ data: Uint8Array; height: string }> {
    // GetTransaction(TxFilter{ hash=3 }) -> RawTransaction{ data=1, height=2 }
    const hashInternal = reverseBytes(hexToBytes(txidDisplayHex));
    const req = new ProtoWriter().bytesField(3, hashInternal).finish();
    const res = await unary(this.baseUrl, 'GetTransaction', req);
    const r = new ProtoReader(res);
    let data = EMPTY;
    let height = '0';
    while (!r.done) {
      const { field, wire } = r.tag();
      if (field === 1 && wire === 2) data = Uint8Array.from(r.bytes());
      else if (field === 2 && wire === 0) height = String(r.varint());
      else r.skip(wire);
    }
    return { data, height };
  }

  async *getBlockRange(start: number, end: number): AsyncGenerator<CompactBlock> {
    // GetBlockRange(BlockRange{ start=1:BlockID, end=2:BlockID }) -> stream CompactBlock
    const req = new ProtoWriter().messageField(1, blockId(start)).messageField(2, blockId(end)).finish();
    for await (const msg of serverStream(this.baseUrl, 'GetBlockRange', req)) {
      yield decodeCompactBlock(msg);
    }
  }

  async sendTransaction(txHex: string): Promise<{ errorCode: number; errorMessage: string }> {
    // SendTransaction(RawTransaction{ data=1, height=2 }) -> SendResponse{ errorCode=1, errorMessage=2 }
    const req = new ProtoWriter().bytesField(1, hexToBytes(txHex)).varintField(2, 0).finish();
    const res = await unary(this.baseUrl, 'SendTransaction', req);
    const r = new ProtoReader(res);
    let errorCode = 0;
    let errorMessage = '';
    while (!r.done) {
      const { field, wire } = r.tag();
      if (field === 1 && wire === 0) errorCode = r.varint();
      else if (field === 2 && wire === 2) errorMessage = r.string();
      else r.skip(wire);
    }
    return { errorCode, errorMessage };
  }

  /** gRPC-web has no channel to close; provided for interface parity. */
  close(): void {
    /* no-op */
  }
}

function decodeCompactOutput(msg: Uint8Array): CompactOutput {
  const r = new ProtoReader(msg);
  const out: CompactOutput = { cmu: EMPTY, epk: EMPTY, ciphertext: EMPTY };
  while (!r.done) {
    const { field, wire } = r.tag();
    if (field === 1 && wire === 2) out.cmu = Uint8Array.from(r.bytes());
    else if (field === 2 && wire === 2) out.epk = Uint8Array.from(r.bytes());
    else if (field === 3 && wire === 2) out.ciphertext = Uint8Array.from(r.bytes());
    else r.skip(wire);
  }
  return out;
}

function decodeCompactTx(msg: Uint8Array): CompactTx {
  const r = new ProtoReader(msg);
  const tx: CompactTx = { index: '0', hash: EMPTY, spends: [], outputs: [] };
  while (!r.done) {
    const { field, wire } = r.tag();
    if (field === 1 && wire === 0) tx.index = String(r.varint());
    else if (field === 2 && wire === 2) tx.hash = Uint8Array.from(r.bytes());
    else if (field === 4 && wire === 2) {
      // CompactSpend{ nf=1 }
      const sr = new ProtoReader(r.bytes());
      let nf = EMPTY;
      while (!sr.done) {
        const t = sr.tag();
        if (t.field === 1 && t.wire === 2) nf = Uint8Array.from(sr.bytes());
        else sr.skip(t.wire);
      }
      tx.spends.push({ nf });
    } else if (field === 5 && wire === 2) {
      tx.outputs.push(decodeCompactOutput(r.bytes()));
    } else r.skip(wire);
  }
  return tx;
}

function decodeCompactBlock(msg: Uint8Array): CompactBlock {
  const r = new ProtoReader(msg);
  const block: CompactBlock = { height: '0', hash: EMPTY, vtx: [] };
  while (!r.done) {
    const { field, wire } = r.tag();
    if (field === 2 && wire === 0) block.height = String(r.varint());
    else if (field === 3 && wire === 2) block.hash = Uint8Array.from(r.bytes());
    else if (field === 7 && wire === 2) block.vtx.push(decodeCompactTx(r.bytes()));
    else r.skip(wire);
  }
  return block;
}

/** Convenience for hex txids from a decoded block (display/big-endian order). */
export function blockTxid(tx: CompactTx): string {
  return bytesToHex(reverseBytes(tx.hash));
}
