/**
 * lightwalletd gRPC adapter — the production data source for shielded spends.
 *
 * Replaces the daemon-RPC "gather" shortcut used in testing. Talks to a
 * `lightwalletd` (VerusCoin/lightwalletd) over gRPC and supplies everything the
 * prover needs without a full node on the signing host:
 *  - getTreeState(h)   → the note-commitment tree at height h (witness/anchor base)
 *  - getBlockRange     → compact blocks (cmus for witness position + note scanning)
 *  - getTransaction    → full raw tx (to extract the full output of a note to spend)
 *  - sendTransaction   → broadcast the signed tx
 *
 * Verified against a live Verus testnet lightwalletd: GetLightdInfo, GetTreeState
 * (238-byte tree = the finalState our witness builder parses), GetBlockRange
 * (cmus + nullifiers), and GetTransaction (full raw tx) all return correctly.
 *
 * gRPC over Node: uses @grpc/grpc-js + @grpc/proto-loader with the `.proto`
 * files in `../proto`. A *browser* consumer needs a gRPC-web proxy in front of
 * lightwalletd; a Node/server consumer connects directly (optionally over an
 * SSH tunnel in dev).
 */

import { fileURLToPath } from 'node:url';
import * as path from 'node:path';
import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';

const PROTO_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'proto');

/** TreeState (from lightwalletd, derived from z_gettreestate). `tree` is the
 *  commitment-tree finalState hex our witness builder parses. */
export interface TreeState {
  network: string;
  height: string;
  hash: string;
  time: number;
  tree: string; // hex
}

/** One Sapling output in a compact block. */
export interface CompactOutput {
  cmu: Uint8Array;
  epk: Uint8Array;
  ciphertext: Uint8Array; // compact (enough for trial-decryption note detection)
}
export interface CompactTx {
  index: string;
  hash: Uint8Array; // txid, internal byte order
  spends: { nf: Uint8Array }[];
  outputs: CompactOutput[];
}
export interface CompactBlock {
  height: string;
  hash: Uint8Array;
  vtx: CompactTx[];
}

export interface LightdInfo {
  chainName: string;
  consensusBranchId: string;
  blockHeight: string;
  saplingActivationHeight: string;
  estimatedHeight: string;
}

/**
 * The minimal lightwalletd RPC surface the shielded orchestration (`../wallet`)
 * depends on. Abstracting it keeps the wallet logic free of any concrete
 * transport: `LightwalletdClient` implements it over Node `@grpc/grpc-js`; a
 * browser consumer implements the same interface over a gRPC-web proxy.
 */
export interface LightwalletdTransport {
  getLatestHeight(): Promise<number>;
  getTreeState(height: number): Promise<TreeState>;
  getTransaction(txidDisplayHex: string): Promise<{ data: Uint8Array; height: string }>;
  getBlockRange(start: number, end: number): AsyncGenerator<CompactBlock>;
  sendTransaction(txHex: string): Promise<{ errorCode: number; errorMessage: string }>;
}

/** Thin, typed client over the lightwalletd CompactTxStreamer service. */
export class LightwalletdClient implements LightwalletdTransport {
  private readonly svc: grpc.Client & Record<string, any>;

  /** @param target host:port of lightwalletd (e.g. "localhost:9077" over an SSH tunnel). */
  constructor(target: string, credentials?: grpc.ChannelCredentials) {
    const def = protoLoader.loadSync('service.proto', {
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true,
      includeDirs: [PROTO_DIR],
    });
    const pkg = grpc.loadPackageDefinition(def) as any;
    const Ctor = pkg.cash.z.wallet.sdk.rpc.CompactTxStreamer;
    this.svc = new Ctor(target, credentials ?? grpc.credentials.createInsecure());
  }

  private unary<T>(method: string, arg: unknown): Promise<T> {
    return new Promise((resolve, reject) =>
      this.svc[method](arg, (err: grpc.ServiceError | null, res: T) =>
        err ? reject(err) : resolve(res),
      ),
    );
  }

  getLightdInfo(): Promise<LightdInfo> {
    return this.unary('GetLightdInfo', {});
  }

  getLatestHeight(): Promise<number> {
    return this.unary<{ height: string }>('GetLatestBlock', {}).then((b) => Number(b.height));
  }

  /** Tree state at `height` — the witness/anchor base. */
  getTreeState(height: number): Promise<TreeState> {
    return this.unary('GetTreeState', { height });
  }

  /** Full raw transaction by txid (display-order hex string). Needed to extract
   *  the full Sapling output (cv/cmu/epk/enc/out/proof) of a note being spent. */
  getTransaction(txidDisplayHex: string): Promise<{ data: Uint8Array; height: string }> {
    const hash = Buffer.from(txidDisplayHex, 'hex').reverse(); // internal byte order
    return this.unary('GetTransaction', { hash });
  }

  /** Stream compact blocks in [start, end]. Used for note detection
   *  (trial-decrypt outputs) and to collect a block's ordered cmus for witness
   *  construction. */
  async *getBlockRange(start: number, end: number): AsyncGenerator<CompactBlock> {
    const stream = this.svc.GetBlockRange({ start: { height: start }, end: { height: end } });
    try {
      for await (const block of stream as AsyncIterable<CompactBlock>) {
        yield block;
      }
    } finally {
      stream.cancel?.();
    }
  }

  /** Broadcast a signed transaction (hex). Returns {errorCode, errorMessage}. */
  sendTransaction(txHex: string): Promise<{ errorCode: number; errorMessage: string }> {
    return this.unary('SendTransaction', { data: Buffer.from(txHex, 'hex'), height: 0 });
  }

  close(): void {
    this.svc.close();
  }
}
