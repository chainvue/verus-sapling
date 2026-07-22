/**
 * gRPC-web transport over `fetch` — the browser's way to reach a native gRPC
 * service (lightwalletd) through a gRPC-web proxy (grpcwebproxy / Envoy).
 *
 * Wire format: each message is a 5-byte-prefixed frame — 1 flag byte (0 = data,
 * 0x80 = trailer) + 4-byte big-endian length + payload. A unary response is one
 * data frame then a trailer frame; a server-streaming response is many data
 * frames then a trailer. The trailer payload is ASCII `grpc-status`/`grpc-message`
 * headers; a non-zero status is surfaced as an error.
 *
 * Uses `application/grpc-web+proto` (binary), which grpcwebproxy serves and
 * Cloudflare tunnels pass through unchanged. Works in the browser and under Node
 * (18+ has `fetch`), which is how the transport is tested headlessly.
 */

const SERVICE = 'cash.z.wallet.sdk.rpc.CompactTxStreamer';

/** Encode one protobuf message as a gRPC-web data frame. */
function encodeFrame(msg: Uint8Array): Uint8Array {
  const frame = new Uint8Array(5 + msg.length);
  frame[0] = 0x00; // data frame, uncompressed
  new DataView(frame.buffer).setUint32(1, msg.length, false); // big-endian length
  frame.set(msg, 5);
  return frame;
}

/** A parsed gRPC-web frame. */
interface Frame {
  trailer: boolean;
  payload: Uint8Array;
}

/**
 * Incremental frame parser: feed it bytes, it yields complete frames and keeps
 * any partial remainder for the next chunk (needed for streaming across network
 * chunk boundaries).
 */
class FrameParser {
  private buf = new Uint8Array(0);

  push(chunk: Uint8Array): Frame[] {
    const merged = new Uint8Array(this.buf.length + chunk.length);
    merged.set(this.buf, 0);
    merged.set(chunk, this.buf.length);
    this.buf = merged;

    const frames: Frame[] = [];
    for (;;) {
      if (this.buf.length < 5) break;
      const flag = this.buf[0]!;
      const len = new DataView(this.buf.buffer, this.buf.byteOffset, this.buf.byteLength).getUint32(1, false);
      if (this.buf.length < 5 + len) break;
      frames.push({ trailer: (flag & 0x80) !== 0, payload: this.buf.subarray(5, 5 + len) });
      this.buf = this.buf.subarray(5 + len);
    }
    return frames;
  }
}

/** Parse a trailer frame's ASCII payload; throw if grpc-status is non-zero. */
function checkTrailer(payload: Uint8Array): void {
  const text = new TextDecoder().decode(payload);
  const status = /grpc-status:\s*(\d+)/i.exec(text);
  if (status && status[1] !== '0') {
    const msg = /grpc-message:\s*(.*)/i.exec(text);
    throw new Error(`gRPC error ${status[1]}${msg ? `: ${decodeURIComponent(msg[1]!.trim())}` : ''}`);
  }
}

async function post(baseUrl: string, method: string, reqMsg: Uint8Array): Promise<Response> {
  const url = `${baseUrl.replace(/\/$/, '')}/${SERVICE}/${method}`;
  // A stale keep-alive connection (e.g. closed by the proxy while the client was
  // busy proving) surfaces as a fetch rejection, NOT an HTTP status — retry once
  // on a fresh connection. gRPC application errors arrive in the trailer, so they
  // never reach this catch; only genuine transport failures do. Broadcasting is
  // idempotent (a duplicate tx is simply rejected), so retrying is safe.
  let lastErr: unknown;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/grpc-web+proto',
          'X-Grpc-Web': '1',
          Accept: 'application/grpc-web+proto',
        },
        // A Uint8Array is a valid fetch body; the cast sidesteps TS 5.7+
        // Uint8Array<ArrayBufferLike> vs BodyInit generic friction.
        body: encodeFrame(reqMsg) as unknown as BodyInit,
      });
      if (!res.ok) throw new Error(`gRPC-web HTTP ${res.status} for ${method}`);
      if (!res.body) throw new Error(`gRPC-web: no response body for ${method}`);
      return res;
    } catch (e) {
      lastErr = e;
      // Only retry genuine transport failures (fetch rejections), not HTTP errors.
      if (e instanceof Error && e.message.startsWith('gRPC-web HTTP')) throw e;
    }
  }
  throw lastErr;
}

/** Unary call: returns the single response message bytes. */
export async function unary(baseUrl: string, method: string, reqMsg: Uint8Array): Promise<Uint8Array> {
  const res = await post(baseUrl, method, reqMsg);
  const buf = new Uint8Array(await res.arrayBuffer());
  const frames = new FrameParser().push(buf);
  let data: Uint8Array | undefined;
  for (const f of frames) {
    if (f.trailer) checkTrailer(f.payload);
    else data ??= f.payload;
  }
  if (!data) throw new Error(`gRPC-web: no data frame for ${method}`);
  return data;
}

/** Server-streaming call: yields each response message's bytes as it arrives. */
export async function* serverStream(
  baseUrl: string,
  method: string,
  reqMsg: Uint8Array,
): AsyncGenerator<Uint8Array> {
  const res = await post(baseUrl, method, reqMsg);
  const reader = res.body!.getReader();
  const parser = new FrameParser();
  let trailerErr: Error | undefined;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      for (const f of parser.push(value)) {
        if (f.trailer) {
          try {
            checkTrailer(f.payload);
          } catch (e) {
            trailerErr = e as Error;
          }
        } else {
          yield f.payload;
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
  if (trailerErr) throw trailerErr;
}
