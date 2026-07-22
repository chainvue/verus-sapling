//! Reconstruct a transaction from `decoderawtransaction` JSON and compute our
//! ZIP-243 sighash over it. Shared by the `verify_golden` example (which also
//! runs the zk/signature verification) and the `golden_sighash` regression test
//! (which asserts the sighash bytes against baked-in, cryptographically-confirmed
//! constants — no proving params needed).
//!
//! NOTE ON BYTE ORDER: `decoderawtransaction` DISPLAYS the 32-byte fields
//! (spend cv/anchor/nullifier/rk and output cv/cmu/ephemeralKey) byte-REVERSED;
//! transparent txids are also reversed. Ciphertexts, proofs, and signatures are
//! raw. This module reverses exactly those fields back to wire order so the
//! sighash description bytes match what the daemon signed. This is the opposite
//! convention from `json_api.rs`, which takes RAW wire order from the TS layer.

use serde_json::Value;

use crate::tx::{shielded_sighash, TxIn, TxOut};

fn h(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| format!("bad hex: {e}"))
}
fn h32(s: &str) -> Result<[u8; 32], String> {
    let b = h(s)?;
    if b.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", b.len()));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok(a)
}
fn h64(s: &str) -> Result<[u8; 64], String> {
    let b = h(s)?;
    if b.len() != 64 {
        return Err(format!("expected 64 bytes, got {}", b.len()));
    }
    let mut a = [0u8; 64];
    a.copy_from_slice(&b);
    Ok(a)
}
fn rev32(mut a: [u8; 32]) -> [u8; 32] {
    a.reverse();
    a
}
fn str_at<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field `{key}`"))
}
/// Sats from a `decoderawtransaction` float coin value. The golden vectors carry
/// exact 8-decimal values, so `* 1e8` round-trips without loss here.
fn coins_to_sats(v: f64) -> i64 {
    (v * 1e8).round() as i64
}

/// A shielded spend in wire order, plus the sighash description bytes.
pub struct GoldenSpend {
    pub cv: [u8; 32],
    pub anchor: [u8; 32],
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub proof: Vec<u8>,
    pub auth_sig: [u8; 64],
}

/// A shielded output in wire order (incl. ciphertexts needed for the sighash).
pub struct GoldenOut {
    pub cv: [u8; 32],
    pub cmu: [u8; 32],
    pub epk: [u8; 32],
    pub enc_ciphertext: Vec<u8>,
    pub out_ciphertext: Vec<u8>,
    pub proof: Vec<u8>,
}

/// A fully decoded golden transaction, in the byte order our serializer uses.
pub struct GoldenTx {
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
    pub expiry_height: u32,
    pub value_balance: i64,
    pub spends: Vec<GoldenSpend>,
    pub outs: Vec<GoldenOut>,
    pub binding_sig: [u8; 64],
}

impl GoldenTx {
    /// Parse a `decoderawtransaction` JSON object.
    pub fn from_decoded_json(d: &Value) -> Result<Self, String> {
        let inputs = match d["vin"].as_array() {
            None => vec![],
            Some(a) => a
                .iter()
                .map(|i| {
                    Ok(TxIn {
                        txid_internal: rev32(h32(str_at(i, "txid")?)?),
                        vout: i["vout"].as_u64().ok_or("vin.vout")? as u32,
                        sequence: i["sequence"].as_u64().ok_or("vin.sequence")? as u32,
                    })
                })
                .collect::<Result<_, String>>()?,
        };
        let outputs = match d["vout"].as_array() {
            None => vec![],
            Some(a) => a
                .iter()
                .map(|o| {
                    Ok(TxOut {
                        value: coins_to_sats(o["value"].as_f64().ok_or("vout.value")?) as u64,
                        script_pubkey: h(str_at(&o["scriptPubKey"], "hex")?)?,
                    })
                })
                .collect::<Result<_, String>>()?,
        };
        let spends = match d["vShieldedSpend"].as_array() {
            None => vec![],
            Some(a) => a
                .iter()
                .map(|s| {
                    Ok(GoldenSpend {
                        cv: rev32(h32(str_at(s, "cv")?)?),
                        anchor: rev32(h32(str_at(s, "anchor")?)?),
                        nullifier: rev32(h32(str_at(s, "nullifier")?)?),
                        rk: rev32(h32(str_at(s, "rk")?)?),
                        proof: h(str_at(s, "proof")?)?,
                        auth_sig: h64(str_at(s, "spendAuthSig")?)?,
                    })
                })
                .collect::<Result<_, String>>()?,
        };
        let outs = match d["vShieldedOutput"].as_array() {
            None => vec![],
            Some(a) => a
                .iter()
                .map(|o| {
                    Ok(GoldenOut {
                        cv: rev32(h32(str_at(o, "cv")?)?),
                        cmu: rev32(h32(str_at(o, "cmu")?)?),
                        epk: rev32(h32(str_at(o, "ephemeralKey")?)?),
                        enc_ciphertext: h(str_at(o, "encCiphertext")?)?,
                        out_ciphertext: h(str_at(o, "outCiphertext")?)?,
                        proof: h(str_at(o, "proof")?)?,
                    })
                })
                .collect::<Result<_, String>>()?,
        };
        Ok(GoldenTx {
            inputs,
            outputs,
            lock_time: d["locktime"].as_u64().unwrap_or(0) as u32,
            expiry_height: d["expiryheight"].as_u64().ok_or("expiryheight")? as u32,
            value_balance: coins_to_sats(d["valueBalance"].as_f64().ok_or("valueBalance")?),
            spends,
            outs,
            binding_sig: h64(str_at(d, "bindingSig")?)?,
        })
    }

    /// Per-spend sighash description: cv || anchor || nullifier || rk || proof.
    pub fn spend_descs(&self) -> Vec<Vec<u8>> {
        self.spends
            .iter()
            .map(|s| {
                let mut v = Vec::new();
                v.extend_from_slice(&s.cv);
                v.extend_from_slice(&s.anchor);
                v.extend_from_slice(&s.nullifier);
                v.extend_from_slice(&s.rk);
                v.extend_from_slice(&s.proof);
                v
            })
            .collect()
    }

    /// Per-output sighash description: cv || cmu || epk || enc || out || proof.
    pub fn out_descs(&self) -> Vec<Vec<u8>> {
        self.outs
            .iter()
            .map(|o| {
                let mut v = Vec::new();
                v.extend_from_slice(&o.cv);
                v.extend_from_slice(&o.cmu);
                v.extend_from_slice(&o.epk);
                v.extend_from_slice(&o.enc_ciphertext);
                v.extend_from_slice(&o.out_ciphertext);
                v.extend_from_slice(&o.proof);
                v
            })
            .collect()
    }

    /// Our ZIP-243 sighash over this transaction for `branch_id`.
    pub fn sighash(&self, branch_id: u32) -> [u8; 32] {
        shielded_sighash(
            branch_id,
            &self.inputs,
            &self.outputs,
            self.lock_time,
            self.expiry_height,
            self.value_balance,
            &self.spend_descs(),
            &self.out_descs(),
        )
    }
}
