//! JSON spec -> transaction builders. Shared by the CLI examples and the wasm
//! boundary so both accept the same request shape. All 32-byte fields in the
//! spec are RAW wire order (the TS/orchestration layer reverses
//! decoderawtransaction display and parses the tree state).
//!
//! Verus has Canopy inactive on testnet, so ZIP-212 enforcement is Off.

use sapling_crypto::circuit::{OutputParameters, SpendParameters};
use sapling_crypto::note_encryption::Zip212Enforcement;
use sapling_crypto::zip32::DiversifiableFullViewingKey;
use serde_json::{json, Value};
use zcash_note_encryption::COMPACT_NOTE_SIZE;

use crate::scan::{detect_notes, read_note, CompactOutput, FullOutput, TreeStateBefore};
use crate::tx::{TxIn, TxOut};
use crate::z2z::{build_zspend_tx, SpendInput, Z2zOutput};
use crate::{build_t2z_unsigned_tx, ShieldOutput};

const ZIP212: Zip212Enforcement = Zip212Enforcement::Off;

fn h(v: &Value, field: &str) -> Result<Vec<u8>, String> {
    hex::decode(v.as_str().ok_or_else(|| format!("{field}: expected hex string"))?)
        .map_err(|e| format!("{field}: bad hex: {e}"))
}
fn h32(v: &Value, field: &str) -> Result<[u8; 32], String> {
    let b = h(v, field)?;
    if b.len() != 32 {
        return Err(format!("{field}: expected 32 bytes, got {}", b.len()));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok(a)
}
fn opt32(v: &Value) -> Result<Option<[u8; 32]>, String> {
    if v.is_null() {
        Ok(None)
    } else {
        Ok(Some(h32(v, "tree node")?))
    }
}
fn u64f(v: &Value, field: &str) -> Result<u64, String> {
    v.as_u64().ok_or_else(|| format!("{field}: expected u64"))
}
fn memo512(v: &Value) -> [u8; 512] {
    let mut memo = [0u8; 512];
    let m = v.as_str().unwrap_or("").as_bytes();
    let n = m.len().min(512);
    memo[..n].copy_from_slice(&m[..n]);
    memo
}

/// Memo for a shielded output. Prefers `memo_hex` (raw bytes, e.g. a structured
/// / binary memo per ZIP-302) if present; otherwise falls back to `memo` (a
/// UTF-8 text string). `memo_hex` must be <= 512 bytes.
fn memo_field(out: &Value) -> Result<[u8; 512], String> {
    if let Some(hx) = out.get("memo_hex").and_then(|v| v.as_str()) {
        let b = hex::decode(hx).map_err(|e| format!("memo_hex: bad hex: {e}"))?;
        if b.len() > 512 {
            return Err(format!("memo_hex: {} bytes > 512", b.len()));
        }
        let mut memo = [0u8; 512];
        memo[..b.len()].copy_from_slice(&b);
        Ok(memo)
    } else {
        Ok(memo512(&out["memo"]))
    }
}
fn recipient43(v: &Value) -> Result<[u8; 43], String> {
    let b = h(v, "recipient_hex")?;
    if b.len() != 43 {
        return Err(format!("recipient_hex: expected 43 bytes, got {}", b.len()));
    }
    let mut a = [0u8; 43];
    a.copy_from_slice(&b);
    Ok(a)
}

/// t->z spec: { inputs:[{txid_display,vout,sequence}], outputs:[{value,script_hex}],
/// shielded:[{recipient_hex,value,memo}], lock_time, expiry_height, branch_id }
pub fn build_t2z_from_json(
    spec: &str,
    sp: &SpendParameters,
    op: &OutputParameters,
) -> Result<String, String> {
    let j: Value = serde_json::from_str(spec).map_err(|e| format!("json: {e}"))?;

    let mut inputs = Vec::new();
    for i in j["inputs"].as_array().ok_or("inputs: expected array")? {
        let mut txid = h(&i["txid_display"], "txid_display")?;
        txid.reverse();
        let mut txid_internal = [0u8; 32];
        txid_internal.copy_from_slice(&txid);
        inputs.push(TxIn {
            txid_internal,
            vout: u64f(&i["vout"], "vout")? as u32,
            sequence: i["sequence"].as_u64().unwrap_or(0xffff_ffff) as u32,
        });
    }

    let mut outputs = Vec::new();
    if let Some(a) = j["outputs"].as_array() {
        for o in a {
            outputs.push(TxOut {
                value: u64f(&o["value"], "output value")?,
                script_pubkey: h(&o["script_hex"], "script_hex")?,
            });
        }
    }

    let mut shielded = Vec::new();
    for s in j["shielded"].as_array().ok_or("shielded: expected array")? {
        shielded.push(ShieldOutput {
            recipient: recipient43(&s["recipient_hex"])?,
            value: u64f(&s["value"], "shielded value")?,
            memo: memo_field(s)?,
        });
    }

    build_t2z_unsigned_tx(
        &inputs,
        &outputs,
        &shielded,
        j["lock_time"].as_u64().unwrap_or(0) as u32,
        u64f(&j["expiry_height"], "expiry_height")? as u32,
        u64f(&j["branch_id"], "branch_id")? as u32,
        sp,
        op,
        ZIP212,
    )
}

/// z->z / z->t spec: { extsk_hex, out:{cv,cmu,epk,enc,ct,proof},
/// tree:{left,right,parents:[]}, block_cmus:[], my_cmu_index,
/// shielded_outputs:[{recipient_hex,value,memo}] (or single "output"),
/// transparent_outputs:[{value,script_hex}], expiry_height, branch_id }
pub fn build_zspend_from_json(
    spec: &str,
    sp: &SpendParameters,
    op: &OutputParameters,
) -> Result<String, String> {
    let j: Value = serde_json::from_str(spec).map_err(|e| format!("json: {e}"))?;

    let o = &j["out"];
    let tree_parents = j["tree"]["parents"]
        .as_array()
        .ok_or("tree.parents: expected array")?
        .iter()
        .map(opt32)
        .collect::<Result<Vec<_>, _>>()?;
    let mut block_cmus = Vec::new();
    for c in j["block_cmus"].as_array().ok_or("block_cmus: expected array")? {
        block_cmus.push(h32(c, "block_cmu")?);
    }

    let spend = SpendInput {
        extsk_bytes: h(&j["extsk_hex"], "extsk_hex")?,
        out_cv: h32(&o["cv"], "out.cv")?,
        out_cmu: h32(&o["cmu"], "out.cmu")?,
        out_epk: h32(&o["epk"], "out.epk")?,
        out_enc: h(&o["enc"], "out.enc")?,
        out_ct: h(&o["ct"], "out.ct")?,
        out_proof: h(&o["proof"], "out.proof")?,
        tree_left: opt32(&j["tree"]["left"])?,
        tree_right: opt32(&j["tree"]["right"])?,
        tree_parents,
        block_cmus,
        my_cmu_index: u64f(&j["my_cmu_index"], "my_cmu_index")? as usize,
    };

    // shielded outputs: "shielded_outputs" array, or a single "output"
    let sh: Vec<&Value> = j["shielded_outputs"]
        .as_array()
        .map(|a| a.iter().collect())
        .or_else(|| j.get("output").map(|o| vec![o]))
        .unwrap_or_default();
    let mut shielded_outputs = Vec::new();
    for out in sh {
        shielded_outputs.push(Z2zOutput {
            recipient: recipient43(&out["recipient_hex"])?,
            value: u64f(&out["value"], "shielded output value")?,
            memo: memo_field(out)?,
        });
    }

    let mut transparent_outputs = Vec::new();
    if let Some(a) = j["transparent_outputs"].as_array() {
        for o in a {
            transparent_outputs.push(TxOut {
                value: u64f(&o["value"], "transparent value")?,
                script_pubkey: h(&o["script_hex"], "script_hex")?,
            });
        }
    }

    build_zspend_tx(
        &spend,
        &shielded_outputs,
        &transparent_outputs,
        u64f(&j["expiry_height"], "expiry_height")? as u32,
        u64f(&j["branch_id"], "branch_id")? as u32,
        ZIP212,
        sp,
        op,
    )
}

fn dfvk_from_json(j: &Value) -> Result<DiversifiableFullViewingKey, String> {
    if let Some(x) = j.get("extsk_hex") {
        crate::scan::dfvk_from_extsk(&h(x, "extsk_hex")?)
    } else if let Some(x) = j.get("dfvk_hex") {
        let b = h(x, "dfvk_hex")?;
        if b.len() != 128 {
            return Err(format!("dfvk_hex: expected 128 bytes, got {}", b.len()));
        }
        let mut a = [0u8; 128];
        a.copy_from_slice(&b);
        DiversifiableFullViewingKey::from_bytes(&a).ok_or_else(|| "dfvk_hex: invalid DFVK bytes".into())
    } else {
        Err("need extsk_hex or dfvk_hex".into())
    }
}

/// Fully decrypt one incoming output (value + recipient + memo).
/// Spec: { extsk_hex | dfvk_hex, out:{cv,cmu,epk,enc,ct,proof} } (raw wire hex).
/// Returns { value, recipient_hex, memo_hex, memo_text } or null if not ours.
pub fn read_note_from_json(spec: &str) -> Result<String, String> {
    let j: Value = serde_json::from_str(spec).map_err(|e| format!("json: {e}"))?;
    let dfvk = dfvk_from_json(&j)?;
    let o = &j["out"];
    let out = FullOutput {
        cv: h32(&o["cv"], "out.cv")?,
        cmu: h32(&o["cmu"], "out.cmu")?,
        epk: h32(&o["epk"], "out.epk")?,
        enc: h(&o["enc"], "out.enc")?,
        ct: h(&o["ct"], "out.ct")?,
        proof: h(&o["proof"], "out.proof")?,
    };
    match read_note(&dfvk, &out, ZIP212)? {
        None => Ok("null".into()),
        Some(n) => {
            // Trim the Sapling memo: text memos are UTF-8 + zero/0xf6 padding.
            let end = n.memo.iter().position(|&b| b == 0x00 || b == 0xf6).unwrap_or(n.memo.len());
            let memo_text = String::from_utf8_lossy(&n.memo[..end]).into_owned();
            let v = json!({
                "value": n.value,
                "recipient_hex": hex::encode(n.recipient),
                "memo_hex": hex::encode(n.memo),
                "memo_text": memo_text,
            });
            serde_json::to_string(&v).map_err(|e| format!("serialize: {e}"))
        }
    }
}

fn compact52(v: &Value) -> Result<[u8; COMPACT_NOTE_SIZE], String> {
    let b = h(v, "ciphertext")?;
    if b.len() < COMPACT_NOTE_SIZE {
        return Err(format!(
            "ciphertext: expected >= {COMPACT_NOTE_SIZE} bytes, got {}",
            b.len()
        ));
    }
    let mut a = [0u8; COMPACT_NOTE_SIZE];
    a.copy_from_slice(&b[..COMPACT_NOTE_SIZE]);
    Ok(a)
}

/// Note-detection spec (read path — no params, no proving):
/// { extsk_hex | dfvk_hex, tree:{left,right,parents:[]},
///   outputs:[{height,tx_index,output_index,cmu,epk,ciphertext}] }
/// where `ciphertext` is (at least) the 52-byte compact enc ciphertext and all
/// 32-byte fields are RAW wire order. `tree` is the state at the block BEFORE
/// the first output (GetTreeState(startHeight-1)); `outputs` MUST be every
/// Sapling output in the range, in global order (positions must stay contiguous).
///
/// Returns a JSON array: [{height,tx_index,output_index,position,value,
/// recipient_hex,nullifier_hex}], one per note belonging to the key.
pub fn detect_notes_from_json(spec: &str) -> Result<String, String> {
    let j: Value = serde_json::from_str(spec).map_err(|e| format!("json: {e}"))?;

    let dfvk: DiversifiableFullViewingKey = if let Some(x) = j.get("extsk_hex") {
        crate::scan::dfvk_from_extsk(&h(x, "extsk_hex")?)?
    } else if let Some(x) = j.get("dfvk_hex") {
        let b = h(x, "dfvk_hex")?;
        if b.len() != 128 {
            return Err(format!("dfvk_hex: expected 128 bytes, got {}", b.len()));
        }
        let mut a = [0u8; 128];
        a.copy_from_slice(&b);
        DiversifiableFullViewingKey::from_bytes(&a).ok_or("dfvk_hex: invalid DFVK bytes")?
    } else {
        return Err("detect: need extsk_hex or dfvk_hex".into());
    };

    let tree_before = TreeStateBefore {
        left: opt32(&j["tree"]["left"])?,
        right: opt32(&j["tree"]["right"])?,
        parents: j["tree"]["parents"]
            .as_array()
            .ok_or("tree.parents: expected array")?
            .iter()
            .map(opt32)
            .collect::<Result<Vec<_>, _>>()?,
    };

    let mut outputs = Vec::new();
    for o in j["outputs"].as_array().ok_or("outputs: expected array")? {
        outputs.push(CompactOutput {
            height: u64f(&o["height"], "height")?,
            tx_index: u64f(&o["tx_index"], "tx_index")?,
            output_index: u64f(&o["output_index"], "output_index")?,
            cmu: h32(&o["cmu"], "cmu")?,
            epk: h32(&o["epk"], "epk")?,
            ciphertext: compact52(&o["ciphertext"])?,
        });
    }

    let found = detect_notes(&dfvk, &tree_before, &outputs, ZIP212)?;
    let arr: Vec<Value> = found
        .iter()
        .map(|n| {
            json!({
                "height": n.height,
                "tx_index": n.tx_index,
                "output_index": n.output_index,
                "position": n.position,
                "value": n.value,
                "recipient_hex": hex::encode(n.recipient),
                "nullifier_hex": hex::encode(n.nullifier),
            })
        })
        .collect();
    serde_json::to_string(&arr).map_err(|e| format!("serialize: {e}"))
}
