//! Sapling v4 transaction serialization + ZIP-243 sighash (Verus branch id).
//!
//! Byte layout validated against the golden vectors in `../test/vectors/`.
//! We serialize the transparent inputs with EMPTY scriptSigs: the Verus daemon
//! fills them via `signrawtransaction`, so this crate never handles a private
//! key. The binding signature commits to the ZIP-243 "shielded" sighash
//! (SIGHASH_ALL, no transparent-input section) computed here.

use blake2b_simd::Params;
use sapling_crypto::bundle::{GrothProofBytes, OutputDescription};

/// Serialize one Sapling OutputDescription in v4 wire order:
/// cv(32)||cmu(32)||ephemeralKey(32)||encCiphertext(580)||outCiphertext(80)||zkproof(192) = 948.
pub fn serialize_output_v4_desc(out: &OutputDescription<GrothProofBytes>) -> Vec<u8> {
    let mut v = Vec::with_capacity(948);
    v.extend_from_slice(&out.cv().to_bytes());
    v.extend_from_slice(&out.cmu().to_bytes());
    v.extend_from_slice(&out.ephemeral_key().0);
    v.extend_from_slice(out.enc_ciphertext());
    v.extend_from_slice(out.out_ciphertext());
    v.extend_from_slice(out.zkproof());
    v
}

/// Overwintered v4 header word (overwintered bit | version 4).
pub const V4_HEADER: u32 = 0x8000_0004;
/// Sapling version group id.
pub const SAPLING_VERSION_GROUP_ID: u32 = 0x892f_2085;
/// SIGHASH_ALL.
const SIGHASH_ALL: u32 = 1;

// ZIP-243 BLAKE2b personalizations (each exactly 16 bytes).
const PREVOUT_PERSONAL: &[u8; 16] = b"ZcashPrevoutHash";
const SEQUENCE_PERSONAL: &[u8; 16] = b"ZcashSequencHash";
const OUTPUTS_PERSONAL: &[u8; 16] = b"ZcashOutputsHash";
const SHIELDED_SPENDS_PERSONAL: &[u8; 16] = b"ZcashSSpendsHash";
const SHIELDED_OUTPUTS_PERSONAL: &[u8; 16] = b"ZcashSOutputHash";
// Sighash personalization is "ZcashSigHash" (12 bytes) || branchId (4 bytes LE).
const SIGHASH_PREFIX: &[u8; 12] = b"ZcashSigHash";

/// A transparent input (outpoint + sequence). scriptSig is filled by the daemon.
pub struct TxIn {
    /// Prevout txid in INTERNAL byte order (display hex reversed).
    pub txid_internal: [u8; 32],
    pub vout: u32,
    pub sequence: u32,
}

/// A transparent output (value in zatoshi + raw scriptPubKey bytes).
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

fn blake2b_personal(personal: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let hash = Params::new()
        .hash_length(32)
        .personal(personal)
        .to_state()
        .update(data)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

fn write_compact_size(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

/// ZIP-243 sighash committing to the whole transaction, with SIGHASH_ALL and no
/// transparent-input section. This is what the Sapling binding signature (and,
/// for z->z, the shielded spend-auth signatures) sign over.
///
/// `shielded_outputs` are the serialized OutputDescriptions (948 bytes each);
/// `shielded_spends` are serialized without their spend-auth sig (v4). For t->z
/// there are no spends, so `hashShieldedSpends` is all-zero per ZIP-243.
#[allow(clippy::too_many_arguments)]
pub fn shielded_sighash(
    branch_id: u32,
    inputs: &[TxIn],
    outputs: &[TxOut],
    lock_time: u32,
    expiry_height: u32,
    value_balance: i64,
    shielded_spends: &[Vec<u8>],
    shielded_outputs: &[Vec<u8>],
) -> [u8; 32] {
    let hash_prevouts = {
        let mut d = Vec::with_capacity(inputs.len() * 36);
        for i in inputs {
            d.extend_from_slice(&i.txid_internal);
            d.extend_from_slice(&i.vout.to_le_bytes());
        }
        blake2b_personal(PREVOUT_PERSONAL, &d)
    };
    let hash_sequence = {
        let mut d = Vec::with_capacity(inputs.len() * 4);
        for i in inputs {
            d.extend_from_slice(&i.sequence.to_le_bytes());
        }
        blake2b_personal(SEQUENCE_PERSONAL, &d)
    };
    let hash_outputs = {
        let mut d = Vec::new();
        for o in outputs {
            d.extend_from_slice(&o.value.to_le_bytes());
            write_compact_size(&mut d, o.script_pubkey.len() as u64);
            d.extend_from_slice(&o.script_pubkey);
        }
        blake2b_personal(OUTPUTS_PERSONAL, &d)
    };
    // No JoinSplits -> all-zero (ZIP-243).
    let hash_joinsplits = [0u8; 32];
    let hash_shielded_spends = if shielded_spends.is_empty() {
        [0u8; 32]
    } else {
        let mut d = Vec::new();
        for s in shielded_spends {
            d.extend_from_slice(s);
        }
        blake2b_personal(SHIELDED_SPENDS_PERSONAL, &d)
    };
    let hash_shielded_outputs = if shielded_outputs.is_empty() {
        [0u8; 32]
    } else {
        let mut d = Vec::new();
        for o in shielded_outputs {
            d.extend_from_slice(o);
        }
        blake2b_personal(SHIELDED_OUTPUTS_PERSONAL, &d)
    };

    if std::env::var("SIGHASH_DEBUG").is_ok() {
        eprintln!("[sighash] prevouts        {}", hex::encode(hash_prevouts));
        eprintln!("[sighash] sequence        {}", hex::encode(hash_sequence));
        eprintln!("[sighash] outputs         {}", hex::encode(hash_outputs));
        eprintln!("[sighash] shieldedSpends  {}", hex::encode(hash_shielded_spends));
        eprintln!("[sighash] shieldedOutputs {}", hex::encode(hash_shielded_outputs));
        eprintln!(
            "[sighash] lock={lock_time} expiry={expiry_height} vb={value_balance} branch={branch_id:#x} nOut={}",
            shielded_outputs.len()
        );
    }

    let mut pre = Vec::with_capacity(220);
    pre.extend_from_slice(&V4_HEADER.to_le_bytes());
    pre.extend_from_slice(&SAPLING_VERSION_GROUP_ID.to_le_bytes());
    pre.extend_from_slice(&hash_prevouts);
    pre.extend_from_slice(&hash_sequence);
    pre.extend_from_slice(&hash_outputs);
    pre.extend_from_slice(&hash_joinsplits);
    pre.extend_from_slice(&hash_shielded_spends);
    pre.extend_from_slice(&hash_shielded_outputs);
    pre.extend_from_slice(&lock_time.to_le_bytes());
    pre.extend_from_slice(&expiry_height.to_le_bytes());
    pre.extend_from_slice(&value_balance.to_le_bytes());
    pre.extend_from_slice(&SIGHASH_ALL.to_le_bytes());
    // No transparent-input section (this is the shielded/binding sighash).

    let mut personal = [0u8; 16];
    personal[..12].copy_from_slice(SIGHASH_PREFIX);
    personal[12..].copy_from_slice(&branch_id.to_le_bytes());
    blake2b_personal(&personal, &pre)
}

/// Serialize the full Sapling v4 transaction with empty transparent scriptSigs.
#[allow(clippy::too_many_arguments)]
pub fn serialize_v4(
    inputs: &[TxIn],
    outputs: &[TxOut],
    lock_time: u32,
    expiry_height: u32,
    value_balance: i64,
    shielded_spends: &[Vec<u8>],
    shielded_outputs: &[Vec<u8>],
    binding_sig: &[u8; 64],
) -> Vec<u8> {
    let mut tx = Vec::new();
    tx.extend_from_slice(&V4_HEADER.to_le_bytes());
    tx.extend_from_slice(&SAPLING_VERSION_GROUP_ID.to_le_bytes());

    write_compact_size(&mut tx, inputs.len() as u64);
    for i in inputs {
        tx.extend_from_slice(&i.txid_internal);
        tx.extend_from_slice(&i.vout.to_le_bytes());
        write_compact_size(&mut tx, 0); // empty scriptSig; daemon signs
        tx.extend_from_slice(&i.sequence.to_le_bytes());
    }

    write_compact_size(&mut tx, outputs.len() as u64);
    for o in outputs {
        tx.extend_from_slice(&o.value.to_le_bytes());
        write_compact_size(&mut tx, o.script_pubkey.len() as u64);
        tx.extend_from_slice(&o.script_pubkey);
    }

    tx.extend_from_slice(&lock_time.to_le_bytes());
    tx.extend_from_slice(&expiry_height.to_le_bytes());
    tx.extend_from_slice(&value_balance.to_le_bytes());

    write_compact_size(&mut tx, shielded_spends.len() as u64);
    for s in shielded_spends {
        tx.extend_from_slice(s);
    }
    write_compact_size(&mut tx, shielded_outputs.len() as u64);
    for o in shielded_outputs {
        tx.extend_from_slice(o);
    }

    write_compact_size(&mut tx, 0); // nJoinSplit

    if !shielded_spends.is_empty() || !shielded_outputs.is_empty() {
        tx.extend_from_slice(binding_sig);
    }
    tx
}
