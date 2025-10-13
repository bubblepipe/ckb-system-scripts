#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

 #[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!(16384, 1258306, 64);

#[cfg(any(feature = "library", test))]
extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

extern crate ckb_hash;
extern crate secp256k1;

use ckb_std::{
    ckb_constants::{Source, CellField},
    error::SysError,
    high_level::load_script,
    syscalls,
};
use ckb_hash::Blake2bBuilder;
use secp256k1::{ecdsa::{RecoverableSignature, RecoveryId}, Message as SecpMessage, Secp256k1};
use ckb_standalone_types::{packed, prelude::*};

mod constants;
use constants::*;

// Extract lock field from WitnessArgs and return the actual lock bytes
// Note: This is primarily for testing, but available for contract use too
pub fn extract_witness_lock(witness_data: &[u8]) -> Result<Option<Vec<u8>>, i8> {
    // Parse WitnessArgs using molecule
    let witness_args = packed::WitnessArgs::from_slice(witness_data)
        .map_err(|_| ERROR_ENCODING)?;

    // Access lock field - molecule handles all the offset calculations
    let lock_opt = witness_args.lock();

    // Check if lock is present
    if lock_opt.is_none() {
        return Ok(None);
    }

    // Get the actual bytes
    let lock_bytes = lock_opt.to_opt()
        .ok_or(ERROR_ENCODING)?;

    let lock_data = lock_bytes.raw_data();

    // Check if we have actual data
    if lock_data.is_empty() {
        return Ok(None);
    }

    // Return a copy of the lock data
    Ok(Some(lock_data.to_vec()))
}

// Internal version for program_entry that returns both the signature and zeroed witness
fn extract_and_zero_witness_lock(witness_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), i8> {
    // Parse WitnessArgs using molecule
    let witness_args = packed::WitnessArgs::from_slice(witness_data)
        .map_err(|_| ERROR_ENCODING)?;

    // Access lock field
    let lock_opt = witness_args.lock();

    if lock_opt.is_none() {
        return Err(ERROR_ENCODING);
    }

    // Get the actual lock bytes
    let lock_bytes = lock_opt.to_opt()
        .ok_or(ERROR_ENCODING)?;

    let lock_data = lock_bytes.raw_data();

    if lock_data.is_empty() {
        return Err(ERROR_ENCODING);
    }

    // Save the signature
    let signature = lock_data.to_vec();

    // Create zeroed witness using molecule builder
    let zeroed_lock = vec![0u8; lock_data.len()];
    let zeroed_witness_args = witness_args
        .as_builder()
        .lock(Some(ckb_standalone_types::bytes::Bytes::from(zeroed_lock)).pack())
        .build();

    Ok((signature, zeroed_witness_args.as_slice().to_vec()))
}

pub fn calculate_inputs_len() -> usize {
    let mut count = 0;
    loop {
        let mut buf = [0u8; 1];
        let ret = syscalls::load_cell(&mut buf, 0, count, Source::Input);
        match ret {
            Ok(_) => count += 1,
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            // Don't break on other errors like LengthNotEnough - just continue counting
            Err(SysError::LengthNotEnough(_)) => count += 1,
            Err(_) => break,
        }
    }
    count
}


pub fn blake160(data: &[u8]) -> [u8; BLAKE160_SIZE] {
    let mut blake2b = Blake2bBuilder::new(32)
        .personal(CKB_HASH_PERSONALIZATION)
        .build();

    blake2b.update(data);

    let mut hash = [0u8; 32];
    blake2b.finalize(&mut hash);

    hash[0..BLAKE160_SIZE].try_into().unwrap()
}

pub fn parse_and_match_type_id(script_data: &[u8], expected_type_id: &[u8]) -> bool {
    // Parse Script using molecule
    let script = match packed::Script::from_slice(script_data) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Verify code_hash matches TYPE_ID_CODE_HASH
    let code_hash = script.code_hash().raw_data();
    if code_hash.as_ref() != TYPE_ID_CODE_HASH {
        return false;
    }

    // Check args
    let args = script.args().raw_data();
    if args.len() != TYPE_ID_SIZE {
        return false;
    }

    // Compare args with expected type_id
    args.as_ref() == expected_type_id
}

// Find Cell B by its type_id
fn find_cell_by_type_id(type_id: &[u8]) -> Result<(usize, Source), i8> {
    let mut index = 0;
    loop {
        let mut type_hash = [0u8; 32];
        match syscalls::load_cell_by_field(
            &mut type_hash, 0, index,
            Source::CellDep,
            CellField::TypeHash
        ) {
            Ok(32) => {
                // Cell has a type script, load the full script
                let mut type_script_buf = [0u8; 256];
                match syscalls::load_cell_by_field(
                    &mut type_script_buf, 0, index,
                    Source::CellDep,
                    CellField::Type
                ) {
                    Ok(len) => {
                        if parse_and_match_type_id(&type_script_buf[..len], type_id) {
                            return Ok((index, Source::CellDep));
                        }
                    }
                    Err(_) => {} // Continue
                }
            }
            Err(SysError::IndexOutOfBound) => break,
            Ok(_) | Err(_) => {} // Cell has no type script or other error, continue
        }
        index += 1;
    }

    Err(ERROR_CELL_NOT_FOUND)
}

// Load blake160 hash from Cell B's data
fn load_blake160_from_cell(index: usize, source: Source) -> Result<[u8; BLAKE160_SIZE], i8> {
    let mut data = [0u8; BLAKE160_SIZE];
    match syscalls::load_cell_data(&mut data, 0, index, source) {
        Ok(BLAKE160_SIZE) => Ok(data),
        Ok(_) => Err(ERROR_ENCODING), 
        Err(_) => Err(ERROR_SYSCALL),
    }
}

pub fn program_entry() -> i8 {
    // Stack allocated buffers like C code
    let mut temp: [u8; TEMP_SIZE] = [0u8; TEMP_SIZE];
    let mut lock_bytes: [u8; SIGNATURE_SIZE] = [0u8; SIGNATURE_SIZE];

    let script = match load_script() {
        Ok(s) => s,
        Err(_) => return ERROR_SYSCALL,
    };

    let args = script.args().raw_data();
    if args.len() != TYPE_ID_SIZE {
        return ERROR_ARGUMENTS_LEN;
    }

    // Find Cell B by type_id and load pubkey hash
    let (cell_index, source) = match find_cell_by_type_id(&args) {
        Ok((idx, src)) => (idx, src),
        Err(e) => return e,
    };

    let pubkey_hash = match load_blake160_from_cell(cell_index, source) {
        Ok(hash) => hash,
        Err(e) => return e,
    };

    // Load first witness from the same group
    let witness_len = match syscalls::load_witness(&mut temp, 0, 0, Source::GroupInput) {
        Ok(actual_len) => actual_len,
        Err(SysError::LengthNotEnough(actual_len)) => {
            if actual_len > MAX_WITNESS_SIZE {
                return ERROR_WITNESS_SIZE;
            }
            return ERROR_SYSCALL;
        }
        Err(_) => return ERROR_SYSCALL,
    };

    if witness_len > MAX_WITNESS_SIZE {
        return ERROR_WITNESS_SIZE;
    }

    // Extract lock field and get zeroed witness using molecule
    let witness_data = &temp[..witness_len];
    let (signature, zeroed_witness) = match extract_and_zero_witness_lock(witness_data) {
        Ok(result) => result,
        Err(e) => return e,
    };

    if signature.len() != SIGNATURE_SIZE {
        return ERROR_ARGUMENTS_LEN;
    }

    // Save signature
    lock_bytes.copy_from_slice(&signature);

    // Load transaction hash
    let mut tx_hash = [0u8; BLAKE2B_BLOCK_SIZE];
    match syscalls::load_tx_hash(&mut tx_hash, 0) {
        Ok(actual_len) if actual_len == BLAKE2B_BLOCK_SIZE => {},
        _ => return ERROR_SYSCALL,
    };

    // Start building the message for signature verification
    let mut message = [0u8; BLAKE2B_BLOCK_SIZE];
    let mut blake2b_ctx = Blake2bBuilder::new(BLAKE2B_BLOCK_SIZE)
        .personal(CKB_HASH_PERSONALIZATION)
        .build();

    // Hash transaction hash
    blake2b_ctx.update(&tx_hash);

    // Hash the zeroed witness (with length prefix)
    let zeroed_witness_len = zeroed_witness.len() as u64;
    blake2b_ctx.update(&zeroed_witness_len.to_le_bytes());
    blake2b_ctx.update(&zeroed_witness);

    // Hash remaining witnesses in the group
    let mut i = 1;
    loop {
        match syscalls::load_witness(&mut temp, 0, i, Source::GroupInput) {
            Ok(actual_len) => {
                if actual_len > MAX_WITNESS_SIZE {
                    return ERROR_WITNESS_SIZE;
                }
                let witness_len_bytes = (actual_len as u64).to_le_bytes();
                blake2b_ctx.update(&witness_len_bytes);
                blake2b_ctx.update(&temp[..actual_len]);
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return ERROR_SYSCALL,
        }
    }

    // Hash witnesses with index >= input count
    let input_count = calculate_inputs_len();
    i = input_count;
    loop {
        match syscalls::load_witness(&mut temp, 0, i, Source::Input) {
            Ok(actual_len) => {
                if actual_len > MAX_WITNESS_SIZE {
                    return ERROR_WITNESS_SIZE;
                }
                let witness_len_bytes = (actual_len as u64).to_le_bytes();
                blake2b_ctx.update(&witness_len_bytes);
                blake2b_ctx.update(&temp[..actual_len]);
                i += 1;
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return ERROR_SYSCALL,
        }
    }

    blake2b_ctx.finalize(&mut message);

    // Verify signature format
    if lock_bytes[RECID_INDEX] > 3 {
        return ERROR_SECP_PARSE_SIGNATURE;
    }

    // Extract signature components
    let sig_bytes = &lock_bytes[..64];
    let recid_byte = lock_bytes[RECID_INDEX];

    let recovery_id = match RecoveryId::from_i32(recid_byte as i32) {
        Ok(id) => id,
        Err(_) => return ERROR_SECP_PARSE_SIGNATURE,
    };

    let recoverable_sig = match RecoverableSignature::from_compact(sig_bytes, recovery_id) {
        Ok(sig) => sig,
        Err(_) => return ERROR_SECP_PARSE_SIGNATURE,
    };

    let secp_message = match SecpMessage::from_digest_slice(&message) {
        Ok(msg) => msg,
        Err(_) => return ERROR_SECP_PARSE_SIGNATURE,
    };

    // Recover public key from signature
    let secp = Secp256k1::verification_only();
    let pubkey = match secp.recover_ecdsa(&secp_message, &recoverable_sig) {
        Ok(key) => key,
        Err(_) => return ERROR_SECP_RECOVER_PUBKEY,
    };

    // Compare with pubkey hash from Cell B
    let calculated_hash = blake160(&pubkey.serialize());
    if calculated_hash != pubkey_hash {
        return ERROR_PUBKEY_BLAKE160_HASH;
    }

    0 // successful
}