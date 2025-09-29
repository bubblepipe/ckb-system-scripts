#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;
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

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!(16384, 1258306, 64);

mod constants;
use constants::*;

// Extract lock field from WitnessArgs and return its offset range in the witness buffer
pub fn extract_witness_lock(witness_data: &[u8]) -> Result<Option<(usize, usize)>, i8> {
    // Minimum size for WitnessArgs header is 16 bytes (4 byte total size + 3 * 4 byte offsets)
    // WitnessArgs is a table with 3 fields: lock, input_type, output_type
    if witness_data.len() < 16 {
        return Err(ERROR_ENCODING);
    }

    // Read header (total size)
    let total_size = u32::from_le_bytes(
        witness_data[0..4].try_into().map_err(|_| ERROR_ENCODING)?
    ) as usize;

    // Strict validation: witness_data length must exactly match total_size
    if witness_data.len() != total_size {
        return Err(ERROR_ENCODING);
    }

    // Read offset array (3 offsets: lock_start, input_type_start, output_type_start)
    let offset_to_lock = u32::from_le_bytes(
        witness_data[4..8].try_into().map_err(|_| ERROR_ENCODING)?
    ) as usize;

    let offset_to_input_type = u32::from_le_bytes(
        witness_data[8..12].try_into().map_err(|_| ERROR_ENCODING)?
    ) as usize;

    // The lock field data is between offset_to_lock and offset_to_input_type
    if offset_to_input_type == offset_to_lock {
        // Lock field is empty
        return Ok(None);
    }

    if offset_to_input_type < offset_to_lock || offset_to_lock < 16 {
        return Err(ERROR_ENCODING);
    }

    // Add bounds checking
    if offset_to_input_type > total_size || offset_to_lock >= total_size {
        return Err(ERROR_ENCODING);
    }

    if offset_to_input_type > witness_data.len() {
        return Err(ERROR_ENCODING);
    }

    let lock_field = &witness_data[offset_to_lock..offset_to_input_type];

    // Lock field is BytesOpt - it can be empty (0 bytes) or contain Bytes
    if lock_field.is_empty() {
        return Ok(None);
    }

    // BytesOpt when present is encoded as Bytes (4-byte length + data)
    if lock_field.len() < 4 {
        return Err(ERROR_ENCODING);
    }

    let lock_bytes_len = u32::from_le_bytes(
        lock_field[0..4].try_into().map_err(|_| ERROR_ENCODING)?
    ) as usize;

    // In Molecule spec for Bytes type, the length field is the payload size only
    // The total field size should be 4 (header) + lock_bytes_len (payload)
    if lock_field.len() != lock_bytes_len + 4 {
        return Err(ERROR_ENCODING);
    }

    // Check if we have actual data
    if lock_bytes_len == 0 {
        return Ok(None);
    }

    // Return absolute offsets in the witness buffer (skip 4-byte length header)
    Ok(Some((offset_to_lock + 4, offset_to_lock + 4 + lock_bytes_len)))
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
    // Molecule Script table encoding
    // 
    // Reference: 
    // https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0008-serialization/0008-serialization.md
    // https://docs.ckb.dev/docs/rfcs/0022-transaction-structure/0022-transaction-structure
    // 
    // table Script { code_hash: Byte32, hash_type: byte, args: Bytes }
    //
    // Encoding layout:
    // - 4 bytes: total size
    // - 12 bytes: three offsets (4 bytes each for code_hash, hash_type, args)
    // - 32 bytes: code_hash data
    // - 1 byte: hash_type data
    // - Variable: args data (4-byte length + actual bytes)
    //
    // For TYPE_ID script with 32-byte args:
    // - Header: 16 bytes (4 + 12)
    // - Data: 69 bytes (32 + 1 + 4 + 32)
    // - Total: 85 bytes minimum

    if script_data.len() < 85 { // Minimum size for a valid TYPE_ID script
        return false;
    }

    let total_size = u32::from_le_bytes(
        script_data[0..4].try_into().unwrap_or([0; 4])
    ) as usize;

    if script_data.len() != total_size {
        return false;
    }

    let code_hash_offset = u32::from_le_bytes(
        script_data[4..8].try_into().unwrap_or([0; 4])
    ) as usize;

    let hash_type_offset = u32::from_le_bytes(
        script_data[8..12].try_into().unwrap_or([0; 4])
    ) as usize;

    let args_offset = u32::from_le_bytes(
        script_data[12..16].try_into().unwrap_or([0; 4])
    ) as usize;

    if code_hash_offset >= total_size || hash_type_offset >= total_size || args_offset >= total_size {
        return false;
    }

    // Make sure we dont do out-of-range reads 
    if code_hash_offset + 32 > total_size {
        return false;
    }

    // Verify code_hash matches TYPE_ID_CODE_HASH
    let code_hash = &script_data[code_hash_offset..code_hash_offset + 32];
    if code_hash != TYPE_ID_CODE_HASH {
        return false; 
    }

    let args_data = &script_data[args_offset..];
    if args_data.len() < 4 {
        return false;
    }

    let args_len = u32::from_le_bytes(
        args_data[0..4].try_into().unwrap_or([0; 4])
    ) as usize;

    if args_len != TYPE_ID_SIZE || args_data.len() < 4 + args_len {
        return false;
    }

    // Compare args with expected type_id
    &args_data[4..4 + TYPE_ID_SIZE] == expected_type_id
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

    // Extract lock field offset from WitnessArgs
    // Only pass the actual witness data, not the whole buffer
    let witness_data = &temp[..witness_len];
    let lock_range = match extract_witness_lock(witness_data) {
        Ok(Some(range)) => range,
        Ok(None) => return ERROR_ENCODING,
        Err(e) => return e,
    };

    let (lock_start, lock_end) = lock_range;
    if lock_end - lock_start != SIGNATURE_SIZE {
        return ERROR_ARGUMENTS_LEN;
    }

    // Save signature before we zero it
    lock_bytes.copy_from_slice(&temp[lock_start..lock_end]);

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

    // Zero the signature in place in the witness
    for i in lock_start..lock_end {
        temp[i] = 0;
    }

    // Hash the modified first witness (with length prefix)
    let witness_len_bytes = (witness_len as u64).to_le_bytes();
    blake2b_ctx.update(&witness_len_bytes);
    blake2b_ctx.update(&temp[..witness_len]);

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