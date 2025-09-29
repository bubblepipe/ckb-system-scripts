// Shared constants for dynamic ownership lock script
// This file is included by main.rs and test files to ensure consistency

pub const ERROR_ARGUMENTS_LEN: i8 = -1;
pub const ERROR_ENCODING: i8 = -2;
pub const ERROR_SYSCALL: i8 = -3;
pub const ERROR_SECP_RECOVER_PUBKEY: i8 = -11;
pub const ERROR_SECP_PARSE_SIGNATURE: i8 = -14;
pub const ERROR_WITNESS_SIZE: i8 = -22;
pub const ERROR_PUBKEY_BLAKE160_HASH: i8 = -31;
pub const ERROR_CELL_NOT_FOUND: i8 = -32;

pub const BLAKE160_SIZE: usize = 20;
pub const TYPE_ID_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 65;
pub const RECID_INDEX: usize = 64;
pub const MAX_WITNESS_SIZE: usize = 32768;
pub const BLAKE2B_BLOCK_SIZE: usize = 32;
pub const TEMP_SIZE: usize = 32768;
pub const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";

// TYPE_ID script code hash - this is the standard TYPE_ID script on CKB
// The last 8 bytes spell "TYPE_ID" in ASCII
pub const TYPE_ID_CODE_HASH: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x49, 0x44  // "TYPE_ID" in ascii
];