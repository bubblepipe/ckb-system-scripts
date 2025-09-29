#![cfg_attr(not(feature = "library"), no_std)]
#![allow(special_module_name)]
#![allow(unused_attributes)]

pub mod constants;
pub use constants::*;

#[cfg(feature = "library")]
#[path = "main.rs"]
mod main;

#[cfg(feature = "library")]
pub use main::{
    program_entry, extract_witness_lock, calculate_inputs_len, blake160, parse_and_match_type_id
};

extern crate alloc;
