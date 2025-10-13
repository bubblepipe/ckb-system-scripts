use ckb_testtool::ckb_hash::new_blake2b;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    packed,
    prelude::*,
};

use dynamic_ownership_secp256k1_blake160_sighash::{
    extract_witness_lock, blake160 as contract_blake160,
    ERROR_ENCODING, BLAKE160_SIZE
};  



#[cfg(test)]
mod helper_tests {
    use super::*;

    fn create_witness_args_with_lock(lock_bytes: Option<Vec<u8>>) -> Vec<u8> {
        // WitnessArgs is a molecule table with 3 fields: lock, input_type, output_type
        // Molecule table structure:
        // - 4 bytes: total size
        // - 4 bytes: offset to lock field data
        // - 4 bytes: offset to input_type field data
        // - 4 bytes: offset to output_type field data
        // - lock field data (if present)
        // - input_type field data (if present)
        // - output_type field data (if present)

        let header_size = 16; // 4 + 3*4 (total_size + 3 offsets)

        let lock_data = if let Some(bytes) = lock_bytes {
            // BytesOpt::Some(Bytes) encoding: 4-byte length + data
            let mut data = vec![];
            // The length is JUST the payload size, NOT including the 4-byte header!
            data.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            data.extend_from_slice(&bytes);
            data
        } else {
            // BytesOpt::None encoding: empty
            vec![]
        };

        let total_size = header_size + lock_data.len();

        let mut witness = vec![];

        // Total size
        witness.extend_from_slice(&(total_size as u32).to_le_bytes());

        // Offset to lock field (starts right after header)
        witness.extend_from_slice(&(header_size as u32).to_le_bytes());

        // Offset to input_type field (after lock field)
        let input_type_offset = header_size + lock_data.len();
        witness.extend_from_slice(&(input_type_offset as u32).to_le_bytes());

        // Offset to output_type field (same as input_type since it's empty)
        witness.extend_from_slice(&(input_type_offset as u32).to_le_bytes());

        // Note: No "end" offset in proper Molecule encoding!
        // The table only has offsets for each field

        // Append lock field data
        witness.extend_from_slice(&lock_data);

        witness
    }

    #[test]
    fn test_extract_witness_lock_with_signature() {
        let signature = vec![0xAA; 65];
        let witness = create_witness_args_with_lock(Some(signature.clone()));

        let result = extract_witness_lock(&witness);
        assert!(result.is_ok(), "extract_witness_lock failed: {:?}", result);

        let lock_bytes = result.unwrap();
        assert!(lock_bytes.is_some(), "Expected Some lock bytes");

        let extracted = lock_bytes.unwrap();
        assert_eq!(extracted.len(), 65, "Lock field should be exactly 65 bytes");
        assert_eq!(&extracted[..], &signature[..], "Extracted signature mismatch");
    }

    #[test]
    fn test_extract_witness_lock_empty() {
        let witness = create_witness_args_with_lock(None);

        let result = extract_witness_lock(&witness);
        assert!(result.is_ok(), "extract_witness_lock failed: {:?}", result);

        let lock_range = result.unwrap();
        assert!(lock_range.is_none(), "Expected None for empty lock field");
    }

    #[test]
    fn test_extract_witness_lock_invalid() {
        // Too short
        let result = extract_witness_lock(&[0u8; 15]);
        assert!(result.is_err(), "Should fail with too short data");
        assert_eq!(result.unwrap_err(), ERROR_ENCODING);

        // Invalid total size
        let mut bad_witness = vec![100, 0, 0, 0]; // Total size = 100
        bad_witness.extend_from_slice(&[0u8; 12]); // But only 16 bytes
        let result = extract_witness_lock(&bad_witness);
        assert!(result.is_err(), "Should fail with invalid total size");

        // Invalid offsets
        let mut bad_witness = vec![16, 0, 0, 0]; // Total size = 16
        bad_witness.extend_from_slice(&[20, 0, 0, 0]); // lock offset = 20 (> total)
        bad_witness.extend_from_slice(&[16, 0, 0, 0]); // input_type offset
        bad_witness.extend_from_slice(&[16, 0, 0, 0]); // output_type offset
        let result = extract_witness_lock(&bad_witness);
        assert!(result.is_err(), "Should fail with invalid offset");
    }

    #[test]
    fn test_witness_args_encoding() {
        // Test with various sizes
        let test_cases = vec![
            vec![0; 65],   // Standard signature size
            vec![1; 100],  // Larger data
            vec![2; 32],   // Smaller data
        ];

        for test_data in test_cases {
            let expected_len = test_data.len();
            let witness = create_witness_args_with_lock(Some(test_data.clone()));

            // Verify the structure
            let total_size = u32::from_le_bytes(witness[0..4].try_into().unwrap()) as usize;
            assert_eq!(total_size, witness.len());

            // Extract and verify the lock field
            let lock_offset = u32::from_le_bytes(witness[4..8].try_into().unwrap()) as usize;
            let input_type_offset = u32::from_le_bytes(witness[8..12].try_into().unwrap()) as usize;

            let lock_field = &witness[lock_offset..input_type_offset];
            assert!(!lock_field.is_empty());

            // Check the Bytes encoding within BytesOpt
            let lock_bytes_len = u32::from_le_bytes(lock_field[0..4].try_into().unwrap()) as usize;
            assert_eq!(lock_bytes_len, expected_len); // Just payload size
            assert_eq!(lock_field.len(), expected_len + 4); // Field includes 4-byte header

            // Verify actual data
            let actual_data = &lock_field[4..];
            assert_eq!(actual_data, &test_data[..]);

            // Also verify with extract_witness_lock
            let result = extract_witness_lock(&witness).unwrap();
            if expected_len > 0 {
                let extracted = result.unwrap();
                assert_eq!(&extracted[..], &test_data[..]);
            }
        }
    }

    #[test]
    fn test_witness_with_junk_data() {
        // Test that extract_witness_lock rejects witness with trailing junk data
        let signature = vec![0xAA; 65];
        let mut witness = create_witness_args_with_lock(Some(signature.clone()));

        // Append junk byte - this should cause extract_witness_lock to fail
        witness.push(0);

        let result = extract_witness_lock(&witness);
        assert!(result.is_err(), "Should fail with junk data appended");
        assert_eq!(result.unwrap_err(), ERROR_ENCODING, "Should return ERROR_ENCODING for junk data");
    }

    #[test]
    fn test_parse_and_match_type_id() {
        use dynamic_ownership_secp256k1_blake160_sighash::{parse_and_match_type_id, TYPE_ID_CODE_HASH};

        // Create a valid Molecule-encoded Script with type_id as args
        let type_id = [0x42u8; 32];

        // Build a minimal valid Script structure
        let mut script = Vec::new();

        // Calculate offsets
        let header_size = 16; // 4 bytes total + 3 * 4 bytes offsets
        let code_hash_offset = header_size;
        let hash_type_offset = code_hash_offset + 32;
        let args_offset = hash_type_offset + 1;

        // Args is Bytes type: 4-byte length + data
        let args_size = 4 + 32; // 4-byte length + 32-byte type_id
        let total_size = args_offset + args_size;

        // Write header
        script.extend_from_slice(&(total_size as u32).to_le_bytes());
        script.extend_from_slice(&(code_hash_offset as u32).to_le_bytes());
        script.extend_from_slice(&(hash_type_offset as u32).to_le_bytes());
        script.extend_from_slice(&(args_offset as u32).to_le_bytes());

        // Write code_hash (32 bytes) - use the actual TYPE_ID code hash
        script.extend_from_slice(&TYPE_ID_CODE_HASH);

        // Write hash_type (1 byte)
        script.push(0x01);

        // Write args (Bytes type)
        script.extend_from_slice(&(32u32).to_le_bytes()); // Length of type_id
        script.extend_from_slice(&type_id);

        // Test matching type_id
        assert!(parse_and_match_type_id(&script, &type_id),
                "Should match correct type_id");

        // Test non-matching type_id
        let wrong_type_id = [0x11u8; 32];
        assert!(!parse_and_match_type_id(&script, &wrong_type_id),
                "Should not match wrong type_id");

        // Test invalid script (too short)
        assert!(!parse_and_match_type_id(&[0u8; 10], &type_id),
                "Should reject too short script");

        // Test script with wrong args size
        let mut bad_script = script.clone();
        bad_script[args_offset..args_offset + 4].copy_from_slice(&(20u32).to_le_bytes());
        assert!(!parse_and_match_type_id(&bad_script[..bad_script.len() - 12], &type_id),
                "Should reject script with wrong args size");
    }

    #[test]
    fn test_real_witness_args() {
        // Test that our helper matches real WitnessArgs encoding
        let signature = vec![0xFF; 65];

        // Create expected using real WitnessArgs
        let expected_witness_args = packed::WitnessArgs::new_builder()
            .lock(Some(Bytes::from(signature.clone())).pack())
            .build();
        let expected = expected_witness_args.as_bytes();

        // Create actual using our helper
        let actual = create_witness_args_with_lock(Some(signature.clone()));

        // They should be identical
        assert_eq!(expected.len(), actual.len(),
                   "Helper and real WitnessArgs should have same length");

        // Compare the structure
        if expected.len() >= 20 {
            // Check header
            for i in 0..16 {
                assert_eq!(expected[i], actual[i],
                           "Header byte {} mismatch", i);
            }

            // Extract and compare lock field
            let lock_offset = u32::from_le_bytes(expected[4..8].try_into().unwrap()) as usize;
            let input_type_offset = u32::from_le_bytes(expected[8..12].try_into().unwrap()) as usize;

            if lock_offset < input_type_offset {
                let expected_lock_field = &expected[lock_offset..input_type_offset];
                let actual_lock_field = &actual[lock_offset..input_type_offset];

                // Check lock field length encoding
                let expected_len = u32::from_le_bytes(
                    expected_lock_field[0..4].try_into().unwrap()
                ) as usize;
                let actual_len = u32::from_le_bytes(
                    actual_lock_field[0..4].try_into().unwrap()
                ) as usize;

                assert_eq!(expected_len, 65, "Real WitnessArgs should encode length as 65");
                assert_eq!(actual_len, 65, "Helper should encode length as 65");
                assert_eq!(expected_len, actual_len, "Length encoding should match");
            }
        }

        let result = extract_witness_lock(&expected);
        assert!(result.is_ok(), "Should extract from real WitnessArgs");
        let extracted = result.unwrap().unwrap();
        assert_eq!(&extracted[..], &signature[..],
                   "Should extract correct signature from real WitnessArgs");
    }

    #[test]
    fn test_blake2b_implementation() {
        let test_cases = vec![
            b"hello world".to_vec(),
            vec![0u8; 33], // Compressed pubkey size
            vec![0xFF; 65], // Signature size
            vec![0x02; 33], // Typical compressed pubkey
        ];

        for input in test_cases {
            let result = contract_blake160(&input);
            assert_eq!(result.len(), BLAKE160_SIZE, "blake160 should return 20 bytes");

            let mut expected_blake2b = new_blake2b();
            expected_blake2b.update(&input);
            let mut expected_hash = [0u8; 32];
            expected_blake2b.finalize(&mut expected_hash);
            let mut expected = [0u8; 20];
            expected.copy_from_slice(&expected_hash[..20]);

            assert_eq!(result, expected, "blake160 mismatch for input len {}", input.len());
        }
    }

    #[test]
    fn test_witness_args_edge_cases() {
        let test_sizes = vec![0, 1, 32, 64, 65, 100, 255];

        for size in test_sizes {
            let data = vec![0xAA; size];
            let witness = create_witness_args_with_lock(Some(data.clone()));

            let result = extract_witness_lock(&witness);
            assert!(result.is_ok(), "Failed to parse witness with {} byte lock", size);

            if size > 0 {
                let extracted = result.unwrap().unwrap();
                assert_eq!(extracted.len(), size, "Wrong size extracted for {} byte lock", size);
                assert_eq!(&extracted[..], &data[..], "Wrong data extracted");
            }
        }

        for size in &[0, 65, 100] {
            let data = if *size > 0 { Some(vec![0xFF; *size]) } else { None };

            let real_wa = packed::WitnessArgs::new_builder()
                .lock(data.clone().map(|d| Bytes::from(d)).pack())
                .build();
            let helper_wa = create_witness_args_with_lock(data.clone());

            // Both should parse the same way
            let real_result = extract_witness_lock(&real_wa.as_bytes());
            let helper_result = extract_witness_lock(&helper_wa);

            assert_eq!(real_result.is_ok(), helper_result.is_ok(),
                       "Parse results should match for size {}", size);

            if let (Ok(real_opt), Ok(helper_opt)) = (real_result, helper_result) {
                assert_eq!(real_opt.is_some(), helper_opt.is_some(),
                           "Lock presence should match for size {}", size);

                if let (Some(real_bytes), Some(helper_bytes)) = (real_opt, helper_opt) {
                    assert_eq!(real_bytes.len(), helper_bytes.len(),
                               "Extracted sizes should match for size {}", size);
                    assert_eq!(real_bytes, helper_bytes,
                               "Extracted bytes should match for size {}", size);
                }
            }
        }
    }
}