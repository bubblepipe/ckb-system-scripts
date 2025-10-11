use ckb_crypto::secp::Privkey;
use ckb_hash::{blake2b_256, new_blake2b};
use ckb_sdk::{
    rpc::ckb_light_client::{Order, ScriptType, SearchKey},
    traits::DefaultCellDepResolver,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, Capacity, DepType, ScriptHashType, TransactionBuilder, TransactionView},
    packed::{
        Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs,
    },
    prelude::*,
    H256,
};

// ========== CONSTANTS FROM OFFCKB ==========

// - "#": 18
// address: ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqvm52pxjfczywarv63fmjtyqxgs2syfffq2348ad
// privkey: 0xa5808e79c243d8e026a034273ad7a5ccdcb2f982392fd0230442b1734c98a4c2
// pubkey: 0x034417bf068a1166a1443cfbbf974e61a65bf402dcce7b157a67260c18c6dd76f7
// lock_arg: 0x9ba28269270223ba366a29dc96401910540894a4
// lockScript:
//     codeHash: 0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8
//     hashType: type
//     args: 0x9ba28269270223ba366a29dc96401910540894a4

// - "#": 19
// address: ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq2prryvze6fhufxkgjx35psh7w70k3hz7c3mtl4d
// privkey: 0xace08599f3174f4376ae51fdc30950d4f2d731440382bb0aa1b6b0bd3a9728cd
// pubkey: 0x0216bc7b5b0a30fb910c372062a7f8cfa89f3a231f5d4a975e60a787ea828aa49e
// lock_arg: 0x4118c8c16749bf126b22468d030bf9de7da3717b
// lockScript:
//     codeHash: 0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8
//     hashType: type
//     args: 0x4118c8c16749bf126b22468d030bf9de7da3717b

const ACCOUNT_19_PRIVKEY: &str = "0xace08599f3174f4376ae51fdc30950d4f2d731440382bb0aa1b6b0bd3a9728cd";
const ACCOUNT_19_LOCK_ARG: &str = "0x4118c8c16749bf126b22468d030bf9de7da3717b";

const ACCOUNT_18_PRIVKEY: &str = "0xa5808e79c243d8e026a034273ad7a5ccdcb2f982392fd0230442b1734c98a4c2";
const ACCOUNT_18_LOCK_ARG: &str = "0x9ba28269270223ba366a29dc96401910540894a4";

// After deploying dynamic ownership contract
const CONTRACT_TX_HASH: &str = "0x6cb9dc027e35d51b5d4a9b6af0cc77f2db5e5b4cc2525fb66698e346387bde91";
const CONTRACT_INDEX: usize = 0;
const CONTRACT_DATA_HASH: &str = "0x0b298d208cd89792494a87b32a10caba92fb19457cc46869a96df26b2b6eadd5"; 

// Secp256k1 code hash (obtained from genesis block via DefaultCellDepResolver)
const SECP256K1_CODE_HASH: &str = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";

// Type ID type script code hash
const TYPE_ID_CODE_HASH: &str = "0x00000000000000000000000000000000000000000000000000545950455f4944";

// RPC URL for offckb
const OFFCKB_RPC_URL: &str = "http://127.0.0.1:8114";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Dynamic Ownership Transfer Test ===\n");

    // Setup RPC client
    let client = ckb_sdk::rpc::CkbRpcClient::new(OFFCKB_RPC_URL);

    let cell_dep_resolver = {
        let genesis_block = client.get_block_by_number(0.into())?.unwrap();
        DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))?
    };

    // Parse keys
    let account_19_privkey = Privkey::from_slice(&hex::decode(&ACCOUNT_19_PRIVKEY[2..])?);
    let account_18_privkey = Privkey::from_slice(&hex::decode(&ACCOUNT_18_PRIVKEY[2..])?);

    let account_19_pubkey = account_19_privkey.pubkey()?;
    let account_18_pubkey = account_18_privkey.pubkey()?;

    // Calculate pubkey hashes
    let account_19_pubkey_hash = blake160(&account_19_pubkey.serialize());
    let account_18_pubkey_hash = blake160(&account_18_pubkey.serialize());

    println!("Account 19 pubkey hash: 0x{}", hex::encode(&account_19_pubkey_hash));
    println!("Account 18 pubkey hash: 0x{}", hex::encode(&account_18_pubkey_hash));

    // ========== Step 1: Create Cell B ==========
    println!("\n1. Creating Cell B with self-referential dynamic ownership lock...");

    let (cell_b_tx_hash, cell_b_type_id) = create_cell_b(&client, &cell_dep_resolver, &account_19_privkey, &account_19_pubkey_hash).await?;

    println!("Cell B created with type_id: 0x{}", hex::encode(&cell_b_type_id));
    println!("tx hash: 0x{}", hex::encode(&cell_b_tx_hash));

    // ========== Step 2: Create Cell A (10000 CKB) ==========
    println!("\n2. Creating Cell A with 10000 CKB locked by dynamic ownership...");

    let cell_a_tx_hash = create_cell_a(
        &client,
        &cell_dep_resolver,
        &account_19_privkey,
        &cell_b_type_id,
        10000_0000_0000, // 10000 CKB in shannons
    ).await?;

    println!("Cell A created, tx hash: 0x{}", hex::encode(&cell_a_tx_hash));

    // ========== Step 3: Unlock Cell A with account 19, pay 1000 CKB to account 18 ==========
    println!("\n3. Unlocking Cell A with account 19, paying 1000 CKB to account 18...");

    let (new_cell_a_tx_hash, new_cell_a_index) = unlock_and_transfer(
        &client,
        &cell_dep_resolver,
        &account_19_privkey,
        &cell_a_tx_hash,
        0, // Cell A is at index 0
        &cell_b_tx_hash,
        0, // Cell B is at index 0
        &cell_b_type_id,
        1000_0000_0000, // Transfer 1000 CKB to account 18
        &account_18_lock_script(),
    ).await?;

    println!("Success! New Cell A' created with 9000 CKB");
    println!("tx hash: 0x{}", hex::encode(&new_cell_a_tx_hash));

    // ========== Step 4: Try to unlock Cell A' with account 18 (should FAIL) ==========
    println!("\n4. Trying to unlock Cell A' with account 18 (should fail)...");

    match try_unlock_with_wrong_owner(
        &client,
        &cell_dep_resolver,
        &account_18_privkey,
        &new_cell_a_tx_hash,
        new_cell_a_index,
        &cell_b_tx_hash,
        0,
        &cell_b_type_id,
    ).await {
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("TransactionFailedToVerify") ||
               error_msg.contains("ValidationFailure") ||
               error_msg.contains("error code") {
                println!("✅ Expected failure: Account 18 cannot unlock Cell A' (Cell B still points to account 19)");
                println!("   Error code: {}", if error_msg.contains("error code -31") { "-31" } else { "unknown" });
            } else {
                return Err(format!("Unexpected error: {}", e).into());
            }
        },
        Ok(_) => return Err("Should have failed but succeeded!".into()),
    }

    // ========== Step 5: Update Cell B to have account 18's pubkey ==========
    println!("\n5. Updating Cell B owner from account 19 to account 18...");

    let updated_cell_b_tx_hash = update_cell_b_owner_self_ref(
        &client,
        &cell_dep_resolver,
        &account_19_privkey,
        &cell_b_tx_hash,
        0,
        &cell_b_type_id,
        &account_18_pubkey_hash,
    ).await?;

    println!("Cell B updated! New owner is account 18");
    println!("Transaction: 0x{}", hex::encode(&updated_cell_b_tx_hash));

    // ========== Step 6: Retry unlock with account 18 (should SUCCEED) ==========
    println!("\n6. Retrying unlock with account 18 (should succeed now)...");

    let final_tx_hash = unlock_and_transfer(
        &client,
        &cell_dep_resolver,
        &account_18_privkey,
        &new_cell_a_tx_hash,
        new_cell_a_index,
        &updated_cell_b_tx_hash,
        0,
        &cell_b_type_id,
        1000_0000_0000, // Transfer 1000 CKB back to account 19
        &account_19_lock_script(),
    ).await?;

    println!("✅ Success! Account 18 successfully unlocked Cell A' after ownership transfer");
    println!("Final transaction: 0x{}", hex::encode(final_tx_hash.0.as_bytes()));

    println!("\n=== All tests passed! ===");
    Ok(())
}

// Helper function to create Cell B with simplified secp256k1 lock
async fn create_cell_b_simple(
    client: &ckb_sdk::rpc::CkbRpcClient,
    resolver: &DefaultCellDepResolver,
    owner_privkey: &Privkey,
    owner_pubkey_hash: &[u8; 20],
) -> Result<(H256, [u8; 32]), Box<dyn std::error::Error>> {
    // Get an input cell from account 19
    let cell_b_capacity = 200_0000_0000u64; // 200 CKB for Cell B
    let fee = 1000_0000u64; // 0.01 CKB fee
    let min_capacity = cell_b_capacity + fee;

    let (input_outpoint, input_capacity) = get_live_cell_for_account_19(client, min_capacity).await?;

    // For Type ID creation, args should be: blake2b(CellInput[0] || output_index)
    // CellInput = OutPoint + since field
    let output_index: u64 = 0; // First output (Cell B)

    // Create the CellInput that will be used in the transaction
    let cell_input = CellInput::new(input_outpoint.clone(), 0);

    // Hash CellInput (not just OutPoint!) + output_index
    let mut blake2b = new_blake2b();
    blake2b.update(cell_input.as_slice()); // Hash the complete CellInput (OutPoint + since)
    blake2b.update(&output_index.to_le_bytes()); // Hash the output index
    let mut type_id_args = [0u8; 32];
    blake2b.finalize(&mut type_id_args);

    // Build Cell B with Type ID creation args
    let type_script = Script::new_builder()
        .code_hash(hex_to_byte32(TYPE_ID_CODE_HASH)?)
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(type_id_args.to_vec()).pack())
        .build();

    // Simple secp256k1 lock for account 19 (not self-referential)
    let lock_script = account_19_lock_script();

    let cell_b_output = CellOutput::new_builder()
        .capacity(Capacity::shannons(cell_b_capacity).pack())
        .lock(lock_script)
        .type_(Some(type_script).pack())
        .build();

    // Calculate change (input - output - fee)
    let change_capacity = input_capacity - cell_b_capacity - fee;

    // Create change output back to account 19
    let change_output = CellOutput::new_builder()
        .capacity(Capacity::shannons(change_capacity).pack())
        .lock(account_19_lock_script())
        .build();

    // Build transaction
    let tx = TransactionBuilder::default()
        .input(cell_input.clone())
        .output(cell_b_output)
        .output_data(Bytes::from(owner_pubkey_hash.to_vec()).pack())
        .output(change_output)
        .output_data(Bytes::new().pack())
        .cell_dep(secp256k1_dep(resolver))
        // Note: Type ID is a built-in system script and doesn't require a cell_dep
        .witness(WitnessArgs::default().as_bytes().pack())
        .build();

    // Sign with account 19's secp256k1 lock
    let signed_tx = sign_secp256k1_transaction(tx, owner_privkey)?;
    let tx_hash = client.send_transaction(signed_tx.data().into(), None)?;

    wait_for_confirmation(client, &tx_hash).await?;

    // Return tx_hash and the Type ID (which is the args we used for creation)
    Ok((tx_hash, type_id_args))
}

// Helper function to create Cell B with self-referential dynamic ownership lock
async fn create_cell_b(
    client: &ckb_sdk::rpc::CkbRpcClient,
    resolver: &DefaultCellDepResolver,
    owner_privkey: &Privkey,
    owner_pubkey_hash: &[u8; 20],
) -> Result<(H256, [u8; 32]), Box<dyn std::error::Error>> {
    // Get an input cell from account 19
    let cell_b_capacity = 200_0000_0000u64; // 200 CKB for Cell B
    let fee = 1000_0000u64; // 0.01 CKB fee
    let min_capacity = cell_b_capacity + fee;

    let (input_outpoint, input_capacity) = get_live_cell_for_account_19(client, min_capacity).await?;

    // For Type ID creation, args should be: blake2b(CellInput[0] || output_index)
    let output_index: u64 = 0; // First output (Cell B)

    // Create the CellInput that will be used in the transaction
    let cell_input = CellInput::new(input_outpoint.clone(), 0);

    // Hash CellInput + output_index to get Type ID args
    let mut blake2b = new_blake2b();
    blake2b.update(cell_input.as_slice());
    blake2b.update(&output_index.to_le_bytes());
    let mut type_id_args = [0u8; 32];
    blake2b.finalize(&mut type_id_args);

    // Build Cell B with Type ID
    let type_script = Script::new_builder()
        .code_hash(hex_to_byte32(TYPE_ID_CODE_HASH)?)
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(type_id_args.to_vec()).pack())
        .build();

    // Self-referential dynamic ownership lock - references its own type ID!
    let lock_script = Script::new_builder()
        .code_hash(hex_to_byte32(CONTRACT_DATA_HASH)?)
        .hash_type(ScriptHashType::Data1.into())
        .args(Bytes::from(type_id_args.to_vec()).pack())
        .build();

    let cell_b_output = CellOutput::new_builder()
        .capacity(Capacity::shannons(cell_b_capacity).pack())
        .lock(lock_script)
        .type_(Some(type_script).pack())
        .build();

    // Calculate change
    let change_capacity = input_capacity - cell_b_capacity - fee;

    // Create change output back to account 19
    let change_output = CellOutput::new_builder()
        .capacity(Capacity::shannons(change_capacity).pack())
        .lock(account_19_lock_script())
        .build();

    // Build transaction
    let tx = TransactionBuilder::default()
        .input(cell_input.clone())
        .output(cell_b_output)
        .output_data(Bytes::from(owner_pubkey_hash.to_vec()).pack())
        .output(change_output)
        .output_data(Bytes::new().pack())
        .cell_dep(contract_dep())
        .cell_dep(secp256k1_dep(resolver))
        .witness(WitnessArgs::default().as_bytes().pack())
        .build();

    // Sign with account 19's secp256k1 lock (input is locked by secp256k1)
    let signed_tx = sign_secp256k1_transaction(tx, owner_privkey)?;
    let tx_hash = client.send_transaction(signed_tx.data().into(), None)?;

    wait_for_confirmation(client, &tx_hash).await?;

    // Return tx_hash and the Type ID
    Ok((tx_hash, type_id_args))
}

// Helper function to create Cell A
async fn create_cell_a(
    client: &ckb_sdk::rpc::CkbRpcClient,
    resolver: &DefaultCellDepResolver,
    owner_privkey: &Privkey,
    cell_b_type_id: &[u8; 32],
    capacity: u64,
) -> Result<H256, Box<dyn std::error::Error>> {
    // Get input from account 19
    let fee = 1000_0000u64; // 0.01 CKB fee
    let min_capacity = capacity + fee;

    let (input_outpoint, input_capacity) = get_live_cell_for_account_19(client, min_capacity).await?;

    // Dynamic ownership lock referencing Cell B's type_id
    let lock_script = Script::new_builder()
        .code_hash(hex_to_byte32(CONTRACT_DATA_HASH)?)
        .hash_type(ScriptHashType::Data1.into())
        .args(Bytes::from(cell_b_type_id.to_vec()).pack())
        .build();

    let cell_a_output = CellOutput::new_builder()
        .capacity(Capacity::shannons(capacity).pack())
        .lock(lock_script)
        .build();

    // Calculate change
    let change_capacity = input_capacity - capacity - fee;

    let change_output = CellOutput::new_builder()
        .capacity(Capacity::shannons(change_capacity).pack())
        .lock(account_19_lock_script())
        .build();

    let tx = TransactionBuilder::default()
        .input(CellInput::new(input_outpoint, 0))
        .output(cell_a_output)
        .output_data(Bytes::new().pack())
        .output(change_output)
        .output_data(Bytes::new().pack())
        .cell_dep(contract_dep())
        .cell_dep(secp256k1_dep(resolver))
        .witness(WitnessArgs::default().as_bytes().pack())
        .build();

    let signed_tx = sign_secp256k1_transaction(tx, owner_privkey)?;
    let tx_hash = client.send_transaction(signed_tx.data().into(), None)?;

    wait_for_confirmation(client, &tx_hash).await?;
    Ok(tx_hash)
}

// Helper function to unlock Cell A and transfer funds
async fn unlock_and_transfer(
    client: &ckb_sdk::rpc::CkbRpcClient,
    resolver: &DefaultCellDepResolver,
    owner_privkey: &Privkey,
    cell_a_tx_hash: &H256,
    cell_a_index: usize,
    cell_b_tx_hash: &H256,
    cell_b_index: usize,
    _cell_b_type_id: &[u8; 32],
    transfer_amount: u64,
    recipient_lock: &Script,
) -> Result<(H256, usize), Box<dyn std::error::Error>> {
    let cell_a_outpoint = h256_to_outpoint(cell_a_tx_hash, cell_a_index as u32)?;
    let cell_b_outpoint = h256_to_outpoint(cell_b_tx_hash, cell_b_index as u32)?;

    // Get Cell A info
    let cell_a_info = client.get_live_cell(cell_a_outpoint.clone().into(), false)?
        .cell.ok_or("Cell A not found")?;
    let cell_a_capacity: u64 = cell_a_info.output.capacity.into();

    // Build outputs
    let remaining_capacity = cell_a_capacity - transfer_amount - 1000_0000; // Minus fees

    // Output 1: Remaining funds still with dynamic ownership
    let cell_a_new = CellOutput::new_builder()
        .capacity(Capacity::shannons(remaining_capacity).pack())
        .lock(cell_a_info.output.lock.into()) // Keep same lock
        .build();

    // Output 2: Transfer to recipient
    let transfer_output = CellOutput::new_builder()
        .capacity(Capacity::shannons(transfer_amount).pack())
        .lock(recipient_lock.clone())
        .build();

    let tx = TransactionBuilder::default()
        .input(CellInput::new(cell_a_outpoint, 0))
        .output(cell_a_new)
        .output_data(Bytes::new().pack())
        .output(transfer_output)
        .output_data(Bytes::new().pack())
        .cell_dep(contract_dep())
        .cell_dep(CellDep::new_builder()
            .out_point(cell_b_outpoint)
            .dep_type(DepType::Code.into())
            .build())
        .cell_dep(secp256k1_dep(resolver))
        .witness(WitnessArgs::default().as_bytes().pack())
        .build();

    let signed_tx = sign_transaction_for_dynamic_ownership(tx, owner_privkey)?;
    let tx_hash = client.send_transaction(signed_tx.data().into(), None)?;

    wait_for_confirmation(client, &tx_hash).await?;
    Ok((tx_hash, 0)) // New Cell A' is at index 0
}

// Helper function to update Cell B's owner
async fn update_cell_b_owner(
    client: &ckb_sdk::rpc::CkbRpcClient,
    resolver: &DefaultCellDepResolver,
    current_owner_privkey: &Privkey,
    cell_b_tx_hash: &H256,
    cell_b_index: usize,
    _cell_b_type_id: &[u8; 32],
    new_owner_pubkey_hash: &[u8; 20],
) -> Result<H256, Box<dyn std::error::Error>> {
    let cell_b_outpoint = h256_to_outpoint(cell_b_tx_hash, cell_b_index as u32)?;

    // Get Cell B info
    let cell_b_info = client.get_live_cell(cell_b_outpoint.clone().into(), false)?
        .cell.ok_or("Cell B not found")?;

    // Build new Cell B with same lock and type, but new data
    let capacity_u64: u64 = cell_b_info.output.capacity.into();

    // Subtract fee from capacity (CKB requires fee for all transactions)
    let fee = 1000u64; // 0.00001 CKB fee (1000 shannons)
    let new_capacity = capacity_u64 - fee;

    let new_cell_b = CellOutput::new_builder()
        .capacity(Capacity::shannons(new_capacity).pack())
        .lock(cell_b_info.output.lock.into()) // Keep same secp256k1 lock
        .type_(cell_b_info.output.type_.map(|t| {
            let script: ckb_types::packed::Script = t.into();
            script
        }).pack())
        .build();

    let tx = TransactionBuilder::default()
        .input(CellInput::new(cell_b_outpoint.clone(), 0))
        .output(new_cell_b)
        .output_data(Bytes::from(new_owner_pubkey_hash.to_vec()).pack()) // New owner!
        .cell_dep(secp256k1_dep(resolver))
        .witness(WitnessArgs::default().as_bytes().pack())
        .build();

    // Sign with secp256k1 (Cell B uses secp256k1 lock, not dynamic ownership)
    let signed_tx = sign_secp256k1_transaction(tx, current_owner_privkey)?;
    let tx_hash = client.send_transaction(signed_tx.data().into(), None)?;

    wait_for_confirmation(client, &tx_hash).await?;
    Ok(tx_hash)
}

// Helper function to update Cell B's owner (for self-referential Cell B)
async fn update_cell_b_owner_self_ref(
    client: &ckb_sdk::rpc::CkbRpcClient,
    resolver: &DefaultCellDepResolver,
    current_owner_privkey: &Privkey,
    cell_b_tx_hash: &H256,
    cell_b_index: usize,
    _cell_b_type_id: &[u8; 32],
    new_owner_pubkey_hash: &[u8; 20],
) -> Result<H256, Box<dyn std::error::Error>> {
    let cell_b_outpoint = h256_to_outpoint(cell_b_tx_hash, cell_b_index as u32)?;

    // Get Cell B info
    let cell_b_info = client.get_live_cell(cell_b_outpoint.clone().into(), false)?
        .cell.ok_or("Cell B not found")?;

    // Build new Cell B with same lock and type, but new data
    let capacity_u64: u64 = cell_b_info.output.capacity.into();

    // Subtract fee from capacity
    let fee = 1000u64; // 0.00001 CKB fee (1000 shannons)
    let new_capacity = capacity_u64 - fee;

    let new_cell_b = CellOutput::new_builder()
        .capacity(Capacity::shannons(new_capacity).pack())
        .lock(cell_b_info.output.lock.into()) // Keep same dynamic ownership lock
        .type_(cell_b_info.output.type_.map(|t| {
            let script: ckb_types::packed::Script = t.into();
            script
        }).pack())
        .build();

    let tx = TransactionBuilder::default()
        .input(CellInput::new(cell_b_outpoint.clone(), 0))
        .output(new_cell_b)
        .output_data(Bytes::from(new_owner_pubkey_hash.to_vec()).pack()) // New owner!
        .cell_dep(contract_dep())
        .cell_dep(CellDep::new_builder()
            .out_point(cell_b_outpoint.clone())
            .dep_type(DepType::Code.into())
            .build())
        .cell_dep(secp256k1_dep(resolver))
        .witness(WitnessArgs::default().as_bytes().pack())
        .build();

    // Sign with dynamic ownership (Cell B uses self-referential dynamic ownership lock)
    let signed_tx = sign_transaction_for_dynamic_ownership(tx, current_owner_privkey)?;
    let tx_hash = client.send_transaction(signed_tx.data().into(), None)?;

    wait_for_confirmation(client, &tx_hash).await?;
    Ok(tx_hash)
}

// Helper function to try unlock with wrong owner (should fail)
async fn try_unlock_with_wrong_owner(
    client: &ckb_sdk::rpc::CkbRpcClient,
    resolver: &DefaultCellDepResolver,
    wrong_privkey: &Privkey,
    cell_a_tx_hash: &H256,
    cell_a_index: usize,
    cell_b_tx_hash: &H256,
    cell_b_index: usize,
    _cell_b_type_id: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let cell_a_outpoint = h256_to_outpoint(cell_a_tx_hash, cell_a_index as u32)?;
    let cell_b_outpoint = h256_to_outpoint(cell_b_tx_hash, cell_b_index as u32)?;

    // Try to build and send transaction with wrong signature
    let tx = TransactionBuilder::default()
        .input(CellInput::new(cell_a_outpoint, 0))
        .output(CellOutput::new_builder()
            .capacity(Capacity::shannons(8000_0000_0000).pack())
            .lock(account_18_lock_script())
            .build())
        .output_data(Bytes::new().pack())
        .cell_dep(contract_dep())
        .cell_dep(CellDep::new_builder()
            .out_point(cell_b_outpoint)
            .dep_type(DepType::Code.into())
            .build())
        .cell_dep(secp256k1_dep(resolver))
        .witness(WitnessArgs::default().as_bytes().pack())
        .build();

    let signed_tx = sign_transaction_for_dynamic_ownership(tx, wrong_privkey)?;

    // Dump transaction JSON for debugging
    println!("\n=== Transaction JSON (attempting to unlock with wrong owner) ===");
    let tx_json: ckb_jsonrpc_types::Transaction = signed_tx.data().into();
    let json_str = serde_json::to_string_pretty(&tx_json)?;
    println!("{}", json_str);
    println!("=== End Transaction JSON ===\n");

    client.send_transaction(signed_tx.data().into(), None)?;

    Ok(())
}

// Helper functions for script creation
fn account_19_lock_script() -> Script {
    // Standard secp256k1 lock for account 19
    Script::new_builder()
        .code_hash(hex_to_byte32(SECP256K1_CODE_HASH).unwrap())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(hex::decode(&ACCOUNT_19_LOCK_ARG[2..]).unwrap()).pack())
        .build()
}

fn account_18_lock_script() -> Script {
    // Standard secp256k1 lock for account 18
    Script::new_builder()
        .code_hash(hex_to_byte32(SECP256K1_CODE_HASH).unwrap())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(hex::decode(&ACCOUNT_18_LOCK_ARG[2..]).unwrap()).pack())
        .build()
}

fn contract_dep() -> CellDep {
    CellDep::new_builder()
        .out_point(OutPoint::new(
            hex_to_byte32(CONTRACT_TX_HASH).unwrap(),
            CONTRACT_INDEX as u32,
        ))
        .dep_type(DepType::Code.into())
        .build()
}

fn secp256k1_dep(resolver: &DefaultCellDepResolver) -> CellDep {
    // Get the secp256k1 sighash dep from genesis block
    resolver.sighash_dep().expect("Failed to get secp256k1 dep from genesis").0.clone()
}

// Sign transaction for dynamic ownership
fn sign_transaction_for_dynamic_ownership(
    tx: TransactionView,
    privkey: &Privkey,
) -> Result<TransactionView, Box<dyn std::error::Error>> {
    let tx_hash = tx.hash();
    let witness = tx.witnesses().get(0).unwrap();
    let witness_for_digest = WitnessArgs::new_unchecked(witness.unpack())
        .as_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();

    let mut blake2b = new_blake2b();
    blake2b.update(tx_hash.as_slice());
    blake2b.update(&(witness_for_digest.as_bytes().len() as u64).to_le_bytes());
    blake2b.update(&witness_for_digest.as_bytes());

    let mut message = [0u8; 32];
    blake2b.finalize(&mut message);

    // Sign with ckb-crypto's SECP256K1
    let sig = privkey.sign_recoverable(&message.into())?;
    let sig_bytes = sig.serialize();

    let signed_witness = witness_for_digest
        .as_builder()
        .lock(Some(Bytes::from(sig_bytes.to_vec())).pack())
        .build();

    Ok(tx.as_advanced_builder()
        .set_witnesses(vec![signed_witness.as_bytes().pack()])
        .build())
}

// SDK-based signing for secp256k1 locks
fn sign_secp256k1_transaction(
    tx: TransactionView,
    privkey: &Privkey,
) -> Result<TransactionView, Box<dyn std::error::Error>> {
    // For secp256k1, we need to sign tx_hash | witness_for_digest
    // This follows the sighash_all signing scheme

    let witness = tx.witnesses().get(0).unwrap();
    let witness_for_digest = WitnessArgs::new_unchecked(witness.unpack())
        .as_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())  // Placeholder for signature
        .build();

    // Build the message to sign
    let mut blake2b = new_blake2b();
    let tx_hash = tx.hash();
    blake2b.update(tx_hash.as_slice());

    // Add the witness length and data
    let witness_bytes = witness_for_digest.as_bytes();
    blake2b.update(&(witness_bytes.len() as u64).to_le_bytes());
    blake2b.update(&witness_bytes);

    // Add remaining witnesses (if any) as empty
    for i in 1..tx.witnesses().len() {
        let w = tx.witnesses().get(i).unwrap();
        blake2b.update(&(w.len() as u64).to_le_bytes());
        blake2b.update(&w.raw_data());
    }

    let mut message = [0u8; 32];
    blake2b.finalize(&mut message);

    // Sign with ckb-crypto's SECP256K1
    let sig = privkey.sign_recoverable(&message.into())?;
    let sig_bytes = sig.serialize();

    // Build final witness with actual signature
    let signed_witness = witness_for_digest
        .as_builder()
        .lock(Some(Bytes::from(sig_bytes.to_vec())).pack())
        .build();

    Ok(tx.as_advanced_builder()
        .set_witnesses(vec![signed_witness.as_bytes().pack()])
        .build())
}

// Utility functions
fn blake160(data: &[u8]) -> [u8; 20] {
    let mut result = [0u8; 20];
    let hash = blake2b_256(data);
    result.copy_from_slice(&hash[0..20]);
    result
}

fn hex_to_byte32(hex: &str) -> Result<Byte32, Box<dyn std::error::Error>> {
    let bytes = hex::decode(&hex[2..])?;
    Ok(Byte32::from_slice(&bytes)?)
}

fn h256_to_outpoint(tx_hash: &H256, index: u32) -> Result<OutPoint, Box<dyn std::error::Error>> {
    Ok(OutPoint::new(
        hex_to_byte32(&format!("0x{}", hex::encode(tx_hash.as_bytes())))?,
        index,
    ))
}

async fn get_live_cell_for_account_19(
    client: &ckb_sdk::rpc::CkbRpcClient,
    min_capacity: u64,
) -> Result<(OutPoint, u64), Box<dyn std::error::Error>> {
    // Use SDK's cell collector to find unspent cells for account 19
    let lock_script = account_19_lock_script();

    // Create search key for cells with this lock
    let search_key = SearchKey {
        script: ckb_jsonrpc_types::Script::from(lock_script),
        script_type: ScriptType::Lock,
        script_search_mode: None,
        filter: None,
        with_data: Some(false),
        group_by_transaction: Some(false),
    };

    let order = Order::Desc;
    let limit = 50u32.into(); // Increase limit to search more cells
    let after = None;

    // Search for live cells
    let cells_response = client.get_cells(search_key, order, limit, after)?;

    if cells_response.objects.is_empty() {
        return Err("No live cells found for account 19. Please fund the account first.".into());
    }

    // Find a cell with sufficient capacity
    for cell in &cells_response.objects {
        let capacity: u64 = cell.output.capacity.into();

        if capacity >= min_capacity {
            let out_point = OutPoint::new(
                hex_to_byte32(&format!("0x{}", hex::encode(cell.out_point.tx_hash.as_bytes())))?,
                cell.out_point.index.into(),
            );
            return Ok((out_point, capacity));
        }
    }

    // No cell with sufficient capacity found
    Err(format!(
        "No cell found with sufficient capacity. Required: {} shannons ({} CKB), but all available cells have less.",
        min_capacity,
        min_capacity as f64 / 100_000_000.0
    ).into())
}

async fn wait_for_confirmation(
    client: &ckb_sdk::rpc::CkbRpcClient,
    tx_hash: &H256,
) -> Result<(), Box<dyn std::error::Error>> {
    // Poll until transaction is confirmed
    for _ in 0..30 {
        if let Ok(Some(tx_with_status)) = client.get_transaction(tx_hash.clone()) {
            if tx_with_status.tx_status.status == ckb_jsonrpc_types::Status::Committed {
                return Ok(());
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
    Err("Transaction not confirmed after 30 seconds".into())
}