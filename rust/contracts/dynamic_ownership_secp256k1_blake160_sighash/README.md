# Dynamic Ownership Lock Script


## Overview

This lock script extends the standard secp256k1 lock script by introducing **dynamic ownership**. It enables transferable ownership by referencing an external cell via type-id, which contains the current owner's public key hash.


Consider a cell containing assets ("Cell A") owned by Alice. With the conventional secp256k1 lock script, Cell A contains Alice's public key hash directly in its script args, and the lock script guarantees that Cell A can only be unlocked with a valid witness of Alice's private key. To transfer ownership to Bob, Cell A must be consumed and recreated with Bob's pubkey hash.

With the dynamic ownership lock script, the structure changes fundamentally. Instead of having Alice's public key hash in Cell A's script args, Cell A references the type-id of an external "Cell B". Cell B is a
type-id-enabled cell that contains Alice's public key hash in its data field. Cell A alone does not grant Alice direct access, both Cell B and Alice's signature witness are required to unlock Cell A. The 
type-id mechanism guarantees the uniqueness of Cell B across the entire blockchain, ensuring unambiguous ownership reference.

Ownership transfer becomes simpler: Alice can transfer control of Cell A to Bob by updating Cell B to contain Bob's pubkey hash, without ever modifying Cell A itself. 


## Architecture

```
┌──────────────────────────────────────────────┐
│  Cell A                                      │
│                                              │
│  Data: assets                                │
│                                              │
│  Lock Script: dynamic ownership lock script  │
│  args: type-id of Cell B                     │
└────────────────────────┼─────────────────────┘      
                         │
                         │ references
                         ▼
                  ┌───────────────────────────────┐
                  │  Cell B                       │
                  │                               │
                  │  Data: public key hash        │
                  │                               │
                  │  Type Script: type-id script  │
                  │  args: type-id of Cell B      │
                  └───────────────────────────────┘
```

## Algorithm

When executed, the script performs the following steps:

### 1. Extract Type-id
- Extract the 32-byte type-id from script args, such that we can uniquely identifies Cell B containing the owner's pubkey hash

### 2. Locate Cell B
- Search `cell_deps` for a cell with type script:
  - `code_hash`: type-id script code hash should match (`0x00000000000000000000000000000000000000000000000000545950455f4944`)
  - `args`: match the type-id from script args
- Load cell data from Cell B (must be exactly 20 bytes) as the blake160 hash of the current owner's public key

### 3. Extract Signature from Witness
- Load the first witness, and then extract the `lock` field containing the 65-byte recoverable signature
 
### 4. Build Message for Signature Verification
Compute blake2b hash of:

1. Current transaction hash
2. Modified first witness with lock field zeroed
3. All remaining witnesses in the same input group
4. All witnesses with index >= number of inputs

### 5. Verify Signature
- Parse the 65-byte recoverable signature (64 bytes compact sig + 1 byte recovery ID)
- Recover the public key from signature and message
- Compute blake160 hash of the recovered public key
- Compare with pubkey hash loaded from Cell B, verification succeeds if hashes match

## Script Args Format
```
┌──────────────────────────────────┐
│         type-id (32 bytes)       │
└──────────────────────────────────┘
```

The type-id must match the args of Cell B's type script.

## Cell B Specification

**Lock Script:**
- No requirements

**Type Script:**
- `code_hash`: `0x00000000000000000000000000000000000000000000000000545950455f4944`
- `hash_type`: `"type"`
- `args`: type-id (32 bytes)

**Data:**
- 20 bytes, blake160 hash of owner's public key

**Notes:**
- Must be in transaction's `cell_deps`


## Error Codes

| Code | Constant | Description |
|------|----------|----------------|
| `-1` | `ERROR_ARGUMENTS_LEN` | Script args is not 32 bytes, or signature is not 65 bytes |
| `-2` | `ERROR_ENCODING`      | Invalid witness or Cell B data |
| `-3` | `ERROR_SYSCALL`       | Syscall failure |
| `-11` | `ERROR_SECP_RECOVER_PUBKEY` | Cannot recover public key from signature |
| `-14` | `ERROR_SECP_PARSE_SIGNATURE` | Invalid secp256k1 signature |
| `-22` | `ERROR_WITNESS_SIZE` | Witness exceeds 32KB maximum size limit |
| `-31` | `ERROR_PUBKEY_BLAKE160_HASH` | Recovered public key hash does not match the hash stored in Cell B |
| `-32` | `ERROR_CELL_NOT_FOUND` | No cell in `cell_deps` matches the type-id specified in script args |

## Transcation Examples

### Paying Bob with Cell A owned by Alice

```
cycles: 1465858
fee: ~
min_replace_fee: ~
time_added_to_pool: ~
transaction:
  cell_deps:
    - dep_type: code
      out_point:
        index: 0
        tx_hash: dynamic_ownership_lock_script_creation_tx
    - dep_type: code
      out_point:
        index: 0
        tx_hash: cell_b_creation_tx
    - dep_type: dep_group
      out_point:
        index: 0
        tx_hash: std_secp256k1_lock_script_creation_tx
  hash: 0x58d84b5db1e1fde02464b686426120050eb57be1462fbbcfc4ffb8e44fea4b12
  header_deps: []
  inputs:
    - previous_output:
        index: 0
        tx_hash: cell_a_creation_tx
      since: 0x0 (absolute block(0))
  outputs:
    - capacity: "8999.9"
      lock:
        args: cell_b_type_id
        code_hash: dynamic_ownership_lock_scipt_code_hash
        hash_type: data1
      type: ~
    - capacity: "1000.0"
      lock:
        args: bob_lock_arg
        code_hash: std_secp256k1_lock_script_hash (sighash)
        hash_type: type
      type: ~
  outputs_data:
    - 0x
    - 0x
  version: 0
  witnesses:
    - witness_args_with_alice_signature
tx_status:
  block_hash: 0x4d46a3dfc7caafa460fae3fa7c70b586dd1a83ffd1f02df2a787b7aa04734cef
  block_number: 0xbc68
  reason: ~
  status: committed
  tx_index: 0x1
```

### Transfering ownership of Cell B from Alice to Bob 

```
cycles: 2495364
fee: ~
min_replace_fee: ~
time_added_to_pool: ~
transaction:
  cell_deps:
    - dep_type: code
      out_point:
        index: 0
        tx_hash: dynamic_ownership_lock_script_creation_tx
    - dep_type: code
      out_point:
        index: 0
        tx_hash: cell_b_creation_tx
    - dep_type: dep_group
      out_point:
        index: 0
        tx_hash: std_secp256k1_lock_script_creation_tx
  hash: 0xdd21dd83387568449e6c3b6c8fb0f678f08fe4efe699437daed5cbd373bc7747
  header_deps: []
  inputs:
    - previous_output:
        index: 0
        tx_hash: cell_b_creation_tx
      since: 0x0 (absolute block(0))
  outputs:
    - capacity: "199.99999"
      lock:
        args: cell_b_type_id
        code_hash: dynamic_ownership_lock_scipt_code_hash
        hash_type: data1
      type:
        args: cell_b_type_id
        code_hash: type_id_script_hash
        hash_type: type
  outputs_data:
    - bob_pub_key_hash
  version: 0
  witnesses:
    - witness_args_with_alice_signature
tx_status:
  block_hash: 0x028383f23bc53834967ed7ec508c636fa59c7e37edcdc2196242435a84174677
  block_number: 0xbc6b
  reason: ~
  status: committed
  tx_index: 0x1
```
