# Dynamic Ownership System - Complete Story

## Overview

The Dynamic Ownership System is a novel approach to managing asset ownership on CKB blockchain. It separates the ownership authority from the asset itself, enabling flexible ownership transfers without moving the actual asset.

## Architecture: Two-Cell System

### Cell B (Authority Cell)
- **Role**: Contains the authorized public key hash that determines who can unlock Cell A
- **Lock Script**: Self-referential - uses its own `type_id` as lock args
- **Type Script**: Has a unique `type_id` that serves as its identity
- **Data**: Contains a 20-byte public key hash (blake160 hash of the public key)
- **Key Property**: Only the current owner (whose pubkey hash is in the data) can update Cell B, allowing them to transfer ownership by changing the pubkey hash

### Cell A (Protected Asset Cell)
- **Role**: The actual asset/resource being protected by dynamic ownership
- **Lock Script**: Dynamic ownership lock that references Cell B's `type_id` in its args
- **Type Script**: Can be anything or none (depends on the asset)
- **Data**: The actual asset data
- **Key Property**: Can only be unlocked by the owner specified in Cell B's data field

## Visual Representation

```
    Cell B (Authority)                    Cell A (Asset)
┌─────────────────────────┐        ┌─────────────────────────┐
│ Lock:                   │        │ Lock:                   │
│   Script: DynOwnership  │        │   Script: DynOwnership  │
│   Args: [Own TypeID]    │◄───────│   Args: [B's TypeID]    │
│                         │        │                         │
│ Type:                   │        │ Type:                   │
│   Script: TypeID        │        │   (Asset-specific)      │
│   Args: [Unique ID]     │        │                         │
│                         │        │ Data:                   │
│ Data:                   │        │   [Asset Content]       │
│   [Owner's PubkeyHash]  │        └─────────────────────────┘
└─────────────────────────┘
         ▲
         │
    Controls who can
    unlock Cell A
```

## The Complete Process Flow

### Step 1: Creating Cell B (Authority Cell)
1. Generate a unique `type_id` for Cell B
2. Create Cell B with:
   - Lock: Dynamic ownership lock with args = Cell B's own `type_id` (self-referential)
   - Type: Type ID script with the generated `type_id`
   - Data: Initial owner's pubkey hash (20 bytes)
3. Sign the transaction with the initial owner's private key
4. Cell B is now on-chain and can only be updated by the current owner

### Step 2: Creating Cell A (Protected Asset)
1. Create Cell A with:
   - Lock: Dynamic ownership lock with args = Cell B's `type_id`
   - Type: (Optional) Any type script for the asset
   - Data: The actual asset data
2. This links Cell A to Cell B's authority

### Step 3: Unlocking Cell A
To spend/unlock Cell A:
1. Include Cell A as input
2. Include Cell B as a dependency (to read its data)
3. The dynamic ownership lock script:
   - Reads Cell B's `type_id` from Cell A's lock args
   - Finds Cell B in dependencies
   - Extracts the pubkey hash from Cell B's data
   - Verifies the transaction signature matches this pubkey
4. Only the owner whose pubkey hash is in Cell B can successfully unlock Cell A

### Step 4: Ownership Transfer
To transfer ownership of Cell A to a new owner:
1. Current owner updates Cell B:
   - Spend Cell B (using current owner's signature)
   - Create new Cell B with:
     - Same lock script (self-referential with same `type_id`)
     - Same type script (preserves the `type_id`)
     - New data: New owner's pubkey hash
2. After this transaction:
   - Cell A remains unchanged
   - But now only the new owner can unlock Cell A
   - The new owner can further transfer ownership by updating Cell B again

## Ownership Transfer Flow Diagram

```
Initial State:
    Cell B                        Cell A
┌──────────────┐            ┌──────────────┐
│ Data: Alice  │◄───────────│ Lock→B.TypeID│
└──────────────┘            └──────────────┘
     Alice can unlock Cell A

After Transfer to Bob:
    Cell B'                       Cell A
┌──────────────┐            ┌──────────────┐
│ Data: Bob    │◄───────────│ Lock→B.TypeID│
└──────────────┘            └──────────────┘
     Bob can unlock Cell A

After Transfer to Charlie:
    Cell B''                      Cell A
┌──────────────┐            ┌──────────────┐
│ Data: Charlie│◄───────────│ Lock→B.TypeID│
└──────────────┘            └──────────────┘
     Charlie can unlock Cell A
```

## Key Security Properties

### 1. Cell B Protection
Only the current owner can update Cell B because:
- It's locked by dynamic ownership pointing to itself
- The lock checks that the signer's pubkey hash matches Cell B's data
- This creates a self-enforcing security loop

### 2. Cell A Protection
Only the authorized owner can unlock Cell A because:
- It references Cell B's `type_id` which is unique and persistent
- The lock always checks the current state of Cell B
- No one can forge or bypass the Cell B reference

### 3. Ownership Chain
Creates a clear chain of ownership transfers through Cell B updates:
- Each Cell B update is a recorded ownership transfer event
- The `type_id` remains constant, maintaining the link to Cell A
- Ownership history can be traced through Cell B's transaction history

## Test Scenario Walkthrough

The integration test demonstrates the full cycle:

1. **Alice creates Cell B**:
   - Self-referential lock with her pubkey hash in data
   - Establishes her as the initial authority

2. **Alice creates Cell A**:
   - References Cell B's `type_id` in its lock
   - Cell A is now under Alice's control

3. **Alice transfers to Bob**:
   - Updates Cell B's data to Bob's pubkey hash
   - Bob becomes the new authority

4. **Bob verifies ownership**:
   - Can successfully unlock Cell A
   - Alice can no longer unlock Cell A

5. **Bob transfers to Charlie**:
   - Updates Cell B's data to Charlie's pubkey hash
   - Charlie becomes the final authority

6. **Charlie spends Cell A**:
   - Successfully unlocks and spends Cell A
   - Demonstrates complete ownership control

## Benefits of This System

1. **Separation of Concerns**: Ownership authority is separate from the asset itself
2. **Efficient Transfers**: Ownership changes without moving the asset
3. **Atomic Operations**: Ownership transfer is a single transaction
4. **Flexibility**: Can be applied to any type of asset on CKB
5. **Traceability**: Clear ownership history through Cell B updates
6. **Composability**: Can be integrated with other CKB scripts and patterns

## Use Cases

- **NFT Ownership**: Transfer NFT ownership without moving the NFT cell
- **Asset Management**: Corporate assets with changing authorized managers
- **Escrow Services**: Third-party holds authority during escrow period
- **Time-locked Transfers**: Combine with time locks for scheduled ownership changes
- **Multi-signature Upgrades**: Cell B could itself use multisig for group ownership

## Technical Implementation Details

### Dynamic Ownership Lock Script
The lock script must:
1. Parse its args to get the target `type_id`
2. Search dependencies for a cell with matching `type_id`
3. Read the pubkey hash from that cell's data
4. Verify the transaction signature against this pubkey hash

### Type ID Script
Ensures uniqueness and persistence:
1. Generated deterministically from first input and output index
2. Remains constant across Cell B updates
3. Provides unforgeable reference for Cell A

### Signature Verification
Uses secp256k1 curve with blake2b hashing:
1. Message = blake2b(tx_hash || witness_data)
2. Signature must be from private key matching Cell B's pubkey hash
3. Recovery ID included for public key recovery

## Conclusion

The Dynamic Ownership System provides a powerful primitive for ownership management on CKB. By separating ownership authority from assets, it enables flexible, efficient, and secure ownership transfers while maintaining clear ownership chains and enabling complex ownership patterns.