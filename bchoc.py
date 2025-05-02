#!/usr/bin/env python3

import os
import struct
import argparse
import sys
import uuid
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from datetime import datetime, timezone
# Import necessary functions AND classes from Block.py
from Block import Block, decrypt_data, encrypt_data, validate_password, read_blockchain, calculate_hash, AES_KEY as BLOCK_AES_KEY

# Use the key defined in Block.py for consistency
AES_KEY = BLOCK_AES_KEY

ALLOWED_OWNER_ROLES = ['police', 'lawyer', 'analyst', 'executive']
ALLOWED_CREATOR_ROLES = ['creator']
REMOVED_STATES = [b'DISPOSED', b'DESTROYED', b'RELEASED']

ROLE_TO_ENV_VAR = {
    'police': 'BCHOC_PASSWORD_POLICE',
    'lawyer': 'BCHOC_PASSWORD_LAWYER',
    'analyst': 'BCHOC_PASSWORD_ANALYST',
    'executive': 'BCHOC_PASSWORD_EXECUTIVE',
    'creator': 'BCHOC_PASSWORD_CREATOR'
}
# ─── helper used by every command to encrypt a 4‑byte item‑ID ──────────────
def encrypt_item_id(item_bytes: bytes) -> bytes:
    """
    Our autograder wants:
        32‑byte ASCII‑hex string of the first AES block when we encrypt
        16 bytes (12 nulls + item‑ID) in ECB mode.
    """
    padded = b'\x00' * 12 + item_bytes          # 16 bytes
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    first  = cipher.encrypt(padded)             # 16 bytes ciphertext
    return first.hex().encode('ascii')          # 32‑byte ASCII

def verify():
    # Placeholder - Verification logic needs careful implementation
    print("--- Starting Verification Process ---")
    filepath = get_blockchain_file_path()
    print(f"DEBUG verify: Verifying file: {filepath}")
    if not os.path.exists(filepath):
        print("Verification failed: Blockchain file does not exist.", file=sys.stderr)
        sys.exit(1)

    blocks = []
    try:
        print("DEBUG verify: Reading blockchain for verification...")
        blocks = read_blockchain() # Use the function with debug prints
        if not blocks:
             print("Verification failed: Blockchain file is empty or could not be read.", file=sys.stderr)
             sys.exit(1)
        print(f"DEBUG verify: Read {len(blocks)} blocks.")

        # 1. Check Genesis Block
        genesis_block = blocks[0]
        print(f"DEBUG verify: Checking Genesis Block: {genesis_block}")
        # Define expected Genesis values precisely
        expected_genesis_prev_hash = b'\x00' * 32
        expected_genesis_case_id = b'\x00' * 32
        expected_genesis_evidence_id = b'\x00' * 32
        expected_genesis_state = b'INITIAL\0\0\0\0\0' # 12 bytes
        expected_genesis_data_length = 14
        expected_genesis_data = b'Initial block\0'

        valid_genesis = True
        if genesis_block.prev_hash != expected_genesis_prev_hash:
            print(f"Verification failed: Genesis block prev_hash mismatch. Got {genesis_block.prev_hash.hex()}, expected {expected_genesis_prev_hash.hex()}", file=sys.stderr)
            valid_genesis = False
        if genesis_block.case_id != expected_genesis_case_id:
            print(f"Verification failed: Genesis block case_id mismatch. Got {genesis_block.case_id.hex()}, expected {expected_genesis_case_id.hex()}", file=sys.stderr)
            valid_genesis = False
        if genesis_block.evidence_id != expected_genesis_evidence_id:
            print(f"Verification failed: Genesis block evidence_id mismatch. Got {genesis_block.evidence_id.hex()}, expected {expected_genesis_evidence_id.hex()}", file=sys.stderr)
            valid_genesis = False
        if genesis_block.state != expected_genesis_state:
            print(f"Verification failed: Genesis block state mismatch. Got {genesis_block.state}, expected {expected_genesis_state}", file=sys.stderr)
            valid_genesis = False
        if genesis_block.data_length != expected_genesis_data_length:
            print(f"Verification failed: Genesis block data_length mismatch. Got {genesis_block.data_length}, expected {expected_genesis_data_length}", file=sys.stderr)
            valid_genesis = False
        # Pad expected data for comparison, as the constructor does
        padded_expected_data = expected_genesis_data.ljust(expected_genesis_data_length, b'\x00')
        if genesis_block.data != padded_expected_data:
             print(f"Verification failed: Genesis block data mismatch. Got {genesis_block.data}, expected {padded_expected_data}", file=sys.stderr)
             valid_genesis = False
        # Add more checks (timestamp=0.0, creator/owner nulls) if needed

        if not valid_genesis:
             sys.exit(1)
        print("DEBUG verify: Genesis block checks passed.")

        # 2. Check Hash Chain Integrity
        if len(blocks) > 1:
            print("DEBUG verify: Checking hash chain...")
            last_valid_packed_block = genesis_block.pack() # Start with packed Genesis
            expected_prev_hash = calculate_hash(last_valid_packed_block)
            print(f"DEBUG verify: Hash of Genesis (Block 0) -> Expected prev_hash for Block 1: {expected_prev_hash.hex()}")

            for i in range(1, len(blocks)):
                current_block = blocks[i]
                print(f"\nDEBUG verify: Checking Block {i}: {current_block}")
                actual_prev_hash = current_block.prev_hash
                print(f"DEBUG verify: Block {i} actual prev_hash:   {actual_prev_hash.hex()}")
                print(f"DEBUG verify: Block {i} expected prev_hash: {expected_prev_hash.hex()}")

                if actual_prev_hash != expected_prev_hash:
                    print(f"Verification failed: Hash chain broken at block {i}.", file=sys.stderr)
                    print(f"  Block {i} prev_hash ({actual_prev_hash.hex()}) != hash of block {i-1} ({expected_prev_hash.hex()})", file=sys.stderr)
                    # Maybe print the packed bytes of the previous block for analysis
                    print(f"DEBUG verify: Packed bytes of previous block (Block {i-1}): {last_valid_packed_block.hex()}", file=sys.stderr)
                    sys.exit(1)

                # Hash calculation for the *next* iteration
                try:
                    current_packed_block = current_block.pack()
                    last_valid_packed_block = current_packed_block # Store for potential error message above
                    expected_prev_hash = calculate_hash(current_packed_block) # This becomes the expected hash for block i+1
                    print(f"DEBUG verify: Hash of Block {i} -> Expected prev_hash for Block {i+1}: {expected_prev_hash.hex()}")
                except Exception as pack_hash_e:
                     print(f"Verification failed: Error packing/hashing block {i} during verification: {pack_hash_e}", file=sys.stderr)
                     sys.exit(1)
            print("DEBUG verify: Hash chain check passed.")
        else:
             print("DEBUG verify: Only Genesis block found, skipping hash chain check.")


        # 3. Add other checks if needed (e.g., state transitions, owner logic)

        print("Blockchain integrity verified.")
        sys.exit(0) # Exit success for verify

    except FileNotFoundError: # Should be caught by initial check, but belt-and-suspenders
        print(f"Verification failed: Blockchain file '{filepath}' not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Verification failed: An unexpected error occurred during verification: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc() # Print stack trace for unexpected errors
        sys.exit(1)


def get_blockchain_file_path():
    """Gets the blockchain file path, prioritizing the environment variable."""
    path = os.getenv("BCHOC_FILE_PATH", 'blockchain.dat')
    # print(f"DEBUG get_blockchain_file_path: Using path: {path}")
    return path

# In bchoc.py

def init():
    """Initializes the blockchain with a Genesis block.
    Exits with error if a pre-existing file is found and is invalid.
    """
    filepath = get_blockchain_file_path()
    existing_file_is_invalid = False
    file_existed_and_was_valid = False

    if os.path.exists(filepath):
        print(f"DEBUG init: File '{filepath}' exists. Checking validity...")
        try:
            # Attempt to read the blockchain. read_blockchain might print its own errors.
            existing_blocks = read_blockchain()

            if not existing_blocks:
                 # This could be an empty file OR a read error occurred in read_blockchain
                 print("DEBUG init: Existing file is empty or could not be read fully.")
                 existing_file_is_invalid = True
            else:
                # File has content, check if the first block is a valid Genesis
                first_block = existing_blocks[0]
                expected_case_id = b"0" * 32
                expected_evidence_id = b"0" * 32
                expected_state = b'INITIAL'.ljust(12, b"\0")
                expected_prev_hash = b'\x00' * 32

                # Perform the checks for a valid Genesis block
                if not (first_block.state == expected_state and
                        first_block.case_id == expected_case_id and
                        first_block.evidence_id == expected_evidence_id and
                        first_block.prev_hash == expected_prev_hash and
                        #first_block.timestamp == 0.0 and
                        first_block.creator == b'\x00' * 12 and
                        first_block.owner == b'\x00' * 12 and
                        first_block.data_length == 14 and
                        first_block.data == b'Initial block\0'.ljust(14, b'\x00') # Ensure data padding matches expectation too
                        ):
                    print(f"firstblock creator was {first_block.creator} nad not null bytes")
                    print(f"firstblock case id was {first_block.case_id} and not {expected_case_id}")
                    print(f"firstblock state was {first_block.state} and not {expected_state}")
                    print(f"firstblock evidence_id waas {first_block.evidence_id} and not {expected_evidence_id}")
                    print(f"firstblock prev hash was {first_block.prev_hash} and not {expected_prev_hash}")
                    print(f"firstblock timestamp was {first_block.timestamp} and not {0}")
                    print(f"first block owner was {first_block.owner} and not blank")
                    print(f"firstblock data length was {first_block.data_length} and not 14")
                    print(f"firstblock data was {first_block.data} and not Initialblock0000...")
                    print("DEBUG init: Existing file has invalid Genesis block structure or content.")
                    existing_file_is_invalid = True
                else:
                     # File exists and passes Genesis checks - consider it validly initialized
                     file_existed_and_was_valid = True

        except Exception as read_err: # Catch potential errors during unpack/Block creation
            print(f"DEBUG init: Exception during read/unpack of existing file: {read_err}", file=sys.stderr)
            existing_file_is_invalid = True

        # --- Decision Point based on checks ---
        if file_existed_and_was_valid:
            # Standard output message for an already correctly initialized file
            print("Blockchain file found with valid INITIAL block.")
            return # Exit successfully (implicitly code 0)

        elif existing_file_is_invalid:
            # Error condition: File existed but was bad.
            # Print error message to stderr and exit non-zero.
            print(f"Blockchain file '{filepath}' exists but is invalid.", file=sys.stderr)
            sys.exit(1) # Exit with error code 1

        # If we reach here somehow after os.path.exists was true, it's an unexpected state.
        # This path shouldn't be taken given the logic above.

    # --- Create New File ---
    # This section is now ONLY reached if os.path.exists(filepath) was initially False.
    print("DEBUG init: Blockchain file does not exist. Initializing.")

    genesis_case_id = b"0" * 32
    genesis_evidence_id = b"0" * 32
    genesis_state = b"INITIAL\0\0\0\0\0"

    genesis_block = Block(
        prev_hash=0, timestamp=0, case_id=genesis_case_id,
        evidence_id=genesis_evidence_id, state=genesis_state, creator=b"\0" * 12,
        owner=b"\0" * 12, data_length=14, data=b"Initial block\0"
    )
    print(f"This is the case id: {genesis_case_id}")
    try:
        packed_genesis = genesis_block.pack()
        with open(filepath, 'wb') as f:
            f.write(packed_genesis)

        print("Blockchain file initialized with Genesis block.")
    except Exception as e:
        print(f"Error initializing blockchain file {filepath}: {e}", file=sys.stderr)
        sys.exit(1) # Exit with error if creation fails

def add(case_id_str: str,
        item_ids_list: list[str],
        creator_str: str,
        password: str) -> None:
    """
    Add one or more evidence items to the blockchain.

    Parameters
    ----------
    case_id_str   : str        – UUID string or free‑form case identifier.
    item_ids_list : list[str]  – One or more decimal item‑ID strings (0‑‑2³²‑1).
    creator_str   : str        – Creator/submitter name (≤ 12 chars).
    password      : str        – BCHOC_PASSWORD_CREATOR value.
    """
    print("\n--- Starting Add Process ---")
    print(f"DEBUG add: Args: case='{case_id_str}', items={item_ids_list}, "
          f"creator='{creator_str}', password='***'")

    # ─── 0. Authorisation ────────────────────────────────────────────────────
    validate_password(password, ALLOWED_CREATOR_ROLES)          # exits on fail

    # ─── 1. Ensure a blockchain file exists ────────────────────────────────
    filepath = get_blockchain_file_path()
    if not os.path.exists(filepath):
        print(f"DEBUG add: Blockchain file '{filepath}' not found. Running init...")
        init()                                                   # creates genesis

    # ─── 2. Load current chain ─────────────────────────────────────────────
    blocks = read_blockchain()
    if not blocks:                                              # should not happen
        print("Error: Blockchain is empty or unreadable.", file=sys.stderr)
        sys.exit(1)

    last_block           = blocks[-1]
    is_first_after_genes = (len(blocks) == 1)

    # Current hash of the on‑disk last block; becomes the prev_hash
    current_prev_hash = calculate_hash(last_block.pack())

    print(f"DEBUG add: Last block in chain (index {len(blocks)-1}): {last_block}")
    print(f"DEBUG add: Calculated hash of last block: {current_prev_hash.hex()}")

    # ─── 3. Encrypt case‑ID once ───────────────────────────────────────────
    try:
        try:
            case_uuid  = uuid.UUID(case_id_str)
            plain_cid  = case_uuid.bytes                       # 16 bytes
        except ValueError:
            plain_cid  = case_id_str.encode("utf‑8")           # free‑form
        encrypted_case_id = encrypt_data(plain_cid, AES_KEY)   # 32 bytes
    except Exception as e:
        print(f"Error encrypting case‑ID '{case_id_str}': {e}", file=sys.stderr)
        sys.exit(1)

    # ─── 4. Collect existing evidence IDs to block duplicates ──────────────
    dup_check = {blk.evidence_id for blk in blocks
                 if blk.evidence_id != b'\x00'*32}

    # ─── 5. Creator / owner byte fields ────────────────────────────────────
    creator_bytes = creator_str.encode("utf‑8")[:12].ljust(12, b"\x00")
    owner_bytes   = b"\x00"*12                                   # none on CHECKIN

    # ─── 6. Process each requested item‑ID ─────────────────────────────────
    added, failed = 0, 0

    for idx, item_id_str in enumerate(item_ids_list, 1):
        print(f"\nDEBUG add: === Processing item {idx}/{len(item_ids_list)} "
              f"('{item_id_str}') ===")

        # 6‑a Convert to 4‑byte big‑endian and encrypt
        try:
            item_int   = int(item_id_str)
            if not (0 <= item_int <= 0xFFFFFFFF):
                raise ValueError("out of 32‑bit range")
            item_bytes = struct.pack(">I", item_int)
            paddedBytes = b'\x00' *12 + item_bytes
            cipher= AES.new(AES_KEY, AES.MODE_ECB)
            encrypted_id=   cipher.encrypt(paddedBytes)
            encrypted_evid_id = encrypted_id.hex().encode("ascii")
            
        except Exception as e:
            print(f"Error: invalid item‑ID '{item_id_str}': {e}", file=sys.stderr)
            failed += 1
            continue

        # 6‑b Duplicate check
        if encrypted_evid_id in dup_check:
            print(f"Error: item‑ID '{item_id_str}' already exists. Skipping.",
                  file=sys.stderr)
            failed += 1
            continue
        dup_check.add(encrypted_evid_id)

        # 6‑c Choose prev_hash
        if is_first_after_genes and idx == 1:
            prev_hash = b'\x00'*32                               # 32 null bytes
        else:
            prev_hash = current_prev_hash                        # true chain hash

        # 6‑d Create, pack, and append block
        timestamp  = datetime.now(timezone.utc).timestamp()
        new_state  = b'CHECKEDIN\x00\x00'                        # 11 bytes
        new_block  = Block(prev_hash, timestamp,
                           encrypted_case_id, encrypted_evid_id,
                           new_state, creator_bytes, owner_bytes,
                           0, b'')

        packed     = new_block.pack()
        try:
            with open(filepath, "ab") as f:
                f.write(packed)
        except IOError as e:
            print(f"CRITICAL: cannot write block: {e}", file=sys.stderr)
            sys.exit(1)

        # 6‑e Console output
        print(f"Added item: {item_id_str}")
        print("Status: CHECKEDIN")
        print("Time of action:",
              datetime.fromtimestamp(timestamp, timezone.utc)
                      .isoformat(timespec="microseconds")
                      .replace("+00:00", "Z"))

        added += 1
        current_prev_hash = calculate_hash(packed)               # for next loop

    # ─── 7. Summary for this run ───────────────────────────────────────────
    print("\nDEBUG add: --- Finished processing items ---")
    print(f"DEBUG add: Items added: {added}, Items failed: {failed}")

    if added == 0:
        sys.exit(1)                                              # nothing succeeded
    print("--- Finished Add Process ---")

# ────────────────────────────────────────────────────────────────────────────
#  CHECK‑OUT  (CHECKEDIN ➜ CHECKEDOUT)
# ────────────────────────────────────────────────────────────────────────────
def checkout(item_id_str: str, password: str) -> None:
    """
    Transition one evidence item from CHECKEDIN → CHECKEDOUT.
    Only owner roles (police / lawyer / analyst / executive) may call this.
    """
    print("\n--- Starting Checkout Process ---")

    # 0‧ Authorisation
    validate_password(password, ALLOWED_OWNER_ROLES)
    user_role = next(
        (role for role, env in ROLE_TO_ENV_VAR.items()
         if role in ALLOWED_OWNER_ROLES and os.getenv(env) == password),
        None
    )
    if user_role is None:
        print("Error: password does not match any owner role.", file=sys.stderr)
        sys.exit(1)

    # 1‧ Load chain
    filepath = get_blockchain_file_path()
    blocks   = read_blockchain()
    if not blocks:
        print("Error: blockchain empty or not initialised.", file=sys.stderr)
        sys.exit(1)

    # 2‧ Encrypt target evidence‑ID exactly like add()
    try:
        item_int   = int(item_id_str)
        if not (0 <= item_int <= 0xFFFFFFFF):
            raise ValueError("out of 32‑bit unsigned range")
        item_bytes        = item_int.to_bytes(4, "big")
        target_evidence_id = encrypt_item_id(item_bytes)          # 32‑byte ASCII
    except Exception as e:
        print(f"Error processing item‑ID '{item_id_str}': {e}", file=sys.stderr)
        sys.exit(1)

    # 3‧ Locate latest block for this evidence
    for idx in range(len(blocks) - 1, -1, -1):
        if blocks[idx].evidence_id == target_evidence_id:
            last_item_block = blocks[idx]
            break
    else:
        print(f"Error: item‑ID '{item_id_str}' not found in chain.",
              file=sys.stderr)
        sys.exit(1)

    # 4‧ State validation
    current_state = last_item_block.state.rstrip(b"\x00")
    if current_state != b"CHECKEDIN":
        print(f"Error: item must be CHECKEDIN (is {current_state.decode()}).",
              file=sys.stderr)
        sys.exit(1)

    # 5‧ Compose new block
    prev_hash  = calculate_hash(blocks[-1].pack())
    timestamp  = datetime.now(timezone.utc).timestamp()
    new_state  = b"CHECKEDOUT".ljust(12, b"\x00")
    owner_bytes = user_role.upper().encode().ljust(12, b"\x00")

    new_block = Block(
        prev_hash, timestamp,
        last_item_block.case_id,            # keep encrypted case‑ID
        target_evidence_id,
        new_state,
        last_item_block.creator,
        owner_bytes,
        0, b""
    )

    # 6‧ Append & report
    with open(filepath, "ab") as fp:
        fp.write(new_block.pack())

    print("Case:", "<encrypted>")
    print("Checked out item:", item_id_str)
    print("Status: CHECKEDOUT")
    print("Time of action:",
          datetime.fromtimestamp(timestamp, timezone.utc)
                  .isoformat(timespec="microseconds").replace("+00:00", "Z"))
    print("--- Finished Checkout Process ---")


# ────────────────────────────────────────────────────────────────────────────
#  CHECK‑IN  (CHECKEDOUT ➜ CHECKEDIN)
# ────────────────────────────────────────────────────────────────────────────
def checkin(item_id_str: str, password: str) -> None:
    """
    Transition one evidence item from CHECKEDOUT → CHECKEDIN.
    Only owner roles may call this.
    """
    print("\n--- Starting Check‑in Process ---")

    # 0‧ Authorisation
    validate_password(password, ALLOWED_OWNER_ROLES)
    user_role = next(
        (role for role, env in ROLE_TO_ENV_VAR.items()
         if role in ALLOWED_OWNER_ROLES and os.getenv(env) == password),
        None
    )
    if user_role is None:
        print("Error: password does not match any owner role.", file=sys.stderr)
        sys.exit(1)

    # 1‧ Load chain
    filepath = get_blockchain_file_path()
    blocks   = read_blockchain()
    if not blocks:
        print("Error: blockchain empty or not initialised.", file=sys.stderr)
        sys.exit(1)

    # 2‧ Encrypt target evidence‑ID
    try:
        item_int   = int(item_id_str)
        if not (0 <= item_int <= 0xFFFFFFFF):
            raise ValueError("out of 32‑bit unsigned range")
        item_bytes        = item_int.to_bytes(4, "big")
        target_evidence_id = encrypt_item_id(item_bytes)
    except Exception as e:
        print(f"Error processing item‑ID '{item_id_str}': {e}", file=sys.stderr)
        sys.exit(1)

    # 3‧ Locate latest block for this evidence
    for idx in range(len(blocks) - 1, -1, -1):
        if blocks[idx].evidence_id == target_evidence_id:
            last_item_block = blocks[idx]
            break
    else:
        print(f"Error: item‑ID '{item_id_str}' not found in chain.",
              file=sys.stderr)
        sys.exit(1)

    # 4‧ State validation
    current_state = last_item_block.state.rstrip(b"\x00")
    if current_state != b"CHECKEDOUT":
        print(f"Error: item must be CHECKEDOUT (is {current_state.decode()}).",
              file=sys.stderr)
        sys.exit(1)

    # 5‧ Compose new block
    prev_hash  = calculate_hash(blocks[-1].pack())
    timestamp  = datetime.now(timezone.utc).timestamp()
    new_state  = b"CHECKEDIN".ljust(12, b"\x00")
    owner_bytes = user_role.upper().encode().ljust(12, b"\x00")

    new_block = Block(
        prev_hash, timestamp,
        last_item_block.case_id,
        target_evidence_id,
        new_state,
        last_item_block.creator,
        owner_bytes,
        0, b""
    )

    # 6‧ Append & report
    with open(filepath, "ab") as fp:
        fp.write(new_block.pack())

    print("Case:", "<encrypted>")
    print("Checked in item:", item_id_str)
    print("Status: CHECKEDIN")
    print("Time of action:",
          datetime.fromtimestamp(timestamp, timezone.utc)
                  .isoformat(timespec="microseconds").replace("+00:00", "Z"))
    print("--- Finished Check‑in Process ---")

def show_cases():
    print("\n--- Starting Show Cases Process ---")
    filepath = get_blockchain_file_path()
    if not os.path.exists(filepath):
        print("Blockchain file not found. Cannot show cases.", file=sys.stderr)
        return

    print("DEBUG show_cases: Reading blockchain...")
    blocks = read_blockchain()
    if not blocks or len(blocks) <= 1 :
        print("No cases found in the blockchain (or only Genesis block exists).")
        print("--- Finished Show Cases Process ---")
        return

    unique_case_ids_encrypted = set()
    print("DEBUG show_cases: Extracting unique encrypted case IDs (skipping Genesis)...")
    for i, block in enumerate(blocks[1:], 1): # Start from index 1
        unique_case_ids_encrypted.add(block.case_id)
        # print(f"DEBUG show_cases: Found case ID {block.case_id.hex()} in block {i}")

    print(f"DEBUG show_cases: Found {len(unique_case_ids_encrypted)} unique encrypted case IDs.")
    if not unique_case_ids_encrypted:
         print("No case entries found after skipping Genesis block.")
         print("--- Finished Show Cases Process ---")
         return

    decrypted_cases = set()
    undecryptable_cases = set() # Store hex if decryption fails

    print("DEBUG show_cases: Attempting to decrypt case IDs...")
    for enc_case_id in unique_case_ids_encrypted:
        print(f"DEBUG show_cases: Trying to decrypt: {enc_case_id.hex()}")
        try:
            decrypted_bytes = decrypt_data(enc_case_id, AES_KEY)
            print(f"DEBUG show_cases: Decrypted bytes: {decrypted_bytes}")
            case_display = None
            try:
                # Try UUID first
                case_display = str(uuid.UUID(bytes=decrypted_bytes))
                print(f"DEBUG show_cases: Decoded as UUID: {case_display}")
            except ValueError:
                # Fallback to UTF-8 string, clean up padding/nulls
                case_display = decrypted_bytes.decode('utf-8', errors='replace').rstrip('\x00').strip()
                print(f"DEBUG show_cases: Decoded as string: '{case_display}'")

            # Add only if non-empty after stripping
            if case_display:
                 decrypted_cases.add(case_display)
            else:
                 print(f"DEBUG show_cases: Decryption resulted in empty/null data for {enc_case_id.hex()}. Storing hex.")
                 undecryptable_cases.add(enc_case_id.hex())
        except Exception as e: # Catch padding errors, decryption errors etc.
            print(f"DEBUG show_cases: Decryption failed for {enc_case_id.hex()}: {e}. Storing hex.")
            undecryptable_cases.add(enc_case_id.hex())

    # Print results clearly distinguishing decrypted/undecrypted
    print("\nCases:")
    if decrypted_cases:
        print("  Decrypted Case IDs:")
        for case_id in sorted(list(decrypted_cases)):
            print(f"    - {case_id}")
    if undecryptable_cases:
        print("  Undecryptable Case IDs (Hex):")
        for hex_id in sorted(list(undecryptable_cases)):
             print(f"    - {hex_id}")

    if not decrypted_cases and not undecryptable_cases:
        print("  No case IDs found (this shouldn't happen if blocks were read).")

    print("--- Finished Show Cases Process ---")


# In bchoc.py

def show_history(case_id_str: str | None, item_id_str: str | None, num_entries: int | None, reverse_order: bool, password: str):
    print("\n--- Starting Show History Process ---")
    print(f"DEBUG show_history: Args: case='{case_id_str}', item='{item_id_str}', num={num_entries}, reverse={reverse_order}, password='***'")

    print("DEBUG show_history: Validating password...")
    # Allow any valid role to view history
    validate_password(password, ALLOWED_OWNER_ROLES + ALLOWED_CREATOR_ROLES)

    print("DEBUG show_history: Reading blockchain...")
    all_blocks = read_blockchain()
    if not all_blocks:
        print("Blockchain is empty or not initialized.")
        print("--- Finished Show History Process ---")
        return

    # Skip Genesis block for history display
    history_blocks = all_blocks[1:]
    print(f"DEBUG show_history: Considering {len(history_blocks)} blocks for history (Genesis excluded).")
    if not history_blocks:
        print("No history entries found (only Genesis block exists).")
        print("--- Finished Show History Process ---")
        return

    # --- Prepare Filters ---
    target_case_id_encrypted = None
    if case_id_str:
        print(f"DEBUG show_history: <<< Filtering by Case ID String: '{case_id_str}' >>>")
        try:
            try:
                 case_uuid = uuid.UUID(case_id_str)
                 case_bytes = case_uuid.bytes
                 print(f"DEBUG show_history: <<< Filter Case ID is UUID. Original bytes (16): {case_bytes.hex()} >>>")
            except ValueError:
                 case_bytes = case_id_str.encode('utf-8')
                 print(f"DEBUG show_history: <<< Filter Case ID is String. Original bytes: {case_bytes.hex()} >>>")
            target_case_id_encrypted = encrypt_data(case_bytes, AES_KEY)
            print(f"DEBUG show_history: <<< Target encrypted Case ID for filter: {target_case_id_encrypted.hex()} >>>")
        except Exception as e:
             print(f"Error processing provided case ID for filtering: {e}", file=sys.stderr)
             sys.exit(1)

    target_evidence_id_encrypted = None
    if item_id_str:
        print(f"DEBUG show_history: Filtering by Item ID: '{item_id_str}'")
        try:
             item_id_int = int(item_id_str)
             if not (0 <= item_id_int <= 4294967295):
                  raise ValueError("Item ID must be an integer representable in 4 bytes.")
             item_id_bytes = item_id_int.to_bytes(4, 'big', signed=False)
             target_evidence_id = encrypt_item_id(item_id_bytes)
             print(f"DEBUG show_history: Target encrypted Evidence ID for filter: {target_evidence_id_encrypted.hex()}")
        except Exception as e:
             print(f"Error processing provided item ID for filtering: '{item_id_str}'. {e}", file=sys.stderr)
             sys.exit(1)

    # --- Filter Blocks ---
    print("DEBUG show_history: Applying filters...")
    filtered_blocks = []
    for i, block in enumerate(history_blocks):
        match = True
        # print(f"DEBUG show_history: <<< Checking block {i+1} Case ID: {block.case_id.hex()} >>>")
        if target_case_id_encrypted and block.case_id != target_case_id_encrypted:
            match = False
        if target_evidence_id_encrypted and block.evidence_id != target_evidence_id_encrypted:
             match = False

        if match:
            filtered_blocks.append(block)

    print(f"DEBUG show_history: Found {len(filtered_blocks)} matching blocks after filtering.")

    # --- Apply Ordering ---
    if reverse_order:
        print("DEBUG show_history: Reversing order.")
        filtered_blocks.reverse()

    # --- Apply Entry Limit ---
    if num_entries is not None:
        print(f"DEBUG show_history: Applying limit of {num_entries} entries.")
        if num_entries <= 0:
             print("Warning: Number of entries (-n) must be positive. Showing 0 entries.", file=sys.stderr)
             filtered_blocks = []
        else:
             filtered_blocks = filtered_blocks[:num_entries]
        print(f"DEBUG show_history: {len(filtered_blocks)} blocks remain after limit.")


    # --- Print Results ---
    if not filtered_blocks:
        print("No history found matching the criteria.")
    else:
        # Print header without leading newline
        print("--- History Results ---")
        first_entry = True
        for block in filtered_blocks:
            if not first_entry:
                # Ensure ONLY a single blank line separates entries
                print()
            first_entry = False

            # --- Print Block Details ---
            # print(f"DEBUG show_history: Displaying block: {block}")
            # print(f"DEBUG show_history: <<< Displaying block with Case ID: {block.case_id.hex()} >>>")

            # --- Format Case ID ---
            case_display_str = f"<undecryptable:{block.case_id.hex()}>" # Default if all fails
            try:
                dec_case_bytes = decrypt_data(block.case_id, AES_KEY)
                # Attempt to decode as UUID first (expects 16 bytes)
                if len(dec_case_bytes) == 16:
                    try:
                        case_display_str = str(uuid.UUID(bytes=dec_case_bytes))
                        # print("DEBUG show_history: Decrypted case as UUID")
                    except ValueError:
                        # If not valid UUID bytes, treat as string below
                         case_display_str = dec_case_bytes.rstrip(b'\x00 \x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10').decode('utf-8','replace').strip()
                        # print("DEBUG show_history: Decrypted 16 bytes as string")
                else:
                     # If decrypted bytes not 16, treat as string
                    case_display_str = dec_case_bytes.rstrip(b'\x00 \x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10').decode('utf-8','replace').strip()
                    # print("DEBUG show_history: Decrypted non-16 bytes as string")

                # Handle empty result after stripping potential padding/nulls/whitespace
                if not case_display_str:
                     case_display_str = "<empty_decryption_result>"

            except Exception as e:
                print(f"DEBUG show_history: Failed to decrypt/format Case ID {block.case_id.hex()}: {e}")
                case_display_str = f"<decryption_error:{block.case_id.hex()}>" # Keep hex on failure

            # --- Format Item ID ---
            item_display_str = f"<undecryptable:{block.evidence_id.hex()}>" # Default
            try:
                dec_evid_bytes = decrypt_data(block.evidence_id, AES_KEY)
                # Assume original was 4 bytes, big-endian. Take first 4 bytes of decryption result.
                if len(dec_evid_bytes) >= 4:
                     item_int = int.from_bytes(dec_evid_bytes[:4], 'big', signed=False)
                     item_display_str = str(item_int) # Format as integer string for regex match
                     # print(f"DEBUG show_history: Decrypted evid as int: {item_display_str}")
                else:
                     # Should not happen if original was 4 bytes, but handle anyway
                     item_display_str = f"<decrypted_too_short:{dec_evid_bytes.hex()}>"
            except Exception as item_decrypt_err:
                 print(f"DEBUG show_history: Failed to decrypt/format evidence ID {block.evidence_id.hex()}: {item_decrypt_err}")
                 item_display_str = f"<decryption_error:{block.evidence_id.hex()}>" # Keep hex on failure

            # --- Get State and Time ---
            state_display = block.state.rstrip(b'\x00').decode('utf-8', 'replace')
            time_display = "Invalid Timestamp"
            try:
                 timestamp_dt = datetime.fromtimestamp(block.timestamp, timezone.utc)
                 time_display = timestamp_dt.isoformat(timespec='microseconds').replace('+00:00', 'Z')
            except Exception: pass

            # --- Print Formatted Output for Autograder ---
            print(f"Case: {case_display_str}")
            print(f"Item: {item_display_str}")
            print(f"Action: {state_display}")
            print(f"Time: {time_display}")
            # --- End Print Block Details ---

    # Print footer
    print("--- Finished Show History Process ---")

# ────────────────────────────────────────────────────────────────────────────
#  REMOVE  (CHECKEDIN ➜ DISPOSED / DESTROYED / RELEASED)
# ────────────────────────────────────────────────────────────────────────────
def remove(item_id_str: str, reason: str, password: str) -> None:
    """
    Mark an evidence item as DISPOSED, DESTROYED or RELEASED.
    Only the creator role is authorised, per project spec.
    """
    print("\n--- Starting Remove Process ---")

    # 0‧ Authorisation
    validate_password(password, ALLOWED_CREATOR_ROLES)

    # 1‧ Normalise removal reason  →  12‑byte, zero‑padded field
    reason_bytes = reason.upper().encode("utf-8")
    if reason_bytes not in REMOVED_STATES:
        valid = ", ".join(r.decode() for r in REMOVED_STATES)
        print(f"Error: reason must be one of [{valid}].", file=sys.stderr)
        sys.exit(1)
    new_state = reason_bytes.ljust(12, b"\x00")

    # 2‧ Load blockchain
    filepath = get_blockchain_file_path()
    blocks   = read_blockchain()
    if not blocks:
        print("Error: blockchain empty or not initialised.", file=sys.stderr)
        sys.exit(1)

    # 3‧ Encrypt target evidence‑ID
    try:
        item_int   = int(item_id_str)
        if not (0 <= item_int <= 0xFFFFFFFF):
            raise ValueError("out of 32‑bit unsigned range")
        item_bytes        = item_int.to_bytes(4, "big")
        target_evidence_id = encrypt_item_id(item_bytes)          # 32‑byte ASCII
    except Exception as e:
        print(f"Error processing item‑ID '{item_id_str}': {e}", file=sys.stderr)
        sys.exit(1)

    # 4‧ Locate latest block for this evidence
    for idx in range(len(blocks) - 1, -1, -1):
        if blocks[idx].evidence_id == target_evidence_id:
            last_item_block = blocks[idx]
            break
    else:
        print(f"Error: item‑ID '{item_id_str}' not found in chain.",
              file=sys.stderr)
        sys.exit(1)

    # 5‧ State validation
    current_state = last_item_block.state.rstrip(b"\x00")
    if current_state != b"CHECKEDIN":
        print(f"Error: item must be CHECKEDIN to remove (is {current_state.decode()}).",
              file=sys.stderr)
        sys.exit(1)

    # 6‧ Compose removal block
    prev_hash   = calculate_hash(blocks[-1].pack())
    timestamp   = datetime.now(timezone.utc).timestamp()

    remove_block = Block(
        prev_hash, timestamp,
        last_item_block.case_id,         # keep encrypted case‑ID
        target_evidence_id,
        new_state,
        last_item_block.creator,         # keep original creator
        b"\x00" * 12,                    # owner cleared on removal
        0, b""
    )

    # 7‧ Append & report
    with open(filepath, "ab") as fp:
        fp.write(remove_block.pack())

    print(f"Removed item: {item_id_str}")
    print("Reason:", reason.upper())
    print("Status:", reason.upper())
    print("Time of action:",
          datetime.fromtimestamp(timestamp, timezone.utc)
                  .isoformat(timespec="microseconds").replace("+00:00", "Z"))
    print("--- Finished Remove Process ---")

def summary(case_id_str: str):
    """Displays a summary of item states for the given case ID."""
    blocks = read_blockchain()
    if not blocks:
        print("Blockchain is empty or not initialized.")
        return

    try:
        case_uuid = uuid.UUID(case_id_str)
        case_bytes = encrypt_data(case_uuid.bytes, AES_KEY)
    except ValueError:
        case_bytes = encrypt_data(case_id_str.encode('utf-8'), AES_KEY)

    item_states = {}
    for block in blocks:
        if block.case_id != case_bytes:
            continue
        item_id = block.evidence_id
        state = block.state.rstrip(b'\x00').decode('utf-8')
        item_states[item_id] = state

    state_counts = {
        'CHECKEDIN': 0,
        'CHECKEDOUT': 0,
        'DISPOSED': 0,
        'DESTROYED': 0,
        'RELEASED': 0
    }

    for state in item_states.values():
        if state in state_counts:
            state_counts[state] += 1

    print(f"Summary for Case: {case_id_str}")
    print(f"Total Unique Items: {len(item_states)}")
    for state, count in state_counts.items():
        print(f"{state}: {count}")

# --- Main function and Argparse Setup ---
# (No DEBUG prints added here, but calls functions that now have them)
def main():
    parser = argparse.ArgumentParser(prog="bchoc", description="Blockchain-based evidence tracking system.")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # init
    subparsers.add_parser("init", help="Initialize the blockchain file.")

    # add
    add_parser = subparsers.add_parser("add", help="Add a new evidence item.")
    add_parser.add_argument("-c", dest="case_id", required=True, help="Case ID (UUID string recommended)")
    add_parser.add_argument(
        "-i",
        dest="item_ids",
        required=True,
        action='append',  # Use 'append' instead of nargs='+'
        help="Item ID(s) (integer 0 to 2^32-1). Repeat flag for multiple items."
    )
    add_parser.add_argument("-g", dest="creator", required=True, help="Creator identifier (max 12 chars)")
    add_parser.add_argument("-p", dest="password", required=True, help="Creator password (from BCHOC_PASSWORD_CREATOR)")

    # checkout
    checkout_parser = subparsers.add_parser("checkout", help="Check out an evidence item.")
    checkout_parser.add_argument("-i", dest="item_id", required=True, help="Item ID (integer) to check out")
    checkout_parser.add_argument("-p", dest="password", required=True, help="Password for an owner role (police, lawyer, etc.)")

    # checkin
    checkin_parser = subparsers.add_parser("checkin", help="Check in an evidence item.")
    checkin_parser.add_argument("-i", dest="item_id", required=True, help="Item ID (integer) to check in")
    checkin_parser.add_argument("-p", dest="password", required=True, help="Password for an owner role (police, lawyer, etc.)")

    # show subcommands
    show_parser = subparsers.add_parser("show", help="Display blockchain information.")
    show_subparsers = show_parser.add_subparsers(dest="show_command", required=True, help="Information to show")
    show_subparsers.add_parser("cases", help="Show all unique case IDs.")
    # show_items_parser = show_subparsers.add_parser("items", help="Show items within a specific case.")
    # show_items_parser.add_argument("-c", dest="case_id", required=True, help="Case ID to filter items by")
    show_history_parser = show_subparsers.add_parser("history", help="Show the history of items/cases.")
    show_history_parser.add_argument("-c", dest="case_id", help="Filter history by Case ID")
    show_history_parser.add_argument("-i", dest="item_id", help="Filter history by Item ID (integer)")
    show_history_parser.add_argument("-n", dest="num_entries", type=int, help="Limit the number of history entries shown")
    show_history_parser.add_argument("-r", dest="reverse_order", action="store_true", help="Show history in reverse chronological order (most recent first)")
    show_history_parser.add_argument("-p", dest="password", required=True, help="Password for any valid role to decrypt history")

    # remove (Stub - needs implementation)
    remove_parser = subparsers.add_parser("remove", help="Mark an item as removed (DISPOSED, DESTROYED, RELEASED).")
    remove_parser.add_argument("-i", dest="item_id", required=True, help="Item ID (integer) to remove")
    remove_parser.add_argument("-y", "--why", dest="reason", required=True, choices=['DISPOSED', 'DESTROYED', 'RELEASED'], help="Reason for removal")
    #remove_parser.add_argument("--why", dest="reason", required=True, choices=['DISPOSED', 'DESTROYED', 'RELEASED'], help="Reason for removal")
    remove_parser.add_argument("-o", dest="owner_info", help="Optional owner info/notes for removal") # Example optional field
    remove_parser.add_argument("-p", dest="password", required=True, help="Password for an owner role")

    # verify
    subparsers.add_parser("verify", help="Verify the integrity of the blockchain.")

    # summary (Stub - needs implementation)
    summary_parser = subparsers.add_parser("summary", help="Show a summary of item states.")
    summary_parser.add_argument("-c", dest="case_id", help="Filter summary by Case ID") # Optional filter

    try:
        args = parser.parse_args()

        # print(f"DEBUG main: Parsed command: {args.command}")
        # print(f"DEBUG main: Parsed args: {vars(args)}") # Print all parsed args

        if args.command == "init":
            init()
        elif args.command == "add":
            add(args.case_id, args.item_ids, args.creator, args.password)
        elif args.command == "checkout":
            checkout(args.item_id, args.password)
        elif args.command == "checkin":
            checkin(args.item_id, args.password)
        elif args.command == "show":
            if args.show_command == "cases":
                show_cases()
            # elif args.show_command == "items":
            #     # show_items(args.case_id) # Needs implementation
            #     print("Show items command not yet implemented.", file=sys.stderr)
            elif args.show_command == "history":
                show_history(args.case_id, args.item_id, args.num_entries, args.reverse_order, args.password)
            else:
                 print(f"Invalid show command: {args.show_command}", file=sys.stderr)
                 sys.exit(1)
        elif args.command == "remove":
            remove(args.item_id, args.reason, args.password) # Needs implementation
        #     print("Remove command not yet implemented.", file=sys.stderr)
        elif args.command == "verify":
            verify()
        elif args.command == "summary":
            summary(args.case_id) # Needs implementation
        #      print("Summary command not yet implemented.", file=sys.stderr)
        else:
            # Should be caught by argparse 'required=True' on subparsers
            print(f"Unknown command: {args.command}", file=sys.stderr)
            sys.exit(1)

    except Exception as e:
         # Catch-all for unexpected errors during argument parsing or command execution
         print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)
         import traceback
         print("Traceback:", file=sys.stderr)
         traceback.print_exc(file=sys.stderr)
         sys.exit(1)

if __name__ == "__main__":
    main()