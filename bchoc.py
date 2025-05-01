#!/usr/bin/env python3

import os
import struct
import argparse
import sys
import uuid
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from datetime import datetime, timezone
from Block import Block, decrypt_data, encrypt_data, validate_password, read_blockchain

BLOCKCHAIN_FILE = 'blockchain.dat'
BLOCK_SIZE = 158
AES_KEY = b"R0chLi4uLi4uLi4="

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

def init():
    """
    Initializes the blockchain with a Genesis block if not already initialized.
    Detects and resets the blockchain file if it is invalid.
    """
    if os.path.exists(BLOCKCHAIN_FILE):
        try:
            with open(BLOCKCHAIN_FILE, "rb") as f:
                first_block = f.read(BLOCK_SIZE)
                if len(first_block) != BLOCK_SIZE:
                    raise ValueError("Blockchain file is invalid.")
        except (ValueError, IOError):
            print("Invalid blockchain file detected. Reinitializing...")
            os.remove(BLOCKCHAIN_FILE)  # Delete corrupted file to reset
        else:
            print("Blockchain file found with INITIAL block.")
            return

    # Create Genesis block
    genesis_block = Block(
        prev_hash=b'\x00' * 32,           # Genesis block has no previous hash
        timestamp=0.0,                    # Default timestamp for Genesis block
        case_id=b'0' * 32,                # Placeholder case ID (32 zero bytes)
        evidence_id=b'0' * 32,            # Placeholder evidence ID (32 zero bytes)
        state=b'INITIAL\0\0\0\0\0',        # Initial state (padded to 12 bytes)
        creator=b'\0' * 12,               # Creator (12 null bytes)
        owner=b'\0' * 12,                 # Owner (12 null bytes)
        data_length=14,                   # Length of the data (14 bytes)
        data=b'Initial block\0'           # Data for the Genesis block
    )

    with open(BLOCKCHAIN_FILE, 'wb') as f:
        f.write(genesis_block.pack())

    print("Blockchain file initialized with Genesis block.")

def add(case_id_str: str, item_ids_list: list[str], creator_str: str, password: str):
    """Adds one or more new evidence items to the blockchain for a given case."""

    validate_password(password, ALLOWED_CREATOR_ROLES) # Exits on failure

    filepath = BLOCKCHAIN_FILE
    if not os.path.exists(filepath):
        init()

    try:
        blocks = read_blockchain()

        existing_evidence_ids = set()

        genesis_evidence_id = b'0' * 32
        for block in blocks:
            if block.evidence_id != genesis_evidence_id:
                 existing_evidence_ids.add(block.evidence_id)

        last_block_in_chain = blocks[-1]
        current_prev_hash = calculate_hash(last_block_in_chain.pack())

        try:
            uuid.UUID(case_id_str)
            encrypted_case_id = encrypt_data(uuid.UUID(case_id_str).bytes, AES_KEY)
        except ValueError:
             print(f"Warning: Case ID '{case_id_str}' is not a valid UUID. Proceeding with string.", file=sys.stderr)
             encrypted_case_id = encrypt_data(case_id_str.encode('utf-8'), AES_KEY)

        creator_bytes = creator_str.encode('utf-8').ljust(12, b'\x00')
        owner_bytes = creator_bytes # Creator is initial owner

        items_added_this_run = 0
        for item_id_str in item_ids_list:

            encrypted_evidence_id = encrypt_data(item_id_str.encode('utf-8'), AES_KEY)

            timestamp = datetime.now(timezone.utc).timestamp()
            new_state = b'CHECKEDIN\0\0\0\0'
            data_length = 0
            data = b''

            # Create the Block object
            new_block = Block(
                prev_hash=current_prev_hash,
                timestamp=timestamp,
                case_id=encrypted_case_id,
                evidence_id=encrypted_evidence_id,
                state=new_state,
                creator=creator_bytes,
                owner=owner_bytes,
                data_length=data_length,
                data=data
            )

            # Pack and Append
            packed_new_block = new_block.pack()

            with open(filepath, 'ab') as f:
                f.write(packed_new_block)

            print(f"Added item: {item_id_str}")
            print(f"Status: CHECKEDIN")
            timestamp_str = datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec='microseconds') + 'Z'
            print(f"Time of action: {timestamp_str}")
            if len(item_ids_list) > 1 and items_added_this_run < len(item_ids_list) - 1:
                 print()

            items_added_this_run += 1

            #Updating prev_hash for the next bloc
            current_prev_hash = calculate_hash(packed_new_block)

            # Add to set to prevent duplicates within the same command run
            existing_evidence_ids.add(encrypted_evidence_id)

    except (IOError, struct.error, ValueError, Exception) as e:
        print(f"An error occurred during add: {e}", file=sys.stderr)
        sys.exit(1)

def checkout(item_id_str: str, password: str):
    """Checks out an item, adding a new block to the chain."""

    validate_password(password, ALLOWED_OWNER_ROLES) # Exits on invalid password

    user_role = None
    for role, env_var in ROLE_TO_ENV_VAR.items():

        if role in ALLOWED_OWNER_ROLES:
             env_password = os.getenv(env_var)
             if env_password and env_password == password:
                 user_role = role
                 break

    try:
        blocks = read_blockchain()

        last_item_block = None
        target_evidence_id = encrypt_data(item_id_str.encode('utf-8'), AES_KEY)
        for block in reversed(blocks):
            if block.evidence_id == target_evidence_id:
                last_item_block = block
                break # Found the most recent one

        if last_item_block is None:
            print(f"Error: Item ID '{item_id_str}' not found in the blockchain.", file=sys.stderr)
            sys.exit(1)

        # Compare bytes directly, removing trailing nulls first
        current_state_bytes = last_item_block.state.rstrip(b'\x00')
        if current_state_bytes in REMOVED_STATES:
            state_str = current_state_bytes.decode('utf-8', 'replace')
            print(f"Error: Item '{item_id_str}' has been removed ({state_str}) and cannot be checked out.", file=sys.stderr)
            sys.exit(1)
        if current_state_bytes != b'CHECKEDIN':
            state_str = current_state_bytes.decode('utf-8', 'replace')
            print(f"Error: Item '{item_id_str}' must be CHECKEDIN to checkout. Current state: {state_str}", file=sys.stderr)
            sys.exit(1)

        last_block_in_chain = blocks[-1]
        prev_hash = calculate_hash(last_block_in_chain.pack())

        timestamp = datetime.now(timezone.utc).timestamp()
        case_id = last_item_block.case_id

        new_state = b'CHECKEDOUT\0\0\0'
        creator = last_item_block.creator

        owner = user_role.upper().encode('utf-8').ljust(12, b'\x00')
        data_length = 0
        data = b''

        new_block = Block(prev_hash, timestamp, case_id, target_evidence_id, new_state, creator, owner, data_length, data)

        filepath = BLOCKCHAIN_FILE
        with open(filepath, 'ab') as f:
            f.write(new_block.pack())

        try:
            decrypted_case_bytes = decrypt_data(case_id, AES_KEY)
            if len(decrypted_case_bytes) == 16:
                 decrypted_case_str = str(uuid.UUID(bytes=decrypted_case_bytes))
            #string decoding
            else:
                 decrypted_case_str = decrypted_case_bytes.decode('utf-8', errors='replace').strip('\x00').strip()
        except Exception:
            decrypted_case_str = case_id.hex() # Fallback to hex

        print(f"Case: {decrypted_case_str}")
        print(f"Checked out item: {item_id_str}")
        print(f"Status: CHECKEDOUT")
        timestamp_str = datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec='microseconds') + 'Z'
        print(f"Time of action: {timestamp_str}")

    except FileNotFoundError:
        print(f"Error: Blockchain file '{BLOCKCHAIN_FILE}' not found. Run 'init' first.", file=sys.stderr)
        sys.exit(1)
    except (IOError, struct.error, ValueError, Exception) as e:
        print(f"An error occurred during checkout: {e}", file=sys.stderr)
        sys.exit(1)

def checkin(item_id_str: str, password: str):
    """Checks in an item, adding a new block to the chain."""
    validate_password(password, ALLOWED_OWNER_ROLES) 

    user_role = None
    for role, env_var in ROLE_TO_ENV_VAR.items():
        if role in ALLOWED_OWNER_ROLES:
            env_password = os.getenv(env_var)
            if env_password and env_password == password:
                user_role = role
                break
    if not user_role:
         print("Error: Could not map validated password to a role.", file=sys.stderr)
         sys.exit(1)

    try:

        blocks = read_blockchain()

        #last state
        last_item_block = None
        target_evidence_id = encrypt_data(item_id_str.encode('utf-8'), AES_KEY)
        for block in reversed(blocks):
            if block.evidence_id == target_evidence_id:
                last_item_block = block
                break

        current_state_bytes = last_item_block.state.rstrip(b'\x00')
        if current_state_bytes in REMOVED_STATES:
            state_str = current_state_bytes.decode('utf-8', 'replace')
            print(f"Error: Item '{item_id_str}' has been removed ({state_str}) and cannot be checked in.", file=sys.stderr)
            sys.exit(1)
        if current_state_bytes != b'CHECKEDOUT':
            state_str = current_state_bytes.decode('utf-8', 'replace')
            print(f"Error: Item '{item_id_str}' must be CHECKEDOUT to checkin. Current state: {state_str}", file=sys.stderr)
            sys.exit(1)

        last_block_in_chain = blocks[-1]
        prev_hash = calculate_hash(last_block_in_chain.pack())

        timestamp = datetime.now(timezone.utc).timestamp()
        case_id = last_item_block.case_id

        # evidence_id is target_evidence_id
        new_state = b'CHECKEDIN\0\0\0\0' # Padded to 12 bytes
        creator = last_item_block.creator
        owner = user_role.upper().encode('utf-8').ljust(12, b'\x00')
        data_length = 0
        data = b''

        new_block = Block(prev_hash, timestamp, case_id, target_evidence_id, new_state, creator, owner, data_length, data)

        #append the new bloc
        filepath = BLOCKCHAIN_FILE
        with open(filepath, 'ab') as f:
            f.write(new_block.pack())

        try:
            decrypted_case_bytes = decrypt_data(case_id, AES_KEY)
            if len(decrypted_case_bytes) == 16:
                 decrypted_case_str = str(uuid.UUID(bytes=decrypted_case_bytes))
            else:
                 decrypted_case_str = decrypted_case_bytes.decode('utf-8', errors='replace').strip('\x00').strip()
        except Exception:
            decrypted_case_str = case_id.hex()

        print(f"Case: {decrypted_case_str}")
        print(f"Checked in item: {item_id_str}")
        print(f"Status: CHECKEDIN")
        timestamp_str = datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec='microseconds') + 'Z'
        print(f"Time of action: {timestamp_str}")

    except FileNotFoundError:
        print(f"Error: Blockchain file '{BLOCKCHAIN_FILE}' not found. Run 'init' first.", file=sys.stderr)
        sys.exit(1)
    except (IOError, struct.error, ValueError, Exception) as e:
        print(f"An error occurred during checkin: {e}", file=sys.stderr)
        sys.exit(1)


def show_cases():
    """
    Displays a list of all unique case IDs stored in the blockchain,
    skipping the Genesis block.
    """
    if not os.path.exists(BLOCKCHAIN_FILE):
        print("Blockchain is not initialized.")
        return

    cases = set()
    password_valid = False

    with open(BLOCKCHAIN_FILE, 'rb') as f:
        while True:
            block_data = f.read(BLOCK_SIZE)
            if not block_data:
                break
            if len(block_data) != BLOCK_SIZE:
                continue
            try:
                unpacked_block = struct.unpack("32s d 32s 32s 12s 12s 12s I 14s", block_data)
                case_id = unpacked_block[2]
                # Skip Genesis block (placeholder case ID)
                if case_id == b'0' * 32:
                    continue

                password_input = input("Enter password to view decrypted Case ID: ")
                valid_passwords = [
                    os.getenv('BCHOC_PASSWORD_POLICE'),
                    os.getenv('BCHOC_PASSWORD_LAWYER'),
                    os.getenv('BCHOC_PASSWORD_ANALYST'),
                    os.getenv('BCHOC_PASSWORD_EXECUTIVE'),
                    os.getenv('BCHOC_PASSWORD_CREATOR')
                ]
                if password_input in valid_passwords:
                    password_valid = True

                if password_valid:
                    decrypted_case_id = decrypt_data(case_id, AES_KEY).decode('utf-8').strip()
                    cases.add(decrypted_case_id)
                else:
                    cases.add(case_id.hex())
            except struct.error:
                break

    if cases:
        print("\nCases in the blockchain:")
        for case in cases:
            print(f"Case ID: {case}")
    else:
        print("No cases found.")

def show_history(case_id_str: str | None, item_id_str: str | None, num_entries: int | None, reverse_order: bool, password: str):
    """
    Displays the history of blockchain entries, optionally filtered by case/item ID,
    limited by number of entries, and ordered. Requires a valid password for decryption.
    """
    # Validate password - allows any valid role (owner or creator) to view history
    # This ensures the user has *some* valid credentials before proceeding.
    # Decryption will still depend on this password being correct for AES_KEY.
    validate_password(password, ALLOWED_OWNER_ROLES + ALLOWED_CREATOR_ROLES) # Exits on failure

    try:
        all_blocks = read_blockchain()
        if not all_blocks:
            print("Blockchain is empty or not initialized.")
            return
        # Skip the Genesis block for history display
        all_blocks = all_blocks[1:]
        if not all_blocks:
            print("No history entries found (only Genesis block exists).")
            return

    except FileNotFoundError:
        print(f"Error: Blockchain file '{BLOCKCHAIN_FILE}' not found. Run 'init' first.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading or parsing blockchain: {e}", file=sys.stderr)
        sys.exit(1)

    filtered_blocks = []
    target_case_id_encrypted = None
    if case_id_str:
        try:
            # Attempt UUID conversion first for encryption, fallback to string encoding
            try:
                 target_case_id_encrypted = encrypt_data(uuid.UUID(case_id_str).bytes, AES_KEY)
            except ValueError:
                 print(f"Warning: Provided Case ID '{case_id_str}' is not a valid UUID. Filtering based on string.", file=sys.stderr)
                 target_case_id_encrypted = encrypt_data(case_id_str.encode('utf-8'), AES_KEY)
        except Exception as e:
             print(f"Error processing provided case ID for filtering: {e}", file=sys.stderr)
             sys.exit(1) # Cannot proceed with filtering if encryption fails

    target_evidence_id_encrypted = None
    if item_id_str:
        try:
            target_evidence_id_encrypted = encrypt_data(item_id_str.encode('utf-8'), AES_KEY)
        except Exception as e:
             print(f"Error processing provided item ID for filtering: {e}", file=sys.stderr)
             sys.exit(1) # Cannot proceed with filtering if encryption fails

    # Filter blocks based on provided criteria
    for block in all_blocks:
        match = True
        # Apply case ID filter if provided
        if target_case_id_encrypted and block.case_id != target_case_id_encrypted:
            match = False
        # Apply item ID filter if provided
        if target_evidence_id_encrypted and block.evidence_id != target_evidence_id_encrypted:
            match = False

        if match:
            filtered_blocks.append(block)

    # Apply ordering
    if reverse_order:
        filtered_blocks.reverse() # Show most recent first

    # Apply entry limit
    if num_entries is not None:
        if num_entries <= 0:
             print("Warning: Number of entries (-n) must be positive. Showing 0 entries.", file=sys.stderr)
             filtered_blocks = [] # Show nothing if n <= 0
        else:
             # Take the first 'num_entries' after sorting/reversing
             filtered_blocks = filtered_blocks[:num_entries]

    # Print the results
    if not filtered_blocks:
        print("No history found matching the criteria.")
        return

    first_entry = True
    for block in filtered_blocks:
        if not first_entry:
            print() # Add blank line between entries as per example [Source 85]
        else:
            first_entry = False

        # Attempt to decrypt IDs - password was validated, so decryption should work if key is right
        try:
            decrypted_case_bytes = decrypt_data(block.case_id, AES_KEY)
            # Handle UUID vs String during decryption/decoding
            try:
                 # Try UUID first (16 bytes after decryption)
                 case_display = str(uuid.UUID(bytes=decrypted_case_bytes))
            except ValueError:
                 # Fallback to UTF-8 string decoding, remove padding/nulls
                 case_display = decrypted_case_bytes.decode('utf-8', errors='replace').rstrip('\x00').strip()
        except Exception:
             case_display = block.case_id.hex() # Fallback to hex if decryption/decoding fails [Source 65, 85]

        try:
             # Item ID is expected to be string originally
             decrypted_item_bytes = decrypt_data(block.evidence_id, AES_KEY)
             item_display = decrypted_item_bytes.decode('utf-8', errors='replace').rstrip('\x00').strip()
        except Exception:
             item_display = block.evidence_id.hex() # Fallback to hex [Source 65, 85]

        # Decode state, removing null padding
        try:
            state_display = block.state.rstrip(b'\x00').decode('utf-8', 'replace')
        except Exception:
            state_display = block.state.hex() # Fallback if decoding fails

        # Format timestamp to ISO 8601 UTC with 'Z'
        try:
             timestamp_dt = datetime.fromtimestamp(block.timestamp, timezone.utc)
             # Ensure microseconds and 'Z' suffix are present
             time_display = timestamp_dt.isoformat(timespec='microseconds').replace('+00:00', 'Z')
             # Add 'Z' if isoformat didn't include it (older Python versions might not)
             if not time_display.endswith('Z'):
                  time_display += 'Z'
        except Exception:
             time_display = f"Invalid timestamp ({block.timestamp})" # Fallback

        # Print according to the format in the example [Source 85]
        print(f"Case: {case_display}")
        print(f"Item: {item_display}")
        print(f"Action: {state_display}")
        print(f"Time: {time_display}")
        
def main():
    parser = argparse.ArgumentParser(prog="bchoc")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    subparsers.add_parser("init")

    # add (stub)
    add_parser = subparsers.add_parser("add")
    add_parser.add_argument("-c", required=True, help="Case ID")
    add_parser.add_argument("-i", required=True, nargs="+", help="Item ID(s)")
    add_parser.add_argument("-g", required=True, help="Creator")
    add_parser.add_argument("-p", required=True, help="Password")

    # checkout (stub)
    checkout_parser = subparsers.add_parser("checkout")
    checkout_parser.add_argument("-i", required=True, help="Item ID")
    checkout_parser.add_argument("-p", required=True, help="Password")

    # checkin (stub)
    checkin_parser = subparsers.add_parser("checkin")
    checkin_parser.add_argument("-i", required=True, help="Item ID")
    checkin_parser.add_argument("-p", required=True, help="Password")

    # show subcommands
    show_parser = subparsers.add_parser("show")
    show_subparsers = show_parser.add_subparsers(dest="show_command", required=True)
    show_subparsers.add_parser("cases")
    show_items_parser = show_subparsers.add_parser("items")
    show_items_parser.add_argument("-c", required=True, help="Case ID")
    show_history_parser = show_subparsers.add_parser("history")
    show_history_parser.add_argument("-c", help="Case ID")
    show_history_parser.add_argument("-i", help="Item ID")
    show_history_parser.add_argument("-n", type=int, help="Number of entries")
    show_history_parser.add_argument("-r", action="store_true", help="Reverse order")
    show_history_parser.add_argument("-p", required=True, help="Password")

    # remove (stub)
    remove_parser = subparsers.add_parser("remove")
    remove_parser.add_argument("-i", required=True, help="Item ID")
    remove_parser.add_argument("-y", required=True, help="Reason")
    remove_parser.add_argument("-p", required=True, help="Password")

    # verify (stub)
    subparsers.add_parser("verify")

    # summary (stub)
    summary_parser = subparsers.add_parser("summary")
    summary_parser.add_argument("-c", required=True, help="Item ID")

    args = parser.parse_args()

    if args.command == "init":
        init()
    elif args.command == "add":
        add(args.c, args.i, args.g, args.p)
    elif args.command == "checkout":
        checkout(args.i, args.p)
    elif args.command == "checkin":
        checkin(args.i, args.p)
    elif args.command == "show":
        if args.show_command == "cases":
            show_cases()
        elif args.show_command == "items":
            show_items(args.c)
        elif args.show_command == "history":
            show_history(args.c, args.i, args.n, args.r, args.p)
    elif args.command == "remove":
        remove(args.i, args.y, args.p)
    elif args.command == "verify":
        verify()
    elif args.command == "summary":
        summary(args.c)
    else:
        print("Invalid command")
        sys.exit(1)

if __name__ == "__main__":
    main()
