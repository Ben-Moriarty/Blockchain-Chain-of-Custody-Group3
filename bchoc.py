import os
import struct
import argparse
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from Block import Block, decrypt_data, encrypt_data

BLOCKCHAIN_FILE = 'blockchain.dat'
BLOCK_SIZE = 158
AES_KEY = b"R0chLi4uLi4uLi4="

def init():
    """
    Initializes the blockchain with a Genesis block if not already initialized.
    """
    if not os.path.exists(BLOCKCHAIN_FILE):
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
        print("Blockchain file not found. Created INITIAL block.")
    else:
        print("Blockchain file found with INITIAL block.")

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
