import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import sys
import hashlib
import os

from datetime import datetime, timezone

class Block:

    #constructor
    def __init__(self,
                prev_hash: bytes,
                timestamp: float,
                case_id: bytes,
                evidence_id: bytes,
                state: bytes,
                creator: bytes,
                owner: bytes,
                data_length: int,
                data: bytes):
        
        self.prev_hash = prev_hash
        self.timestamp = timestamp
        self.case_id = case_id
        self.evidence_id = evidence_id
        self.state = state
        self.creator = creator
        self.owner = owner
        self.data_length = data_length
        self.data = data

    def pack(self) -> bytes:

        #binary form of Block object
        #prev_hash, timestamp.....
        block_format_string = "32s d 32s 32s 12s 12s 12s I"

        try:
            packed_fixed_data = struct.pack(block_format_string,
                                            self.prev_hash,
                                            self.timestamp,
                                            self.case_id,
                                            self.evidence_id,
                                            self.state,
                                            self.creator,
                                            self.owner,
                                            self.data_length)
            
            full_packed_block = packed_fixed_data + self.data

            return full_packed_block

        except struct.error as e:
            print(f"Error while packing block: {e}")

    #takes in packed bytes and formats them into a Block
    @classmethod
    def unpack(cls, packed_data:bytes) -> 'Block':

        block_format_string = "32s d 32s 32s 12s 12s 12s I"

        fixed_header_size = struct.calcsize(block_format_string)

        if len(packed_data) < fixed_header_size:
            raise ValueError(f"Packed data is shorter than minimum header length. minimum length: {fixed_header_size} actual length: {len(packed_data)}")

        try:
            #assigning all the unpacked bytes to corresponding variables
            fixed_header_bytes = packed_data[:fixed_header_size]
            unpacked_fixed_data = struct.unpack(block_format_string, fixed_header_bytes)

            prev_hash, timestamp, case_id, evidence_id, state, creator, owner, data_length = unpacked_fixed_data

            expected_total_size = fixed_header_size + data_length
            
            #missing part of Block
            if len(packed_data) < expected_total_size:
                raise ValueError(f"Packed data is incomplete. Expected {expected_total_size} bytes based on data_length actual {len(packed_data)}")

            data = packed_data[fixed_header_size:expected_total_size]

            return cls(prev_hash,
                       timestamp,
                       case_id,
                       evidence_id,
                       state,
                       creator,
                       owner,
                       data_length,
                       data)

        except struct.error as e:
            print(f"Error while unpacking block: {e}")
            raise
        except ValueError as e:
            print(f"Error during unpacking: {e}")
            raise


def decrypt_data(encrypted_data, key):
    """
    Decrypts data using AES ECB mode with the provided key.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)     
    return decrypted_data

def encrypt_data(plain_bytes: bytes, key: bytes) -> bytes:
    """Encrypts data using AES ECB and pads result to 30 bytes."""

    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(plain_bytes, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)

    if len(encrypted_data) > 32:
        print(f"Error: Encrypted data length ({len(encrypted_data)}) exceeds 32 bytes.", file=sys.stderr)
        raise ValueError("Encrypted data exceeds 32 byte limit")

    return encrypted_data.ljust(32, b'\x00')

def validate_password(password: str, allowed_roles: list[str]):
    """
    Checks the provided password against environment variables for allowed roles.
    Prints error and exits with status 1 if invalid. Otherwise, returns None.
    """
    valid_passwords_for_roles = []

    #Map role names to environment variable names
    role_to_env_var = {
        'police': 'BCHOC_PASSWORD_POLICE',
        'lawyer': 'BCHOC_PASSWORD_LAWYER',
        'analyst': 'BCHOC_PASSWORD_ANALYST',
        'executive': 'BCHOC_PASSWORD_EXECUTIVE',
        'creator': 'BCHOC_PASSWORD_CREATOR'
    }

    #Fetch passwords from environment for the roles allowed for this action
    for role in allowed_roles:
        role = role.lower()
        env_var_name = role_to_env_var.get(role)
        if env_var_name:
            env_password = os.getenv(env_var_name)
            if env_password is not None:
                valid_passwords_for_roles.append(env_password)

    if password not in valid_passwords_for_roles:
        print("Invalid password.", file=sys.stderr)
        sys.exit(1)

    #Returns none if password is valid
    return

def read_blockchain() -> list[Block]:
    """
    Reads the blockchain file block by block and returns a list of Block objects.
    Handles variable data lengths.
    """
    filepath = os.getenv("BCHOC_FILE_PATH", 'blockchain.dat')
    blocks = []
    if not os.path.exists(filepath):

        return blocks

    try:
        with open(filepath, 'rb') as f:
            while True:
                #Read the fixedsize header
                header_bytes = f.read(FIXED_HEADER_SIZE)

                # Check for EOF
                if not header_bytes:
                    break

                #find data_length from header
                try:
                    *_, data_length = struct.unpack(BLOCK_FORMAT_STRING, header_bytes)
                except struct.error as e:
                     print(f"Error unpacking block header: {e}", file=sys.stderr)
                     break 

                #read the variable-length data
                data_bytes = f.read(data_length)

                full_block_bytes = header_bytes + data_bytes

                try:
                    block = Block.unpack(full_block_bytes)
                    blocks.append(block)

                except (ValueError, struct.error) as e:
                     print(f"Error unpacking full block: {e}", file=sys.stderr)

                     break
                except Exception as e:
                    print(f"Unexpected error creating Block object: {e}", file=sys.stderr)
                    break


    except IOError as e:
        print(f"Error reading blockchain file {filepath}: {e}", file=sys.stderr)

    return blocks

def calculate_hash(block_bytes: bytes) -> bytes:
    """
    Calculates the SHA256 hash of the given block bytes.
    Returns the 32-byte digest.
    """
    try:
        hasher = hashlib.sha256()
        hasher.update(block_bytes)

        return hasher.digest()
    except Exception as e:
        print(f"Error during hash calculation: {e}", file=sys.stderr)
        raise 

