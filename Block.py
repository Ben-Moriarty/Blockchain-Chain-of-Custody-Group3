# Block.py
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import sys
import hashlib
import os
from datetime import datetime, timezone

# Define format string as a class attribute for consistency
BLOCK_FORMAT_STRING = "32s d 32s 32s 12s 12s 12s I"
FIXED_HEADER_SIZE = struct.calcsize(BLOCK_FORMAT_STRING)

# AES key - keep it defined here if Block.py might be used independently,
# but ensure it's the same as in bchoc.py if used together.
AES_KEY = b"R0chLi4uLi4uLi4=" # Must be 16 bytes for AES-128

class Block:
    BLOCK_FORMAT_STRING = "32s d 32s 32s 12s 12s 12s I"
    FIXED_HEADER_SIZE = struct.calcsize(BLOCK_FORMAT_STRING)

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

        # DEBUG: Print raw inputs to constructor
        # print(f"DEBUG Block.__init__: Raw prev_hash={prev_hash.hex() if isinstance(prev_hash, bytes) else prev_hash}, timestamp={timestamp}, case_id={case_id.hex() if isinstance(case_id, bytes) else case_id}, evidence_id={evidence_id.hex() if isinstance(evidence_id, bytes) else evidence_id}, state={state}, creator={creator}, owner={owner}, data_length={data_length}, data={data}")

        # Ensure inputs are bytes where expected, apply padding/truncation
        self.prev_hash = (prev_hash.ljust(32, b'\x00')[:32] if isinstance(prev_hash, bytes) else b'\x00'*32)
        self.timestamp = float(timestamp)
        self.case_id = (case_id.ljust(32, b'\x00')[:32] if isinstance(case_id, bytes) else b'\x00'*32)
        self.evidence_id = (evidence_id.ljust(32, b'\x00')[:32] if isinstance(evidence_id, bytes) else b'\x00'*32)
        self.state = (state.ljust(12, b'\x00')[:12] if isinstance(state, bytes) else b'\x00'*12)
        self.creator = (creator.ljust(12, b'\x00')[:12] if isinstance(creator, bytes) else b'\x00'*12)
        self.owner = (owner.ljust(12, b'\x00')[:12] if isinstance(owner, bytes) else b'\x00'*12)
        self.data_length = int(data_length)
        # Ensure data is bytes, truncate/pad to data_length
        self.data = (data[:self.data_length].ljust(self.data_length, b'\x00') if isinstance(data, bytes) else b'\x00'*self.data_length)

        # DEBUG: Print attributes after processing
        # print(f"DEBUG Block.__init__: Processed prev_hash={self.prev_hash.hex()}, timestamp={self.timestamp}, case_id={self.case_id.hex()}, evidence_id={self.evidence_id.hex()}, state={self.state}, creator={self.creator}, owner={self.owner}, data_length={self.data_length}, data={self.data.hex()}")


    def pack(self) -> bytes:
        """Packs the block object into bytes."""
        # print(f"DEBUG Block.pack: Packing block with data_length={self.data_length}")
        try:
            # Pack the fixed-size header part
            packed_fixed_data = struct.pack(self.BLOCK_FORMAT_STRING,
                                            self.prev_hash,
                                            self.timestamp,
                                            self.case_id,
                                            self.evidence_id,
                                            self.state,
                                            self.creator,
                                            self.owner,
                                            self.data_length)

            # Ensure data is correct length *before* concatenation
            if len(self.data) != self.data_length:
                 print(f"DEBUG Block.pack: WARNING - self.data length ({len(self.data)}) != self.data_length ({self.data_length}). Adjusting data.", file=sys.stderr)
                 self.data = self.data[:self.data_length].ljust(self.data_length, b'\x00')

            # Concatenate header and data
            full_packed_block = packed_fixed_data + self.data

            # DEBUG: Print packed sizes
            # print(f"DEBUG Block.pack: packed_fixed_data size={len(packed_fixed_data)}, data size={len(self.data)}, total packed size={len(full_packed_block)}")
            # print(f"DEBUG Block.pack: Packed hex = {full_packed_block.hex()}")
            return full_packed_block

        except struct.error as e:
            print(f"DEBUG Block.pack: Error during struct.pack: {e}", file=sys.stderr)
            # Print the values that caused the error
            print(f"DEBUG Block.pack: Values: prev={self.prev_hash.hex()}, ts={self.timestamp}, case={self.case_id.hex()}, evid={self.evidence_id.hex()}, state={self.state}, creator={self.creator}, owner={self.owner}, len={self.data_length}", file=sys.stderr)
            raise ValueError(f"Failed to pack block data: {e}") from e
        except Exception as e:
            print(f"DEBUG Block.pack: Unexpected error: {e}", file=sys.stderr)
            raise

    @classmethod
    def unpack(cls, packed_data: bytes) -> 'Block':
        """Unpacks bytes into a Block object."""
        # print(f"DEBUG Block.unpack: Attempting to unpack {len(packed_data)} bytes.")
        # print(f"DEBUG Block.unpack: Data hex = {packed_data.hex()}")

        if len(packed_data) < cls.FIXED_HEADER_SIZE:
            raise ValueError(f"Packed data ({len(packed_data)} bytes) is shorter than minimum header size ({cls.FIXED_HEADER_SIZE} bytes).")

        try:
            # Unpack the fixed-size header part
            fixed_header_bytes = packed_data[:cls.FIXED_HEADER_SIZE]
            # print(f"DEBUG Block.unpack: Unpacking header bytes: {fixed_header_bytes.hex()}")
            unpacked_fixed_data = struct.unpack(cls.BLOCK_FORMAT_STRING, fixed_header_bytes)

            prev_hash, timestamp, case_id, evidence_id, state, creator, owner, data_length = unpacked_fixed_data
            # print(f"DEBUG Block.unpack: Unpacked header: prev_hash={prev_hash.hex()}, ts={timestamp}, case_id={case_id.hex()}, ev_id={evidence_id.hex()}, state={state}, creator={creator}, owner={owner}, data_len={data_length}")

            # Calculate the expected total size based on the unpacked data_length
            expected_total_size = cls.FIXED_HEADER_SIZE + data_length
            # print(f"DEBUG Block.unpack: Expected total size based on data_length: {expected_total_size}")

            # Check if the provided packed_data is at least the expected size
            if len(packed_data) < expected_total_size:
                raise ValueError(f"Packed data is incomplete. Expected {expected_total_size} bytes based on data_length, but received {len(packed_data)} bytes.")

            # Extract the data part
            data = packed_data[cls.FIXED_HEADER_SIZE:expected_total_size]
            # print(f"DEBUG Block.unpack: Extracted data ({len(data)} bytes): {data.hex()}")

            # Create and return the Block object using the constructor for validation/padding
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
            print(f"DEBUG Block.unpack: Error unpacking header (struct.error): {e}", file=sys.stderr)
            raise ValueError(f"Failed to unpack block header: {e}") from e
        except ValueError as e: # Catch ValueError from checks or constructor
             print(f"DEBUG Block.unpack: Error during unpacking (ValueError): {e}", file=sys.stderr)
             raise
        except Exception as e:
            print(f"DEBUG Block.unpack: Unexpected error: {e}", file=sys.stderr)
            raise

    # Add __repr__ for easier debugging
    def __repr__(self) -> str:
        # Shorten hashes/ids for readability in repr
        prev_h_short = self.prev_hash[:4].hex() + "..." if self.prev_hash else "None"
        case_id_short = self.case_id[:4].hex()+"..." if self.case_id else "None"
        ev_id_short = self.evidence_id[:4].hex()+"..." if self.evidence_id else "None"
        data_short = self.data[:10].hex()+"..." if self.data else "None"
        state_str = self.state.rstrip(b'\x00').decode('utf-8', 'replace')

        return (f"Block(prev={prev_h_short}, ts={self.timestamp:.2f}, "
                f"case={case_id_short}, evid={ev_id_short}, state='{state_str}', "
                f"d_len={self.data_length}, data={data_short})")


# --- Utility Functions (potentially moved from bchoc.py if Block is standalone) ---

def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypts data using AES ECB mode, assuming the input is 32 bytes
       (16 bytes ciphertext + 16 bytes null padding from encrypt_data).
       MODIFIED: Returns raw 16 decrypted bytes without unpadding.
    """
    # print(f"DEBUG decrypt_data: Decrypting {len(encrypted_data)} bytes: {encrypted_data.hex()}")
    if not isinstance(encrypted_data, bytes):
        raise TypeError("encrypted_data must be bytes")

    # --- Handle the non-standard encryption format ---
    if len(encrypted_data) >= 16:
        actual_ciphertext = encrypted_data[:16] # Extract the meaningful first 16 bytes
    else:
         # This case should ideally not happen if encrypt_data always produces 32 bytes
         print(f"DEBUG decrypt_data: Input data too short (< 16 bytes): {encrypted_data.hex()}. Cannot decrypt.", file=sys.stderr)
         raise ValueError(f"Input data too short ({len(encrypted_data)} bytes) for AES decryption.")

    # Check if the extracted ciphertext is empty or all nulls (e.g., for Genesis case_id/evidence_id)
    if not actual_ciphertext or actual_ciphertext == (b'\x00' * 16):
        # print("DEBUG decrypt_data: Effective ciphertext is empty or nulls, returning empty bytes.")
        return b''
    # --- End Handling ---

    try:
        cipher = AES.new(key, AES.MODE_ECB)
        # Decrypt only the first 16 bytes
        decrypted_bytes = cipher.decrypt(actual_ciphertext)

        # --- MODIFICATION: Remove unpad ---
        # Instead of unpadding, just return the decrypted 16 bytes.
        # The caller will need to handle potential trailing padding/nulls if necessary when interpreting the data.
        # print(f"DEBUG decrypt_data: Returning raw decrypted 16 bytes: {decrypted_bytes.hex()}")
        return decrypted_bytes
        # --- END MODIFICATION ---

    # Catch ValueError specifically, which might indicate key issues if decryption itself fails
    except ValueError as e:
         print(f"DEBUG decrypt_data: Error during AES decryption (ValueError): {e}. Ciphertext input (first 16 bytes) was {actual_ciphertext.hex()}", file=sys.stderr)
         raise ValueError(f"Decryption failed: {e}") from e
    # Catch other potential exceptions during cipher operation
    except Exception as e:
        print(f"DEBUG decrypt_data: Unexpected error during decryption: {e}", file=sys.stderr)
        raise # Re-raise other unexpected errors


def encrypt_data(plain_bytes: bytes, key: bytes) -> bytes:
    """Encrypts data using AES ECB, pads input, encrypts,
       and returns *only the first 16 bytes* of ciphertext,
       padded to 32 bytes with nulls for the block field."""
    if not isinstance(plain_bytes, bytes): raise TypeError("plain_bytes must be bytes")
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        # ALWAYS pad the input data using standard PKCS7 padding
        padded_data = pad(plain_bytes, AES.block_size) # Pad to 16 or 32 bytes
        encrypted_data = cipher.encrypt(padded_data) # Result length is multiple of 16

        # --- MODIFICATION ---
        # Take ONLY the first 16 bytes of the resulting ciphertext
        first_block_ciphertext = encrypted_data[:16]

        # Pad this 16-byte ciphertext to 32 bytes for the struct field
        final_output = first_block_ciphertext.ljust(32, b'\x00')
        # --- END MODIFICATION ---

        return final_output
    except Exception as e:
        print(f"Error during encryption: {e}", file=sys.stderr)
        raise ValueError(f"Encryption failed: {e}") from e


def validate_password(password: str, allowed_roles: list[str]):
    """Checks password against environment variables for allowed roles."""
    # print(f"DEBUG validate_password: Validating password for roles: {allowed_roles}")
    valid_passwords_for_roles = []
    role_to_env_var = {
        'police': 'BCHOC_PASSWORD_POLICE',
        'lawyer': 'BCHOC_PASSWORD_LAWYER',
        'analyst': 'BCHOC_PASSWORD_ANALYST',
        'executive': 'BCHOC_PASSWORD_EXECUTIVE',
        'creator': 'BCHOC_PASSWORD_CREATOR'
    }
    found_valid = False
    for role in allowed_roles:
        env_var_name = role_to_env_var.get(role.lower())
        if env_var_name:
            env_password = os.getenv(env_var_name)
            # print(f"DEBUG validate_password: Checking env var {env_var_name} for role {role}... Found: {'Yes' if env_password else 'No'}")
            if env_password is not None:
                valid_passwords_for_roles.append(env_password)
                if password == env_password:
                    # print(f"DEBUG validate_password: Password matches role {role}")
                    found_valid = True
                    # Don't break early, collect all valid ones for error message maybe?
                    # Although current logic just checks presence.

    if not found_valid:
        print("Invalid password.", file=sys.stderr)
        # print(f"DEBUG validate_password: Password '{password}' not found in allowed passwords for roles {allowed_roles}. Valid passwords found in env: {valid_passwords_for_roles}", file=sys.stderr)
        sys.exit(1)

    # print("DEBUG validate_password: Password validated successfully.")
    return # Return None on success


def read_blockchain() -> list[Block]:
    """Reads the blockchain file block by block."""
    filepath = os.getenv("BCHOC_FILE_PATH", 'blockchain.dat')
    # print(f"DEBUG read_blockchain: Reading from file: {filepath}")
    blocks = []
    if not os.path.exists(filepath):
        # print("DEBUG read_blockchain: File does not exist.")
        return blocks # Return empty list

    block_count = 0
    try:
        with open(filepath, 'rb') as f:
            while True:
                # print(f"\nDEBUG read_blockchain: Reading block #{block_count}")
                # Read the fixed-size header first
                header_bytes = f.read(Block.FIXED_HEADER_SIZE)

                if not header_bytes:
                    # print("DEBUG read_blockchain: EOF reached.")
                    break # End of file

                if len(header_bytes) < Block.FIXED_HEADER_SIZE:
                    print(f"DEBUG read_blockchain: Error - Incomplete header read at block {block_count}. Got {len(header_bytes)} bytes, expected {Block.FIXED_HEADER_SIZE}. Stopping.", file=sys.stderr)
                    break

                # print(f"DEBUG read_blockchain: Read header bytes ({len(header_bytes)}): {header_bytes.hex()}")

                # Unpack data_length from the header to know how much data to read next
                try:
                    # Use struct.unpack_from to avoid slicing, unpack only data_length (last field 'I')
                    # Format string "I" is for the data_length field. Offset is FIXED_HEADER_SIZE - size_of_I (4 bytes).
                    data_length_offset = Block.FIXED_HEADER_SIZE - struct.calcsize("I")
                    data_length, = struct.unpack_from("I", header_bytes, data_length_offset)
                    # print(f"DEBUG read_blockchain: Unpacked data_length = {data_length} from header.")
                except struct.error as e:
                     print(f"DEBUG read_blockchain: Error unpacking data_length from header at block {block_count}: {e}", file=sys.stderr)
                     break # Stop reading if header is corrupt

                # Read the variable-length data part
                data_bytes = f.read(data_length)
                # print(f"DEBUG read_blockchain: Attempting to read {data_length} data bytes...")

                if len(data_bytes) < data_length:
                     print(f"DEBUG read_blockchain: Error - Incomplete data read at block {block_count}. Got {len(data_bytes)} bytes, expected {data_length}. Stopping.", file=sys.stderr)
                     break # Stop reading if data is truncated

                # print(f"DEBUG read_blockchain: Read data bytes ({len(data_bytes)}): {data_bytes.hex()}")

                # Combine header and data to form the full block bytes for unpacking
                full_block_bytes = header_bytes + data_bytes
                # print(f"DEBUG read_blockchain: Total block bytes ({len(full_block_bytes)}): {full_block_bytes.hex()}")

                # Unpack the full block bytes into a Block object
                try:
                    block = Block.unpack(full_block_bytes)
                    # print(f"DEBUG read_blockchain: Successfully unpacked block #{block_count}: {block}")
                    blocks.append(block)
                    block_count += 1
                except (ValueError, struct.error) as e:
                     print(f"DEBUG read_blockchain: Error unpacking full block #{block_count}: {e}", file=sys.stderr)
                     # Optionally, print the problematic bytes:
                     # print(f"DEBUG read_blockchain: Problematic bytes: {full_block_bytes.hex()}", file=sys.stderr)
                     break # Stop reading if a block is corrupt
                except Exception as e:
                    print(f"DEBUG read_blockchain: Unexpected error creating Block object #{block_count}: {e}", file=sys.stderr)
                    break

    except IOError as e:
        print(f"DEBUG read_blockchain: Error opening/reading file {filepath}: {e}", file=sys.stderr)
    except Exception as e:
         print(f"DEBUG read_blockchain: Unexpected error during file processing: {e}", file=sys.stderr)


    # print(f"DEBUG read_blockchain: Finished reading. Total blocks loaded: {len(blocks)}")
    return blocks

def calculate_hash(block_bytes: bytes) -> bytes:
    """Calculates the SHA256 hash of the given block bytes."""
    # print(f"DEBUG calculate_hash: Calculating SHA256 hash for {len(block_bytes)} bytes.")
    # print(f"DEBUG calculate_hash: Input bytes (hex): {block_bytes.hex()}")
    if not isinstance(block_bytes, bytes):
         print("DEBUG calculate_hash: ERROR - Input must be bytes.", file=sys.stderr)
         raise TypeError("Input for hashing must be bytes")
    try:
        hasher = hashlib.sha256()
        hasher.update(block_bytes)
        digest = hasher.digest()
        # print(f"DEBUG calculate_hash: Resulting hash (32 bytes): {digest.hex()}")
        return digest
    except Exception as e:
        print(f"DEBUG calculate_hash: Error during hash calculation: {e}", file=sys.stderr)
        raise ValueError(f"Hashing failed: {e}") from e

# --- End of Block.py additions ---