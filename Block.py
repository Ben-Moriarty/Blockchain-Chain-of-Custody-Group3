import struct
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

    @classmethod
    def unpack(cls, packed_data:bytes) -> 'Block':

        block_format_string = "32s d 32s 12s 12s 12s I"

        fixed_header_size = struct.calcsize(block_format_string)

        if len(packed_data) < fixed_header_size:
            raise ValueError(f"Packed data is shorter than minimum header length. minimum length: {fixed_header_size} actual length: {len(packed_data)}")

        try:
            fixed_header_bytes = packed_data[:fixed_header_size]
            unpacked_fixed_data = struct.unpack(block_format_string, fixed_header_bytes)

            prev_hash, timestamp, case_id, evidence_id, state, creator, owner, data_length = unpacked_fixed_data

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

