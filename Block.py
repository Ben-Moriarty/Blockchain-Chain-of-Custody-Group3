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
