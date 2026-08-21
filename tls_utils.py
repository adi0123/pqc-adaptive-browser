"""
tls_utils.py

Utility classes used throughout the TLS project.

This module intentionally contains NO TLS protocol structures.

Those belong in tls_structures.py.
"""


class BufferReader:

    def __init__(self, data: bytes):

        self.data = data
        self.offset = 0

    # =====================================================
    # Basic Reads
    # =====================================================

    def read(self, size: int) -> bytes:

        if self.offset + size > len(self.data):

            raise ValueError(
                "Attempted to read past end of buffer."
            )

        value = self.data[
            self.offset:self.offset + size
        ]

        self.offset += size

        return value

    # =====================================================
    # Integer Reads
    # =====================================================

    def read_u8(self):

        return int.from_bytes(
            self.read(1),
            "big"
        )

    def read_u16(self):

        return int.from_bytes(
            self.read(2),
            "big"
        )

    def read_u24(self):

        return int.from_bytes(
            self.read(3),
            "big"
        )

    def read_u32(self):

        return int.from_bytes(
            self.read(4),
            "big"
        )

    # =====================================================
    # Position Helpers
    # =====================================================

    def tell(self):

        return self.offset

    def seek(self, position):

        if position < 0 or position > len(self.data):

            raise ValueError(
                "Invalid seek position."
            )

        self.offset = position

    def remaining(self):

        return len(self.data) - self.offset


# ==========================================================
# Optional Writer
#
# Not currently required by the serializer, but useful for
# future TLS message construction.
# ==========================================================

class BufferWriter:

    def __init__(self):

        self.buffer = bytearray()

    # =====================================================
    # Raw Bytes
    # =====================================================

    def write(self, data: bytes):

        self.buffer.extend(data)

    # =====================================================
    # Integer Writes
    # =====================================================

    def write_u8(self, value):

        self.buffer.extend(
            value.to_bytes(1, "big")
        )

    def write_u16(self, value):

        self.buffer.extend(
            value.to_bytes(2, "big")
        )

    def write_u24(self, value):

        self.buffer.extend(
            value.to_bytes(3, "big")
        )

    def write_u32(self, value):

        self.buffer.extend(
            value.to_bytes(4, "big")
        )

    # =====================================================
    # Output
    # =====================================================

    def getvalue(self):

        return bytes(self.buffer)

    def __len__(self):

        return len(self.buffer)
