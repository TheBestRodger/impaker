import struct
from enum import IntEnum

# Error codes from libndr.h
class NDR_ERR(IntEnum):
    SUCCESS = 0
    BUFSIZE = 1
    TOKEN = 2
    ALLOC = 3
    ARRAY_SIZE = 4
    INVALID_POINTER = 5
    UNREAD_BYTES = 6

# Flags from libndr.h
class LIBNDR_FLAG(IntEnum):
    BIGENDIAN = 1 << 0
    NOALIGN = 1 << 1
    PAD_CHECK = 1 << 28
    ALIGN2 = 1 << 22
    ALIGN4 = 1 << 23
    ALIGN8 = 1 << 24


# from ndr_dcerpc.c
class NDRPush:
    def __init__(self, bigendian=False):
        self.buf = bytearray()
        self.off = 0
        self.bigendian = bigendian  # Set from drep[0] & DCERPC_DREP_LE
        self.flags = 0  # LIBNDR_FLAG_*

    def _ensure(self, n):
        """Ensure buffer has space for n bytes."""
        need = self.off + n - len(self.buf)
        if need > 0:
            self.buf.extend(b'\x00' * need)

    def align(self, n):
        """Align offset to n-byte boundary, adding zero padding."""
        if self.flags & LIBNDR_FLAG.NOALIGN:
            return
        pad = (-self.off) & (n - 1)  # Equivalent to (n - (off % n)) % n
        if pad:
            self._ensure(pad)
            self.off += pad

    def trailer_align(self, n):
        """Trailer alignment after variable-length fields."""
        self.align(n)

    def u8(self, v, flags=0):
        """Push uint8_t."""
        self.flags = flags
        if flags & LIBNDR_FLAG.PAD_CHECK and self.off % 1 != 0:
            raise ValueError("NDR_ERR_BUFSIZE: Misaligned u8")
        self._ensure(1)
        self.buf[self.off:self.off + 1] = struct.pack('B', v & 0xFF)
        self.off += 1

    def u16(self, v, flags=0):
        """Push uint16_t with optional alignment."""
        self.flags = flags
        if not (flags & LIBNDR_FLAG.NOALIGN):
            self.align(2)
        if flags & LIBNDR_FLAG.PAD_CHECK and self.off % 2 != 0:
            raise ValueError("NDR_ERR_BUFSIZE: Misaligned u16")
        self._ensure(2)
        fmt = '>H' if self.bigendian else '<H'
        self.buf[self.off:self.off + 2] = struct.pack(fmt, v & 0xFFFF)
        self.off += 2

    def u32(self, v, flags=0):
        """Push uint32_t with optional alignment."""
        self.flags = flags
        if not (flags & LIBNDR_FLAG.NOALIGN):
            self.align(4)
        if flags & LIBNDR_FLAG.PAD_CHECK and self.off % 4 != 0:
            raise ValueError("NDR_ERR_BUFSIZE: Misaligned u32")
        self._ensure(4)
        fmt = '>I' if self.bigendian else '<I'
        self.buf[self.off:self.off + 4] = struct.pack(fmt, v & 0xFFFFFFFF)
        self.off += 4

    def raw(self, b: bytes, flags=0):
        """Push raw bytes without alignment."""
        self.flags = flags
        n = len(b)
        self._ensure(n)
        self.buf[self.off:self.off + n] = b
        self.off += n

    def trailer_align4(self):
        """Convenience for DCERPC 4-byte trailer alignment."""
        self.trailer_align(4)

    def getvalue(self) -> bytes:
        """Return marshalled buffer."""
        return bytes(self.buf)

class NDRPull:
    def __init__(self, data: bytes, bigendian=False):
        self.b = memoryview(data)
        self.off = 0
        self.bigendian = bigendian  # Set from drep[0] & DCERPC_DREP_LE
        self.flags = 0  # LIBNDR_FLAG_*

    def align(self, n):
        """Align offset to n-byte boundary."""
        if self.flags & LIBNDR_FLAG.NOALIGN:
            return
        self.off = (self.off + (n - 1)) & ~(n - 1)  # Round up to multiple of n

    def trailer_align(self, n):
        """Trailer alignment after variable-length fields."""
        self.align(n)

    def _check_bounds(self, n):
        """Check if n bytes are available."""
        if self.off + n > len(self.b):
            raise ValueError(f"NDR_ERR_BUFSIZE: Need {n} bytes, only {len(self.b) - self.off} available")

    def u8(self, flags=0):
        """Pull uint8_t."""
        self.flags = flags
        if flags & LIBNDR_FLAG.PAD_CHECK and self.off % 1 != 0:
            raise ValueError("NDR_ERR_BUFSIZE: Misaligned u8")
        self._check_bounds(1)
        v = struct.unpack_from('B', self.b, self.off)[0]
        self.off += 1
        return v

    def u16(self, flags=0):
        """Pull uint16_t with optional alignment."""
        self.flags = flags
        if not (flags & LIBNDR_FLAG.NOALIGN):
            self.align(2)
        if flags & LIBNDR_FLAG.PAD_CHECK and self.off % 2 != 0:
            raise ValueError("NDR_ERR_BUFSIZE: Misaligned u16")
        self._check_bounds(2)
        fmt = '>H' if self.bigendian else '<H'
        v = struct.unpack_from(fmt, self.b, self.off)[0]
        self.off += 2
        return v

    def u32(self, flags=0):
        """Pull uint32_t with optional alignment."""
        self.flags = flags
        if not (flags & LIBNDR_FLAG.NOALIGN):
            self.align(4)
        if flags & LIBNDR_FLAG.PAD_CHECK and self.off % 4 != 0:
            raise ValueError("NDR_ERR_BUFSIZE: Misaligned u32")
        self._check_bounds(4)
        fmt = '>I' if self.bigendian else '<I'
        v = struct.unpack_from(fmt, self.b, self.off)[0]
        self.off += 4
        return v

    def raw(self, n, flags=0):
        """Pull n raw bytes without alignment."""
        self.flags = flags
        self._check_bounds(n)
        v = self.b[self.off:self.off + n].tobytes()
        self.off += n
        return v

    def trailer_align4(self):
        """Convenience for DCERPC 4-byte trailer alignment."""
        self.trailer_align(4)