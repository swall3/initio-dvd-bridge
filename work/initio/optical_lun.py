"""Read-only virtual DVD LUN; all sector data comes from read_blocks().

This presents a *virtual*, single-session, single-track DVD-ROM view of a
2048-byte-sector data disc. It does not impersonate the physical drive, expose
audio/raw sectors, alter firmware, eject media, or synthesize unread sectors.
Capacity is supplied by the caller from a verified READ CAPACITY response.

Wire layouts follow Microsoft's public scsi.h/ntddmmc.h MMC definitions:
https://github.com/microsoft/win32metadata/tree/main/generation/WinSDK/RecompiledIdlHeaders/shared
The module has no device, socket, service, or filesystem access.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Callable

from dvd_auth_commands import AUTH_OPCODES, validate_auth_command


@dataclass(frozen=True)
class ScsiResult:
    status: int = 0
    data: bytes = b""
    sense: bytes = b""


class ScsiError(Exception):
    """Optional backend exception preserving an actual SCSI sense condition."""

    def __init__(self, key: int, asc: int, ascq: int = 0):
        super().__init__(f"SCSI sense {key:02x}/{asc:02x}/{ascq:02x}")
        self.key, self.asc, self.ascq = key, asc, ascq


def _be(value: int, size: int) -> bytes:
    return value.to_bytes(size, "big")


def _u(data: bytes) -> int:
    return int.from_bytes(data, "big")


def fixed_sense(key: int, asc: int, ascq: int = 0) -> bytes:
    data = bytearray(18)
    data[0], data[2], data[7] = 0x70, key & 15, 10
    data[12], data[13] = asc, ascq
    return bytes(data)


class OpticalLun:
    """Single virtual DVD-ROM LUN implementing the transport execute contract.

    read_blocks(lba, count) must return exactly count*2048 bytes, or raise.
    Missing/short/backend-error data becomes CHECK CONDITION, never zero fill.
    block_count=None (or 0) exposes the same optical identity without media.
    A callback is mandatory whenever media is present. Calls are serialized.
    Optional backend_health() checks cached backend state only; False makes
    media-dependent commands NOT READY without changing media/event state.
    Optional auth_command(cdb12, size, direction, data_out=b'') returns an actual
    ScsiResult-compatible response. CSS feature advertising additionally needs
    the physical drive's validated eight-byte feature0106 descriptor; a callback
    alone does not assert support. No key data is generated or interpreted.
    Optional read_ahead_blocks=16 batches consecutive one-sector reads into a
    single verified window. Authentication, media changes and errors discard
    cached bytes. No background thread or speculative transport retry is used.
    """

    CDB_LENGTHS = {
        0x00: 6, 0x03: 6, 0x12: 6, 0x1A: 6, 0x1B: 6, 0x1E: 6,
        0x23: 10, 0x25: 10, 0x28: 10, 0x2F: 10, 0x35: 10,
        0x43: 10, 0x46: 10, 0x4A: 10, 0x51: 10, 0x52: 10, 0x5A: 10,
        0x88: 16, 0x91: 16, 0x9E: 16, 0xA0: 12, 0xA8: 12,
        0xA3: 12, 0xA4: 12, 0xAD: 12,
    }
    WRITE_OPCODES = frozenset({
        0x04, 0x0A, 0x15, 0x19, 0x1D, 0x2A, 0x2E, 0x3B, 0x3F,
        0x41, 0x50, 0x53, 0x54, 0x55, 0x58, 0x5B, 0x5D, 0x5F,
        0x89, 0x8A, 0x8E, 0x93, 0xAA, 0xAE, 0xB6, 0xBF,
    })
    NO_DATA = frozenset({0x00, 0x1B, 0x1E, 0x2F, 0x35, 0x91})
    NO_MEDIA_OK = frozenset({0x03, 0x12, 0x1A, 0x1B, 0x1E, 0x46,
                             0x4A, 0x5A, 0xA0})

    def __init__(self, read_blocks: Callable[[int, int], bytes] | None = None,
                 block_count: int | None = None, block_size: int = 2048,
                 *, serial: str = "CODEX-DVD-BRIDGE-0001",
                 max_transfer: int = 128 * 1024, read_chunk_blocks: int = 32,
                 backend_health: Callable[[], bool] | None = None,
                 auth_command: Callable | None = None,
                 css_feature: bytes | None = None,
                 read_ahead_blocks: int = 0):
        if block_size != 2048:
            raise ValueError("This DVD frontend requires 2048-byte logical blocks")
        if not isinstance(max_transfer, int) or max_transfer < block_size:
            raise ValueError("max_transfer must fit at least one logical block")
        if not isinstance(read_chunk_blocks, int) or read_chunk_blocks <= 0:
            raise ValueError("read_chunk_blocks must be positive")
        if type(read_ahead_blocks) is not int or read_ahead_blocks not in (0, 16):
            raise ValueError("read_ahead_blocks must be 0 or 16")
        if backend_health is not None and not callable(backend_health):
            raise ValueError("backend_health must be callable or None")
        if auth_command is not None and not callable(auth_command):
            raise ValueError("auth_command must be callable or None")
        if css_feature is not None:
            if not isinstance(css_feature, (bytes, bytearray, memoryview)):
                raise ValueError("css_feature must contain the observed descriptor bytes")
            css_feature = bytes(css_feature)
            if (auth_command is None or len(css_feature) != 8 or css_feature[:2] != b"\x01\x06" or
                    css_feature[2] & 0xC0 or css_feature[3] != 4 or any(css_feature[4:7]) or
                    css_feature[7] != 1):
                raise ValueError("CSS requires a backend and an observed valid CSS version1 feature descriptor")
        encoded = serial.encode("ascii")
        if not encoded or len(encoded) > 128:
            raise ValueError("serial must contain 1..128 ASCII bytes")
        self.serial = encoded
        self.block_size = block_size
        self.max_transfer = max_transfer
        self.read_chunk_blocks = min(read_chunk_blocks, max_transfer // block_size)
        self.read_ahead_blocks = min(read_ahead_blocks, self.read_chunk_blocks)
        self.backend_health = backend_health
        self.auth_command = auth_command
        self.css_feature = css_feature
        self._lock = RLock()
        self._sense = (0, 0, 0)
        self._unit_attention = None
        self._media_event = 0
        self.prevent_removal = False
        self._set_media(read_blocks, block_count)

    @property
    def media_present(self) -> bool:
        return self.block_count > 0

    def _set_media(self, reader, count):
        count = 0 if count is None else count
        if not isinstance(count, int) or not 0 <= count <= 0xFFFFFFFF:
            raise ValueError("block_count must be a nonnegative 32-bit block count")
        if count and not callable(reader):
            raise ValueError("Present media requires a real read_blocks callback")
        self.block_count, self.read_blocks = count, reader
        self._clear_read_cache()

    def _clear_read_cache(self, *, clear_failed=True):
        self._read_cache_lba = None
        self._read_cache_data = b""
        self._read_next_lba = None
        if clear_failed:
            self._read_failed_window = None

    def set_media(self, read_blocks=None, block_count=None):
        """Caller-provided media change; never polls or resets any hardware."""
        with self._lock:
            self._set_media(read_blocks, block_count)
            self._unit_attention = (6, 0x28, 0)
            self._media_event = 2 if self.media_present else 3

    def reset(self):
        """Virtual logical-unit reset only; deliberately does not call backend."""
        with self._lock:
            self._clear_read_cache()
            self._sense = (0, 0, 0)
            self._unit_attention = (6, 0x29, 0)
            self.prevent_removal = False

    def _check(self, key, asc, ascq=0):
        if key in (2, 3, 4, 6, 7):
            self._clear_read_cache(clear_failed=False)
        self._sense = (key, asc, ascq)
        return ScsiResult(2, sense=fixed_sense(key, asc, ascq))

    @staticmethod
    def _reply(data, allocation, expected):
        return ScsiResult(data=bytes(data)[:min(allocation, expected)])

    def execute(self, cdb: bytes, expected_length: int, direction: str,
                data_out: bytes = b"") -> ScsiResult:
        with self._lock:
            if not isinstance(cdb, (bytes, bytearray, memoryview)) or not cdb:
                return self._check(5, 0x24)
            cdb = bytes(cdb)
            if not isinstance(expected_length, int) or expected_length < 0:
                return self._check(5, 0x24)
            op = cdb[0]
            auth = op in AUTH_OPCODES and self.auth_command is not None
            # Reject before considering media state or invoking any backend.
            if (direction == "out" and not (auth and op == 0xA3)) or op in self.WRITE_OPCODES:
                return self._check(7, 0x27)
            if direction not in ("in", "out", "none") or expected_length > self.max_transfer:
                return self._check(5, 0x24)
            if not isinstance(data_out, (bytes, bytearray, memoryview)):
                return self._check(5, 0x24)
            data_out = bytes(data_out)
            if op in AUTH_OPCODES and not auth:
                return self._check(5, 0x20)
            if auth:
                try:
                    cdb = validate_auth_command(cdb, expected_length, direction, data_out)
                except ValueError:
                    return self._check(5, 0x24)
            elif data_out:
                return self._check(5, 0x24)
            required = self.CDB_LENGTHS.get(op)
            if required is None:
                return self._check(5, 0x20)
            if len(cdb) < required or any(cdb[required:]):
                return self._check(5, 0x24)
            if cdb[required - 1] & 0x05:  # linked commands/NACA unsupported
                return self._check(5, 0x24)
            if op in self.NO_DATA:
                if expected_length:
                    return self._check(5, 0x24)
            elif expected_length and direction != "in" and not auth:
                return self._check(5, 0x24)
            if op not in (0x03, 0x12, 0xA0) and self._unit_attention:
                condition, self._unit_attention = self._unit_attention, None
                return self._check(*condition)
            media_independent = auth and (
                op in (0xA3, 0xA4) and cdb[10] & 0x3F == 0x3F or
                op == 0xA4 and cdb[10] & 0x3F == 8)
            if op not in self.NO_MEDIA_OK and not media_independent and not self.media_present:
                return self._check(2, 0x3A)
            if op not in self.NO_MEDIA_OK and self.backend_health is not None:
                try:
                    ready = bool(self.backend_health())
                except Exception:
                    ready = False
                if not ready:
                    return self._check(2, 0x04)
            try:
                if auth:
                    return self._auth(cdb, expected_length, direction, data_out)
                return self._dispatch(op, cdb, expected_length)
            except ScsiError as exc:
                self._clear_read_cache(clear_failed=False)
                return self._check(exc.key, exc.asc, exc.ascq)

    def _auth(self, cdb, expected, direction, data_out):
        # A changed AGID/title key or failed auth must not leave a cached view
        # from an earlier authentication state. Clear even for read-only auth.
        self._clear_read_cache()
        try:
            result = self.auth_command(cdb, expected, direction, data_out=data_out)
            if (type(result.status) is not int or not 0 <= result.status <= 0xFF or
                    not isinstance(result.data, (bytes, bytearray, memoryview)) or
                    not isinstance(result.sense, (bytes, bytearray, memoryview))):
                raise ValueError("Invalid backend SCSI result")
            data, sense = bytes(result.data), bytes(result.sense)
            if len(data) > expected or (direction != "in" and data):
                raise ValueError("Backend returned data outside the validated allocation")
        except ScsiError:
            raise
        except Exception:
            return self._check(4, 0x44)  # backend/internal failure, no fabricated key data
        if result.status == 2 and sense:
            response = sense[0] & 0x7F
            if response in (0x70, 0x71) and len(sense) >= 14:
                self._sense = (sense[2] & 15, sense[12], sense[13])
            elif response in (0x72, 0x73) and len(sense) >= 4:
                self._sense = (sense[1] & 15, sense[2], sense[3])
        return ScsiResult(result.status, data, sense)

    def _dispatch(self, op, cdb, expected):
        if op == 0x00:
            return ScsiResult()
        if op == 0x03:
            if cdb[1] & ~1:
                return self._check(5, 0x24)
            key, asc, ascq = self._sense
            data = (bytes((0x72, key, asc, ascq, 0, 0, 0, 0))
                    if cdb[1] & 1 else fixed_sense(key, asc, ascq))
            self._sense = (0, 0, 0)
            return self._reply(data, cdb[4], expected)
        if op == 0x12:
            return self._inquiry(cdb, expected)
        if op == 0xA0:
            if cdb[2] not in (0, 1, 2) or _u(cdb[6:10]) < 16:
                return self._check(5, 0x24)
            luns = b"" if cdb[2] == 1 else bytes(8)
            return self._reply(_be(len(luns), 4) + bytes(4) + luns,
                               _u(cdb[6:10]), expected)
        if op == 0x25:
            if cdb[8] & ~1 or (not cdb[8] & 1 and _u(cdb[2:6])):
                return self._check(5, 0x24)
            return self._reply(_be(self.block_count - 1, 4) + _be(self.block_size, 4),
                               8, expected)
        if op == 0x9E:
            if cdb[1] != 0x10 or cdb[14] & ~1:
                return self._check(5, 0x24)
            if not cdb[14] & 1 and _u(cdb[2:10]):
                return self._check(5, 0x24)
            data = _be(self.block_count - 1, 8) + _be(self.block_size, 4) + bytes(20)
            return self._reply(data, _u(cdb[10:14]), expected)
        if op == 0x23:
            data = bytes((0, 0, 0, 8)) + _be(self.block_count, 4)
            data += b"\x02" + _be(self.block_size, 3)
            return self._reply(data, _u(cdb[7:9]), expected)
        if op in (0x28, 0xA8, 0x88, 0x2F):
            # Only DPO/FUA are accepted; no protection, RELADR, or compare data.
            if cdb[1] & ~0x18:
                return self._check(5, 0x24)
            lba = _u(cdb[2:10]) if op == 0x88 else _u(cdb[2:6])
            count = (_u(cdb[10:14]) if op == 0x88 else
                     _u(cdb[6:10]) if op == 0xA8 else _u(cdb[7:9]))
            # VERIFY and explicit FUA/DPO requests always reach the backend;
            # they neither consume nor seed speculative cached data.
            data = self._read(lba, count, use_cache=op != 0x2F and not (cdb[1] & 0x18))
            return ScsiResult() if op == 0x2F else self._reply(data, len(data), expected)
        if op in (0x1A, 0x5A):
            return self._mode_sense(cdb, expected, op == 0x5A)
        if op == 0x46:
            return self._configuration(cdb, expected)
        if op == 0x43:
            return self._toc(cdb, expected)
        if op == 0x4A:
            if cdb[1] != 1:  # polled notification only
                return self._check(5, 0x24)
            if cdb[4] & 0x10:
                event, self._media_event = self._media_event, 0
                body = bytes((event, 2 if self.media_present else 0, 0, 0))
                data = b"\x00\x06\x04\x10" + body
            else:
                data = b"\x00\x02\x80\x10"
            return self._reply(data, _u(cdb[7:9]), expected)
        if op == 0x51:
            if cdb[1] & 7:
                return self._check(5, 0x24)
            data = bytearray(34)
            data[:2] = _be(32, 2)
            data[2:7] = bytes((0x0E, 1, 1, 1, 1))  # closed, one session/track
            data[8] = 0xFF  # DVD: CD disc type unspecified
            return self._reply(data, _u(cdb[7:9]), expected)
        if op == 0x52:
            address_type, address = cdb[1] & 3, _u(cdb[2:6])
            if (cdb[1] & ~3 or address_type == 3
                    or address_type in (1, 2) and address != 1
                    or address_type == 0 and address >= self.block_count):
                return self._check(5, 0x24)
            data = bytearray(36)
            data[:2] = _be(34, 2)
            data[2:8] = bytes((1, 1, 0, 4, 1, 2))
            data[24:28] = _be(self.block_count, 4)
            data[28:32] = _be(self.block_count - 1, 4)
            return self._reply(data, _u(cdb[7:9]), expected)
        if op == 0x1E:
            if cdb[4] & ~1:
                return self._check(5, 0x24)
            self.prevent_removal = bool(cdb[4] & 1)
            return ScsiResult()
        if op == 0x1B:
            # A virtual stop/start has no dirty state or motor. No physical eject.
            if cdb[4] & ~1:
                return self._check(5, 0x24)
            return ScsiResult()
        if op in (0x35, 0x91):
            return ScsiResult()  # Read-only LUN has no dirty data to synchronize.
        return self._check(5, 0x20)

    def _read(self, lba, count, *, use_cache=True):
        if not count:
            return b""
        if lba >= self.block_count or count > self.block_count - lba:
            raise ScsiError(5, 0x21)
        if count * self.block_size > self.max_transfer:
            raise ScsiError(5, 0x24)
        try:
            if use_cache and count == 1 and self.read_ahead_blocks > 1:
                data = self._read_single_cached(lba)
                self._read_next_lba = lba + 1
                return data
            # Multi-sector requests already batch their own physical reads.
            # They do not seed the one-sector sequential detector.
            self._clear_read_cache(clear_failed=False)
            chunks = []
            while count:
                n = min(count, self.read_chunk_blocks)
                chunks.append(self._fetch_blocks(lba, n))
                lba, count = lba + n, count - n
            return b"".join(chunks)
        except ScsiError:
            self._clear_read_cache(clear_failed=False)
            raise
        except Exception as exc:
            self._clear_read_cache(clear_failed=False)
            # Preserve the established frontend error mapping, but never retry
            # transport exceptions or malformed/short data as speculative sense.
            raise ScsiError(3, 0x11) from exc

    def _fetch_blocks(self, lba, count):
        data = self.read_blocks(lba, count)
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("read_blocks must return bytes")
        data = bytes(data)
        if len(data) != count * self.block_size:
            raise OSError("short or oversized optical read")
        return data

    def _read_single_cached(self, lba):
        if self._read_cache_lba is not None:
            offset = (lba - self._read_cache_lba) * self.block_size
            if 0 <= offset and offset + self.block_size <= len(self._read_cache_data):
                return self._read_cache_data[offset:offset + self.block_size]
        self._read_cache_lba, self._read_cache_data = None, b""
        n = 1
        if self._read_next_lba == lba:
            n = min(self.read_ahead_blocks, self.block_count - lba)
            if self._read_failed_window is not None:
                start, end = self._read_failed_window
                if start <= lba < end:
                    n = 1
                elif lba < start < lba + n:
                    n = start - lba
        try:
            data = self._fetch_blocks(lba, n)
        except ScsiError as exc:
            if n == 1 or exc.key not in (3, 5, 7):
                raise
            # A valid completed CHECK CONDITION might concern a future block.
            # Discard the whole speculative window; only a fresh read of the
            # requested block can determine this request's actual result.
            self._clear_read_cache(clear_failed=False)
            self._read_failed_window = (lba, lba + n)
            return self._fetch_blocks(lba, 1)
        if n > 1:
            self._read_cache_lba, self._read_cache_data = lba, data
        return data[:self.block_size]

    def _inquiry(self, cdb, expected):
        if cdb[1] & ~1 or cdb[3]:
            return self._check(5, 0x24)
        page = cdb[2]
        if cdb[1] & 1:
            if page == 0:
                body = bytes((0, 0x80, 0x83))
            elif page == 0x80:
                body = self.serial
            elif page == 0x83:
                identifier = b"CODEX   " + self.serial
                body = bytes((2, 1, 0, len(identifier))) + identifier
            else:
                return self._check(5, 0x24)
            data = bytes((5, page)) + _be(len(body), 2) + body
        else:
            if page:
                return self._check(5, 0x24)
            data = bytearray(36)
            data[:5] = bytes((5, 0x80, 5, 2, 31))
            data[8:16] = b"CODEX   "
            data[16:32] = b"USB DVD Bridge  "
            data[32:36] = b"0001"
        return self._reply(data, cdb[4], expected)

    def _mode_sense(self, cdb, expected, ten):
        if cdb[1] & ~8 or cdb[3] not in (0, 0xFF):
            return self._check(5, 0x24)
        page, control = cdb[2] & 0x3F, cdb[2] >> 6
        if control == 3:
            return self._check(5, 0x39)
        recovery = bytearray(12)
        recovery[:2] = bytes((1, 10))
        caching = bytearray(20)
        caching[:2] = bytes((8, 18))  # no write-cache enable
        caps = bytearray(30)
        caps[:3] = bytes((0x2A, 28, 0x08))  # DVD-ROM read, no writes/audio
        caps[6] = 1 | (2 if self.prevent_removal else 0)  # virtual lock policy
        pages = {1: recovery, 8: caching, 0x2A: caps}
        if page not in (*pages, 0x3F):
            return self._check(5, 0x24)
        selected = [pages[p] for p in sorted(pages)] if page == 0x3F else [pages[page]]
        if control == 1:
            selected = [p[:2] + bytes(len(p) - 2) for p in selected]
        desc = b""
        if not cdb[1] & 8:
            desc = b"\x00" + _be(min(self.block_count, 0xFFFFFF), 3)
            desc += b"\x00" + _be(self.block_size, 3)
        body = desc + b"".join(selected)
        if ten:
            data = _be(len(body) + 6, 2) + b"\x00\x80\x00\x00" + _be(len(desc), 2) + body
            allocation = _u(cdb[7:9])
        else:
            data = bytes((len(body) + 3, 0, 0x80, len(desc))) + body
            allocation = cdb[4]
        return self._reply(data, allocation, expected)

    def _configuration(self, cdb, expected):
        request_type, start = cdb[1] & 3, _u(cdb[2:4])
        if cdb[1] & ~3 or request_type == 3:
            return self._check(5, 0x24)
        current = int(self.media_present)
        features = {
            0: (3, b"\x00\x10" + bytes((current, 0))),
            1: (3, bytes(8)),  # virtual/unspecified physical interface
            2: (3, bytes(4)),  # polled events only
            3: (3, b"\x01\x00\x00\x00"),  # lockable; no mechanical eject/load
            0x10: (current, _be(self.block_size, 4) + b"\x00\x01\x01\x00"),
            0x1F: (current, bytes(4)),
            0x108: (3, self.serial + bytes((-len(self.serial)) % 4)),
        }
        if self.auth_command is not None and self.css_feature is not None:
            flags = self.css_feature[2]
            features[0x106] = ((flags & ~1) | (flags & current), self.css_feature[4:])
        data = bytearray()
        for number, (flags, body) in sorted(features.items()):
            if (number < start or request_type == 2 and number != start
                    or request_type == 1 and not flags & 1):
                continue
            data += _be(number, 2) + bytes((flags, len(body))) + body
        data = _be(len(data) + 4, 4) + bytes(2) + _be(0x10 if current else 0, 2) + data
        return self._reply(data, _u(cdb[7:9]), expected)

    @staticmethod
    def _address(lba, msf):
        if not msf:
            return _be(lba, 4)
        minutes, rem = divmod(lba + 150, 75 * 60)
        seconds, frames = divmod(rem, 75)
        if minutes > 255:
            # Large DVDs cannot be represented by the legacy MSF minute byte.
            raise ScsiError(5, 0x24)
        return bytes((0, minutes, seconds, frames))

    def _toc(self, cdb, expected):
        if cdb[1] & ~2 or cdb[2] & ~15:
            return self._check(5, 0x24)
        fmt, track, msf = cdb[2] & 15, cdb[6], bool(cdb[1] & 2)
        if fmt == 0:
            if track not in (0, 1, 0xAA):
                return self._check(5, 0x24)
            entries = b""
            if track != 0xAA:
                entries += b"\x00\x14\x01\x00" + self._address(0, msf)
            entries += b"\x00\x14\xaa\x00" + self._address(self.block_count, msf)
        elif fmt == 1 and track == 0:
            entries = b"\x00\x14\x01\x00" + self._address(0, msf)
        else:
            return self._check(5, 0x24)
        data = _be(len(entries) + 2, 2) + b"\x01\x01" + entries
        return self._reply(data, _u(cdb[7:9]), expected)
