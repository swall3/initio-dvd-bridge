"""Hardware-free whitelist for standard DVD CSS authentication/read commands.

Layouts: Microsoft Windows SDK scsi.h SEND_KEY/REPORT_KEY/READ_DVD_STRUCTURE,
CDVD_KEY_HEADER and payload structures; ntddmmc.h FEATURE_DATA_DVD_CSS.
https://github.com/microsoft/win32metadata/tree/main/generation/WinSDK/RecompiledIdlHeaders/shared
Linux setup_report_key/setup_send_key/dvd_do_auth confirm format lengths and
REPORT KEY (A4), format3F, zero allocation for AGID invalidation:
https://github.com/torvalds/linux/blob/master/drivers/cdrom/cdrom.c
Windows DeviceHandleDvdEndSession uses SEND KEY (A3), format3F, zero transfer:
https://github.com/microsoft/Windows-driver-samples/blob/win11-22h2/storage/class/cdrom/src/ioctl.c

This does not perform authentication, change regions, or interpret key material.
"""

AUTH_OPCODES = frozenset((0xA3, 0xA4, 0xAD))
REPORT_FORMATS = {0: ("report_agid", 8), 1: ("report_challenge", 16),
                  2: ("report_key1", 12), 4: ("report_title_key", 12),
                  5: ("report_asf", 8), 8: ("report_rpc", 8)}
SEND_FORMATS = {1: ("send_challenge", 16), 3: ("send_key2", 12)}
STRUCTURE_FORMATS = {0: ("dvd_physical", 2052), 1: ("dvd_copyright", 8),
                     2: ("dvd_disc_key", 2052)}


def _normalize(cdb):
    if not isinstance(cdb, (bytes, bytearray, memoryview)):
        raise ValueError("CDB must contain bytes")
    cdb = bytes(cdb)
    if len(cdb) not in (10, 12, 16):
        raise ValueError("Unsupported CDB length")
    required = 10 if cdb[0] == 0x46 else 12
    if len(cdb) < required or any(cdb[required:]):
        raise ValueError("CDB is truncated or has nonzero padding")
    if cdb[required - 1]:
        raise ValueError("Control flags are not supported")
    return cdb[:required].ljust(12, b"\x00")


def validate_auth_cdb(cdb, expected_length, direction):
    """Validate envelope before any payload arrives; return the command kind.

    Input allocations must equal the transport length and fit the known format;
    short header queries (at least four bytes) are allowed. Outbound auth uses
    only the exact16-byte challenge or12-byte key2 parameter list. The one
    capability probe is GET CONFIGURATION RT2/start0106/allocation16.
    """
    cdb = _normalize(cdb)
    if type(expected_length) is not int or expected_length < 0:
        raise ValueError("Invalid transport length")
    op = cdb[0]
    if op == 0x46:
        if (cdb[1:4] != b"\x02\x01\x06" or any(cdb[4:7]) or
                int.from_bytes(cdb[7:9], "big") != 16 or expected_length != 16 or direction != "in"):
            raise ValueError("Only the exact DVD CSS capability probe is allowed")
        return "capability_probe"
    if op not in AUTH_OPCODES or cdb[1]:
        raise ValueError("Unsupported authentication opcode, media type, or LUN")
    allocation = int.from_bytes(cdb[8:10], "big")
    if allocation != expected_length:
        raise ValueError("CDB and transport lengths differ")
    fmt, agid = cdb[10] & 0x3F, cdb[10] >> 6
    if op == 0xA3:
        if any(cdb[2:8]):
            raise ValueError("Reserved SEND KEY fields must be zero")
        if fmt == 0x3F:
            if allocation or direction != "none":
                raise ValueError("Windows AGID invalidation requires a zero-data SEND KEY")
            return "invalidate_agid"
        if fmt not in SEND_FORMATS:
            raise ValueError("Only CSS challenge and key2 may be sent; region setting is forbidden")
        kind, size = SEND_FORMATS[fmt]
        if direction != "out" or allocation != size:
            raise ValueError("SEND KEY requires its exact outbound parameter length")
        return kind
    if op == 0xA4:
        if any(cdb[6:8]) or (fmt != 4 and any(cdb[2:6])):
            raise ValueError("Reserved REPORT KEY fields must be zero")
        if fmt == 0x3F:
            if allocation or direction not in ("none", "in"):
                raise ValueError("AGID invalidation is a zero-length REPORT KEY")
            return "invalidate_agid"
        if fmt not in REPORT_FORMATS or (fmt == 8 and agid):
            raise ValueError("Unsupported REPORT KEY format or RPC AGID")
        kind, size = REPORT_FORMATS[fmt]
    else:
        fmt = cdb[7]
        if (any(cdb[2:6]) or cdb[10] & 0x3F or fmt not in STRUCTURE_FORMATS or
                cdb[6] > 3 or (fmt == 2 and cdb[6]) or (fmt != 2 and agid)):
            raise ValueError("Unsupported DVD structure format, layer, or AGID fields")
        kind, size = STRUCTURE_FORMATS[fmt]
    if direction != "in" or not 4 <= allocation <= size:
        raise ValueError("Input allocation is outside the bounded format size")
    return kind


def validate_auth_command(cdb, expected_length, direction, data_out=b""):
    """Validate payload too; return the normalized12-byte CDB or raise ValueError."""
    kind = validate_auth_cdb(cdb, expected_length, direction)
    cdb = _normalize(cdb)
    if not isinstance(data_out, (bytes, bytearray, memoryview)):
        raise ValueError("Outbound data must contain bytes")
    payload = bytes(data_out)
    if direction != "out":
        if payload:
            raise ValueError("Input/no-data commands cannot carry outbound data")
        return cdb
    if len(payload) != expected_length or int.from_bytes(payload[:2], "big") != expected_length - 2:
        raise ValueError("SEND KEY data and header length mismatch")
    if any(payload[2:4]):
        raise ValueError("SEND KEY header reserved bytes must be zero")
    padding = 14 if kind == "send_challenge" else 9
    if any(payload[padding:]):
        raise ValueError("SEND KEY payload reserved bytes must be zero")
    return cdb
