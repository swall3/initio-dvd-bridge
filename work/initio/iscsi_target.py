"""Small loopback-only, read-only iSCSI target (RFC 7143, sections 6, 11, 13).

No socket, service, driver or backend is opened on import. TargetServer.start is
deliberately absent: call serve_forever explicitly from an authorized launcher.

Backend contract: execute(cdb: bytes[16], expected_length: int, direction: str)
returns ScsiResult, a duck-typed status/data/sense object, or (status,data,sense).
Input/no-data retain this three-argument interface. Only validated DVD SEND KEY
challenge/key2 authentication calls use direction='out', data_out=bytes as an
additional keyword argument (16 or 12 bytes). Media writes never reach the backend.
Calls are serialized
and MUST be bounded by the backend. This implementation has one connection per
session, one normal session, ERL=0, no digests/AHS/bidirectional I/O. TMFs cannot
interrupt a synchronous backend call; quiescent logical-unit reset is optional.

Reference: https://www.rfc-editor.org/rfc/rfc7143.html
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import socket
import struct
import threading
import time
from typing import Callable

from dvd_auth_commands import validate_auth_cdb, validate_auth_command

TARGET_IQN = 'iqn.2026-11.local.codex:initio-dvd'
PORT = 32610
LOOPBACK = '127.0.0.1'
MAX_TRANSFER = 256 * 1024
# Includes PDU headers/padding even with the minimum negotiated 512-byte
# segment/burst sizes. This bounds each contiguous socket write independently
# of the logical transfer limit above.
MAX_RESPONSE_BATCH = 2 * MAX_TRANSFER
MAX_RECV_SEGMENT = 65536
MAX_LOGIN_TEXT = 65536
AUTH_DATA_TIMEOUT = 30
MASK = 0xffffffff
READ_ONLY_OPCODES = frozenset((0x00,0x03,0x12,0x1a,0x1b,0x1e,0x23,0x25,0x28,0x2f,0x35,
                             0x43,0x44,0x46,0x4a,0x51,0x52,0x5a,0x5c,
                             0x88,0x91,0x9e,0xa0,0xa4,0xa8,0xad,0xb9,0xbe))


class ProtocolError(ValueError):
    pass


def u32(buf, offset):
    return struct.unpack_from('>I', buf, offset)[0]


def put32(buf, offset, value):
    struct.pack_into('>I', buf, offset, value & MASK)


def log_json(event, **fields):
    print(json.dumps({'time': time.time(), 'event': event, **fields}), flush=True)


@dataclass(frozen=True)
class ScsiResult:
    status: int = 0
    data: bytes = b''
    sense: bytes = b''


def check_condition(key, asc, ascq=0):
    sense = bytearray(18)
    sense[0] = 0x70
    sense[2] = key
    sense[7] = 10
    sense[12:14] = bytes((asc, ascq))
    return ScsiResult(2, b'', bytes(sense))


@dataclass(frozen=True)
class PDU:
    header: bytes
    data: bytes = b''
    ahs: bytes = b''

    def __post_init__(self):
        if len(self.header) != 48:
            raise ProtocolError('BHS must contain 48 bytes')
        if len(self.ahs) != self.header[4] * 4:
            raise ProtocolError('AHS length mismatch')
        if len(self.data) != int.from_bytes(self.header[5:8], 'big'):
            raise ProtocolError('Data segment length mismatch')

    @property
    def opcode(self):
        return self.header[0] & 0x3f

    @property
    def itt(self):
        return u32(self.header, 16)

    def encode(self):
        return self.header + self.ahs + self.data + bytes((-len(self.data)) & 3)


@dataclass
class PendingAuth:
    request: PDU
    expected: int
    ttt: int
    started: float
    data: bytearray
    next_datasn: int = 0


def make_pdu(header, data=b''):
    h = bytearray(header)
    if len(data) > 0xffffff:
        raise ProtocolError('Data segment too large')
    h[5:8] = len(data).to_bytes(3, 'big')
    return PDU(bytes(h), bytes(data))


def recv_exact(conn, length):
    chunks = bytearray()
    while len(chunks) < length:
        chunk = conn.recv(length - len(chunks))
        if not chunk:
            raise EOFError('Connection ended')
        chunks.extend(chunk)
    return bytes(chunks)


def recv_pdu(conn, max_segment=MAX_RECV_SEGMENT):
    header = recv_exact(conn, 48)
    length = int.from_bytes(header[5:8], 'big')
    if length > max_segment:
        raise ProtocolError('Peer exceeded receive segment limit')
    # Bound and consume AHS before rejecting it in Session; keep framing exact.
    ahs = recv_exact(conn, header[4] * 4)
    data = recv_exact(conn, length)
    padding = recv_exact(conn, (-length) & 3)
    if any(padding):
        raise ProtocolError('Nonzero data padding')
    return PDU(header, data, ahs)


def parse_text(data):
    if len(data) > MAX_LOGIN_TEXT or (data and not data.endswith(b'\0')):
        raise ProtocolError('Invalid or oversized text segment')
    result = {}
    for entry in data.split(b'\0'):
        if not entry:
            continue
        try:
            key, value = entry.decode('utf-8', errors='strict').split('=', 1)
        except (ValueError, UnicodeError) as exc:
            raise ProtocolError('Invalid text key/value') from exc
        if not key or len(key) > 63 or len(value) > 4096 or key in result:
            raise ProtocolError('Invalid or duplicate text key')
        result[key] = value
    return result


def encode_text(values):
    return b''.join((key + '=' + str(value)).encode('utf-8') + b'\0'
                    for key, value in values.items())


def integer(value, minimum, maximum):
    try:
        number = int(value, 0) if value.lower().startswith('0x') else int(value, 10)
    except ValueError as exc:
        raise ProtocolError('Invalid numeric negotiation value') from exc
    if not minimum <= number <= maximum:
        raise ProtocolError('Negotiation value outside RFC range')
    return number


class Session:
    """Pure PDU/session state machine; handle() never opens a socket."""
    def __init__(self, backend, *, target_iqn=TARGET_IQN, port=PORT,
                 max_transfer=MAX_TRANSFER, emit=log_json,
                 claim_normal: Callable[[], bool] | None = None,
                 release_normal: Callable[[], None] | None = None):
        self.backend = backend
        self.target_iqn = target_iqn
        self.port = port
        self.max_transfer = max_transfer
        self.emit = emit
        self.claim_normal = claim_normal or (lambda: True)
        self.release_normal = release_normal or (lambda: None)
        self.claimed = False
        self.closed = False
        self.full_feature = False
        self.login_identity = None
        self.login_count = 0
        self.login_fragments = bytearray()
        self.login_values = {}
        self.declared = set()
        self.session_type = 'Normal'
        self.stage = None
        self.statsn = 0
        self.exp_cmdsn = 0
        self.active = False
        self.pending_auth = None
        self.next_ttt = 1
        self.peer_max_recv = 8192
        self.max_burst = 262144
        self.time2wait = 2
        self.tsih = 1

    def close(self):
        self.closed = True
        self.cancel_auth()
        if self.claimed:
            self.claimed = False
            self.release_normal()

    def cancel_auth(self):
        if self.pending_auth is not None:
            self.pending_auth.data.clear()
            self.pending_auth = None
        self.active = False

    def response_header(self, opcode, itt, *, flags=0x80, status=True):
        h = bytearray(48)
        h[0], h[1] = opcode, flags
        put32(h, 16, itt)
        if status:
            put32(h, 24, self.statsn)
            self.statsn = (self.statsn + 1) & MASK
        put32(h, 28, self.exp_cmdsn)
        put32(h, 32, self.exp_cmdsn - (1 if self.active else 0))
        return h

    def login_error(self, request, detail, status_class=2):
        h = self.response_header(0x23, request.itt, flags=0)
        h[8:14] = request.header[8:14]
        h[36:38] = bytes((status_class, detail))
        self.emit('login_rejected', status_class=status_class, detail=detail)
        self.close()
        return [make_pdu(h)]

    def negotiate(self, values):
        reply = {}
        # Text keys are unordered. Resolve this bound before FirstBurstLength.
        if 'MaxBurstLength' in values:
            self.max_burst = min(integer(values['MaxBurstLength'], 512, 0xffffff), self.max_transfer)
        for key, value in values.items():
            if key in self.login_values:
                raise ProtocolError('Repeated login key: ' + key)
            self.login_values[key] = value
            if key in ('InitiatorName', 'InitiatorAlias', 'TargetName', 'SessionType'):
                continue
            if key in ('AuthMethod', 'HeaderDigest', 'DataDigest'):
                if 'None' not in value.split(','):
                    raise ProtocolError('Only authentication/digest None is supported')
                reply[key] = 'None'
            elif key == 'MaxRecvDataSegmentLength':
                self.peer_max_recv = integer(value, 512, 0xffffff)
                reply[key] = str(MAX_RECV_SEGMENT)
            elif key == 'MaxConnections':
                integer(value, 1, 65535)
                reply[key] = '1'
            elif key in ('InitialR2T', 'DataPDUInOrder', 'DataSequenceInOrder'):
                if value not in ('Yes', 'No'):
                    raise ProtocolError('Invalid boolean key')
                reply[key] = 'Yes'
            elif key in ('ImmediateData', 'IFMarker', 'OFMarker'):
                if value not in ('Yes', 'No'):
                    raise ProtocolError('Invalid boolean key')
                reply[key] = 'No'
            elif key == 'MaxBurstLength':
                self.max_burst = min(integer(value, 512, 0xffffff), self.max_transfer)
                reply[key] = str(self.max_burst)
            elif key == 'FirstBurstLength':
                reply[key] = str(min(integer(value, 512, 0xffffff), 65536, self.max_burst))
            elif key == 'MaxOutstandingR2T':
                integer(value, 1, 65535)
                reply[key] = '1'
            elif key == 'ErrorRecoveryLevel':
                integer(value, 0, 2)
                reply[key] = '0'
            elif key in ('DefaultTime2Wait', 'DefaultTime2Retain'):
                number = integer(value, 0, 3600)
                if key == 'DefaultTime2Wait':
                    self.time2wait = number
                    reply[key] = str(number)
                else:
                    reply[key] = '0'
            elif key in ('IFMarkInt', 'OFMarkInt'):
                reply[key] = 'Reject'  # RFC 7143 section 13.25 obsoleted keys.
            else:
                reply[key] = 'NotUnderstood'
        if 'TargetPortalGroupTag' not in self.declared:
            reply['TargetPortalGroupTag'] = '1'
        self.declared.update(reply)
        return reply

    def login(self, request):
        h = request.header
        self.login_count += 1
        if self.login_count > 16 or h[3] != 0 or h[2] < h[3]:
            return self.login_error(request, 5)
        csg, nsg = (h[1] >> 2) & 3, h[1] & 3
        transit, continuation = bool(h[1] & 0x80), bool(h[1] & 0x40)
        if csg not in (0, 1) or (transit and continuation):
            return self.login_error(request, 0)
        identity = (h[8:14], h[16:20], h[20:22])
        if self.login_identity is None:
            self.login_identity = identity
            self.exp_cmdsn = u32(h, 24)
            self.stage = csg
        if identity != self.login_identity or csg != self.stage or h[14:16] != b'\0\0':
            return self.login_error(request, 8)
        if u32(h, 24) != self.exp_cmdsn:
            return self.login_error(request, 0)
        self.login_fragments.extend(request.data)
        if len(self.login_fragments) > MAX_LOGIN_TEXT:
            return self.login_error(request, 0)
        reply = {}
        if not continuation:
            try:
                reply = self.negotiate(parse_text(bytes(self.login_fragments)))
                self.login_fragments.clear()
            except ProtocolError as exc:
                self.emit('negotiation_error', message=str(exc))
                return self.login_error(request, 0)
            self.session_type = self.login_values.get('SessionType', 'Normal')
            if self.session_type not in ('Normal', 'Discovery'):
                return self.login_error(request, 9)
        if transit:
            if nsg not in (1, 3) or nsg <= csg:
                return self.login_error(request, 0)
            if not self.login_values.get('InitiatorName'):
                return self.login_error(request, 7)
            if nsg == 3 and self.session_type == 'Normal':
                if self.login_values.get('TargetName') != self.target_iqn:
                    return self.login_error(request, 3)
                if not self.claim_normal():
                    return self.login_error(request, 6)
                self.claimed = True
            self.stage = nsg
            self.full_feature = nsg == 3
        flags = (csg << 2) | (0x80 | nsg if transit else 0)
        response = self.response_header(0x23, request.itt, flags=flags)
        response[8:14] = h[8:14]
        if self.full_feature:
            response[14:16] = self.tsih.to_bytes(2, 'big')
        self.emit('login', stage=csg, next_stage=self.stage,
                  session_type=self.session_type, full_feature=self.full_feature,
                  request_keys=list(reply), peer_max_recv=self.peer_max_recv)
        return [make_pdu(response, encode_text(reply))]

    def command_sequence(self, request):
        if request.header[0] & 0x40:
            return True
        received = u32(request.header, 24)
        if self.active or received != self.exp_cmdsn:
            self.emit('cmdsn_outside_window', received=received, expected=self.exp_cmdsn)
            return False  # Never replay or execute a command outside the one-slot window.
        self.exp_cmdsn = (self.exp_cmdsn + 1) & MASK
        return True

    def reject(self, request, reason=4):
        response = self.response_header(0x3f, MASK)
        response[2] = reason
        self.emit('pdu_rejected', opcode=request.opcode, reason=reason)
        return [make_pdu(response, request.header + request.ahs)]

    def normalize_result(self, result):
        if isinstance(result, tuple):
            result = ScsiResult(*result)
        value = ScsiResult(int(result.status), bytes(result.data), bytes(result.sense))
        if value.status not in (0, 2, 8, 0x18, 0x28) or len(value.data) > self.max_transfer or len(value.sense) > 252:
            raise ProtocolError('Backend returned an invalid or oversized result')
        if value.status == 2 and not value.sense:
            raise ProtocolError('CHECK CONDITION requires autosense')
        return value

    def scsi(self, request):
        h = request.header
        expected = u32(h, 20)
        cdb = h[32:48]
        direction = 'out' if h[1] & 0x20 else 'in' if h[1] & 0x40 else 'none'
        self.emit('scsi_command', itt=request.itt, cmdsn=u32(h, 24),
                  cdb=cdb.hex(), expected_length=expected, direction=direction)
        self.active = True
        started = time.monotonic()
        try:
            if h[8:16] != bytes(8):
                result = check_condition(5, 0x25)
            elif expected > self.max_transfer or (direction == 'none' and expected):
                result = check_condition(5, 0x24)
            elif cdb[0] == 0xa3:
                try:
                    kind = validate_auth_cdb(cdb, expected, direction)
                except ValueError:
                    result = check_condition(5, 0x24)
                else:
                    if kind == 'invalidate_agid':
                        validate_auth_command(cdb, expected, direction)
                        result = self.normalize_result(self.backend.execute(cdb, expected, direction))
                        if result.data:
                            raise ProtocolError('No-data authentication returned unexpected data')
                    else:
                        return self.request_auth_data(request, expected, started)
            elif direction == 'out' or request.data or cdb[0] not in READ_ONLY_OPCODES:
                result = check_condition(7, 0x27) if direction == 'out' else check_condition(5, 0x20)
            elif cdb[0] == 0x1b and cdb[4] & 2:
                result = check_condition(5, 0x24)  # No physical eject via this bridge.
            else:
                try:
                    if cdb[0] == 0xa4:
                        validate_auth_command(cdb, expected, direction)
                except ValueError:
                    result = check_condition(5, 0x24)
                else:
                    result = self.normalize_result(self.backend.execute(cdb, expected, direction))
        except Exception as exc:
            self.emit('backend_error', error=type(exc).__name__, message=str(exc))
            result = check_condition(4, 0x44)
        return self.complete_scsi(request, result, started)

    def request_auth_data(self, request, expected, started):
        # RFC 7143 11.8: one nonzero, bounded R2T; no immediate/unsolicited data.
        if expected not in (12, 16) or expected > self.max_burst or request.data:
            raise ProtocolError('Invalid authentication data request')
        ttt = self.next_ttt
        self.next_ttt = (ttt + 1) & MASK
        if self.next_ttt == MASK:
            self.next_ttt = 0
        self.pending_auth = PendingAuth(request, expected, ttt, started, bytearray())
        response = self.response_header(0x31, request.itt, status=False)
        response[8:16] = request.header[8:16]
        put32(response, 20, ttt)
        put32(response, 24, self.statsn)  # R2T reports but does not consume StatSN.
        put32(response, 44, expected)  # R2TSN=0, BufferOffset=0.
        self.emit('auth_r2t', itt=request.itt, bytes=expected)
        return [make_pdu(response)]

    def auth_data(self, request):
        pending = self.pending_auth
        h = request.header
        # Data-Out has no CmdSN. Correlate every PDU before buffering anything.
        if (pending is None or h[0] != 5 or h[1] & 0x7f or any(h[2:4]) or
                h[8:16] != pending.request.header[8:16] or request.itt != pending.request.itt or
                u32(h, 20) != pending.ttt or u32(h, 36) != pending.next_datasn or
                u32(h, 40) != len(pending.data) or any(h[24:28]) or any(h[32:36]) or any(h[44:48]) or
                len(request.data) > MAX_RECV_SEGMENT or len(pending.data) + len(request.data) > pending.expected):
            self.close()  # ERL=0: discard the incomplete task with the connection.
            return self.reject(request)
        pending.data.extend(request.data)
        pending.next_datasn = (pending.next_datasn + 1) & MASK
        if not h[1] & 0x80:
            return []  # Zero-length PDUs are permitted by RFC 7143 11.7.7.
        if len(pending.data) != pending.expected:
            self.close()
            return self.reject(request)
        payload = bytes(pending.data)
        cdb = pending.request.header[32:48]
        try:
            validate_auth_command(cdb, pending.expected, 'out', data_out=payload)
        except ValueError:
            result = check_condition(5, 0x26)  # Invalid field in parameter list.
        else:
            try:
                result = self.normalize_result(self.backend.execute(
                    cdb, pending.expected, 'out', data_out=payload))
                if result.data:
                    raise ProtocolError('Authentication data-out backend returned input data')
            except Exception as exc:
                self.emit('backend_error', error=type(exc).__name__, message=str(exc))
                result = check_condition(4, 0x44)
        self.cancel_auth()
        return self.complete_scsi(pending.request, result, pending.started,
                                  transferred_out=len(payload))

    def complete_scsi(self, request, result, started, *, transferred_out=0):
        h = request.header
        expected = u32(h, 20)
        direction = 'out' if h[1] & 0x20 else 'in' if h[1] & 0x40 else 'none'
        actual = len(result.data)
        sent = min(actual, expected) if direction == 'in' else 0
        responses = []
        offset = datasn = sequence_bytes = 0
        while offset < sent:
            size = min(sent - offset, self.peer_max_recv, MAX_RECV_SEGMENT,
                       self.max_burst - sequence_bytes)
            sequence_bytes += size
            last_sequence = offset + size == sent or sequence_bytes == self.max_burst
            data_header = self.response_header(0x25, request.itt,
                                              flags=0x80 if last_sequence else 0, status=False)
            put32(data_header, 20, MASK)
            put32(data_header, 36, datasn)
            put32(data_header, 40, offset)
            responses.append(make_pdu(data_header, result.data[offset:offset+size]))
            offset += size
            datasn += 1
            if last_sequence:
                sequence_bytes = 0
        self.active = False
        response = self.response_header(0x21, request.itt)
        response[3] = result.status
        put32(response, 36, datasn)
        residual = abs(expected - actual) if direction == 'in' else expected - transferred_out
        if residual:
            response[1] |= 4 if direction == 'in' and actual > expected else 2
            put32(response, 44, residual)
        payload = struct.pack('>H', len(result.sense)) + result.sense if result.sense else b''
        responses.append(make_pdu(response, payload))
        self.emit('scsi_result', itt=request.itt, status=result.status, transferred=sent + transferred_out,
                  residual=residual, sense=result.sense.hex(), seconds=time.monotonic()-started)
        return responses

    def handle(self, request):
        if self.closed:
            raise ProtocolError('Session is closed')
        if request.ahs:
            self.close()
            return self.reject(request, 5)
        if not self.full_feature:
            if request.opcode != 3:
                self.close()
                raise ProtocolError('Only login is allowed before full feature phase')
            return self.login(request)
        if request.opcode == 3:
            self.close()
            return self.reject(request)
        ack_delta = (u32(request.header, 28) - self.statsn) & MASK
        if 0 < ack_delta < 0x80000000:
            self.close()
            return self.reject(request)  # Cannot acknowledge a status not yet sent.
        op = request.opcode
        if self.pending_auth is not None and time.monotonic() - self.pending_auth.started > AUTH_DATA_TIMEOUT:
            self.emit('auth_data_timeout', itt=self.pending_auth.request.itt)
            self.close()
            return self.reject(request)
        if op not in (0, 1, 2, 4, 5, 6):
            # SNACK does not carry CmdSN at offset 24.
            self.close()
            return self.reject(request, 5)
        if op == 0 and request.itt == MASK and not request.header[0] & 0x40:
            self.close()
            return self.reject(request)
        if self.session_type == 'Discovery' and op not in (0, 4, 6):
            return self.reject(request)
        if op == 5:
            return self.auth_data(request)
        if op == 1 and (request.itt == MASK or request.header[1] & 0x60 == 0x60 or
                        not request.header[1] & 0x80 or request.data):
            return self.reject(request)
        if op == 1 and self.pending_auth is not None and request.header[0] & 0x40:
            return self.reject(request)  # Immediate commands cannot overwrite the pending task.
        text_reply = b''
        if op == 4:
            if request.header[1] != 0x80 or u32(request.header, 20) != MASK:
                return self.reject(request, 5)
            try:
                values = parse_text(request.data)
            except ProtocolError:
                return self.reject(request)
            if 'SendTargets' in values and (len(values) != 1 or
                    (values['SendTargets'] == 'All' and self.session_type != 'Discovery')):
                return self.reject(request)
            reply = {}
            for key, value in values.items():
                if key == 'SendTargets':
                    if value == self.target_iqn or (value == 'All' and self.session_type == 'Discovery') or (
                            value == '' and self.session_type == 'Normal'):
                        reply['TargetName'] = self.target_iqn
                        reply['TargetAddress'] = f'{LOOPBACK}:{self.port},1'
                else:
                    reply[key] = 'NotUnderstood'
            text_reply = encode_text(reply)
            if len(text_reply) > self.peer_max_recv:
                return self.reject(request, 5)
        # Rejected commands do not consume CmdSN (RFC 7143 section 7.3).
        if not self.command_sequence(request):
            return []
        if op == 0:
            if request.itt == MASK:
                return []
            response = self.response_header(0x20, request.itt)
            response[8:16] = request.header[8:16]
            put32(response, 20, MASK)
            return [make_pdu(response, request.data[:self.peer_max_recv])]
        if op == 4:
            response = self.response_header(0x24, request.itt)
            put32(response, 20, MASK)
            return [make_pdu(response, text_reply)]
        if op == 6:
            response = self.response_header(0x26, request.itt)
            reason = request.header[1] & 0x7f
            cid = request.header[20:22]
            if reason == 2:
                response[2] = 2  # Recovery unsupported at ERL=0.
            elif reason == 1 and cid != self.login_identity[2]:
                response[2] = 1
            elif reason not in (0, 1):
                response[2] = 3
            else:
                self.close()
            return [make_pdu(response)]
        if op == 2:
            function = request.header[1] & 0x7f
            if request.header[8:16] != bytes(8):
                code = 2
            elif function == 1:
                pending = self.pending_auth
                matches = (pending is not None and u32(request.header, 20) == pending.request.itt and
                           (pending.request.header[0] & 0x40 or
                            u32(request.header, 32) == u32(pending.request.header, 24)))
                code = 0 if matches else 1
                if matches:
                    self.cancel_auth()
            elif function == 5 and callable(getattr(self.backend, 'reset', None)):
                self.cancel_auth()
                self.backend.reset()  # Virtual LU state only; backend must not reset hardware.
                code = 0
            else:
                code = 5
            response = self.response_header(0x22, request.itt)
            response[2] = code
            self.emit('task_management', function=function, response=response[2])
            return [make_pdu(response)]
        if op == 1:
            return self.scsi(request)
        # Never accept unrecognized PDUs.
        self.close()
        return self.reject(request, 5)


class TargetServer:
    """Explicitly started TCP service; its bind address cannot be configured."""
    def __init__(self, backend, *, port=PORT, target_iqn=TARGET_IQN, emit=log_json):
        if not 1024 <= port <= 65535:
            raise ValueError('A high loopback port is required')
        self.backend, self.port, self.target_iqn, self.emit = backend, port, target_iqn, emit
        self.stop_event = threading.Event()
        self.normal_lock = threading.Lock()
        self.clients_lock = threading.Lock()
        self.clients = set()
        self.threads = []

    def stop(self):
        self.stop_event.set()
        with self.clients_lock:
            for conn in tuple(self.clients):
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def join_clients(self, timeout=30):
        """Wait for backend calls to finish; never close a live backend early.

        Return False if a bounded callback has not yet returned. A launcher
        must wait again before restoring/closing its hardware backend.
        """
        deadline = time.monotonic() + max(0, timeout)
        for thread in tuple(self.threads):
            if thread is not threading.current_thread():
                thread.join(timeout=max(0, deadline - time.monotonic()))
        return not any(thread.is_alive() for thread in self.threads)

    def serve_connection(self, conn, peer):
        session = Session(self.backend, target_iqn=self.target_iqn, port=self.port,
                          emit=self.emit, claim_normal=lambda: self.normal_lock.acquire(False),
                          release_normal=self.normal_lock.release)
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.settimeout(120)
            while not self.stop_event.is_set() and not session.closed:
                request = recv_pdu(conn)
                responses = session.handle(request)
                wire_size = sum(48 + len(p.ahs) + len(p.data) + ((-len(p.data)) & 3)
                                for p in responses)
                if wire_size > MAX_RESPONSE_BATCH:
                    raise ProtocolError('Response batch exceeds the bounded transfer envelope')
                if responses:
                    # Keep Data-In and its final status adjacent in the TCP
                    # stream; a separate small SCSI status write must
                    # not wait for an ACK of the preceding data write.
                    conn.sendall(b''.join(p.encode() for p in responses))
        except (EOFError, OSError, ProtocolError) as exc:
            self.emit('connection_closed', peer=peer[0], reason=str(exc))
        except Exception as exc:
            self.emit('connection_error', peer=peer[0], error=type(exc).__name__, reason=str(exc))
        finally:
            session.close()
            conn.close()
            with self.clients_lock:
                self.clients.discard(conn)

    def serve_forever(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind((LOOPBACK, self.port))
            listener.listen(4)
            listener.settimeout(1)
            self.emit('listening', address=LOOPBACK, port=self.port, target=self.target_iqn)
            try:
                while not self.stop_event.is_set():
                    try:
                        conn, peer = listener.accept()
                    except socket.timeout:
                        continue
                    with self.clients_lock:
                        if peer[0] != LOOPBACK or len(self.clients) >= 4:
                            conn.close()
                            continue
                        self.clients.add(conn)
                    thread = threading.Thread(target=self.serve_connection, args=(conn, peer), daemon=True)
                    self.threads = [item for item in self.threads if item.is_alive()]
                    self.threads.append(thread)
                    thread.start()
            finally:
                self.stop()
                if not self.join_clients():
                    self.emit('backend_still_active', message='Wait for join_clients() before closing the backend')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serve-no-media', action='store_true',
                        help='Explicitly start a loopback optical target with no inserted media')
    parser.add_argument('--port', type=int, default=PORT)
    args = parser.parse_args()
    if not args.serve_no_media:
        parser.error('No service starts without --serve-no-media; a hardware launcher must supply its backend explicitly')
    from optical_lun import OpticalLun
    target = TargetServer(OpticalLun(), port=args.port)
    try:
        target.serve_forever()
    except KeyboardInterrupt:
        target.stop()


if __name__ == '__main__':
    main()
