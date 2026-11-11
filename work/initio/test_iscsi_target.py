"""Offline wire-level tests. No listeners, services, disks or hardware are used."""
import io
import socket
import unittest
from iscsi_target import (Session, ScsiResult, ProtocolError, PDU, TargetServer,
                          TARGET_IQN, MASK, MAX_TRANSFER, MAX_RECV_SEGMENT, MAX_RESPONSE_BATCH,
                          make_pdu, parse_text, encode_text, recv_pdu, put32, u32)


class Backend:
    def __init__(self, result=ScsiResult()):
        self.result, self.calls, self.resets = result, [], 0

    def execute(self, cdb, expected_length, direction):
        self.calls.append((cdb, expected_length, direction))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    def reset(self):
        self.resets += 1


class AuthBackend(Backend):
    def execute(self, cdb, expected_length, direction, *, data_out=b''):
        self.calls.append((cdb, expected_length, direction, data_out))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def auth_cdb(fmt=1, size=16, op=0xa3, agid=2):
    cdb = bytearray(16)
    cdb[0], cdb[10] = op, (agid << 6) | fmt
    cdb[8:10] = size.to_bytes(2, 'big')
    return bytes(cdb)


def auth_payload(fmt=1):
    return b'\0\x0e\0\0' + bytes(range(1, 11)) + bytes(2) if fmt == 1 else (
        b'\0\x0a\0\0' + bytes(range(1, 6)) + bytes(3))


def data_out(r2t, data, *, offset=0, datasn=0, final=True, expstatsn=0):
    header = bytearray(48)
    header[0], header[1] = 5, 0x80 if final else 0
    header[8:24] = r2t.header[8:24]
    put32(header, 28, expstatsn)
    put32(header, 36, datasn)
    put32(header, 40, offset)
    return make_pdu(header, data)


def request(opcode, *, flags=0x80, itt=9, cmdsn=100, expstatsn=0,
            data=b'', expected=0, cdb=b'', lun=0, immediate=False, ttt=None):
    header = bytearray(48)
    header[0], header[1] = opcode | (0x40 if immediate else 0), flags
    header[8:16] = lun.to_bytes(8, 'big')
    put32(header, 16, itt)
    put32(header, 20, expected if ttt is None else ttt)
    put32(header, 24, cmdsn)
    put32(header, 28, expstatsn)
    header[32:32+len(cdb)] = cdb
    return make_pdu(header, data)


def login_request(values, *, flags=0x83, cmdsn=100, itt=1, data=None):
    pdu = request(3, flags=flags, itt=itt, cmdsn=cmdsn,
                  immediate=True, data=encode_text(values) if data is None else data)
    header = bytearray(pdu.header)
    header[8:14] = bytes.fromhex('400000000001')
    header[14:16] = b'\0\0'
    header[20:22] = b'\0\0'
    return make_pdu(header, pdu.data)


def establish(backend=None, **kwargs):
    s = Session(backend or Backend(), emit=lambda *a, **k: None, **kwargs)
    s.handle(login_request({'InitiatorName':'iqn.2026-11.local.test:initiator',
                            'TargetName':TARGET_IQN, 'AuthMethod':'None'}))
    assert s.full_feature
    return s


class FragmentedSocket:
    def __init__(self, data):
        self.stream = io.BytesIO(data)
    def recv(self, count):
        return self.stream.read(min(count, 3))


class RecordedSocket(FragmentedSocket):
    def __init__(self, data):
        super().__init__(data)
        self.operations=[]
        self.sent=[]
        self.closed=False
    def setsockopt(self,*args):self.operations.append(('option',args))
    def settimeout(self,value):self.operations.append(('timeout',value))
    def sendall(self,data):
        self.operations.append(('send',len(data)))
        self.sent.append(bytes(data))
    def close(self):self.closed=True


class ProtocolTests(unittest.TestCase):
    def test_security_and_operational_login(self):
        s = Session(Backend(), emit=lambda *a, **k: None)
        first = s.handle(login_request({'InitiatorName':'iqn.test',
                                        'TargetName':TARGET_IQN,
                                        'AuthMethod':'CHAP,None'},flags=0x81))[0]
        self.assertEqual(first.header[1], 0x81)
        self.assertEqual(u32(first.header,24), 0)
        self.assertEqual(first.header[14:16], b'\0\0')
        self.assertEqual(parse_text(first.data)['AuthMethod'],'None')
        second = s.handle(login_request({'HeaderDigest':'CRC32C,None',
                                         'DataDigest':'None',
                                         'MaxRecvDataSegmentLength':'4096',
                                         'MaxBurstLength':'8192',
                                         'InitialR2T':'No', 'ImmediateData':'Yes',
                                         'ErrorRecoveryLevel':'2'},flags=0x87))[0]
        self.assertTrue(s.full_feature)
        self.assertEqual(second.header[1], 0x87)
        self.assertEqual(u32(second.header,24), 1)
        self.assertNotEqual(second.header[14:16], b'\0\0')
        keys = parse_text(second.data)
        self.assertEqual(keys['InitialR2T'],'Yes')
        self.assertEqual(keys['ImmediateData'],'No')
        self.assertEqual(keys['ErrorRecoveryLevel'],'0')
        self.assertEqual(s.peer_max_recv,4096)
        self.assertEqual(s.max_burst,8192)
        self.assertEqual(s.exp_cmdsn,100)

    def test_login_continued_text(self):
        s = Session(Backend(),emit=lambda *a,**k:None)
        first=s.handle(login_request({},flags=0x40,data=b'InitiatorName=iqn.'))[0]
        self.assertFalse(s.full_feature)
        self.assertEqual(first.data,b'')
        text=b'test\0TargetName='+TARGET_IQN.encode()+b'\0AuthMethod=None\0'
        second=s.handle(login_request({},data=text))[0]
        self.assertTrue(s.full_feature)
        self.assertEqual(second.header[36:38],b'\0\0')

    def test_burst_negotiation_does_not_depend_on_key_order(self):
        s=Session(Backend(),emit=lambda *a,**k:None)
        reply=s.negotiate({'FirstBurstLength':'65536','MaxBurstLength':'4096'})
        self.assertEqual(reply['FirstBurstLength'],'4096')
        self.assertEqual(reply['MaxBurstLength'],'4096')

    def test_obsolete_marker_intervals_are_rejected(self):
        s=Session(Backend(),emit=lambda *a,**k:None)
        reply=s.negotiate({'IFMarkInt':'2048','OFMarkInt':'2048'})
        self.assertEqual(reply['IFMarkInt'],'Reject')
        self.assertEqual(reply['OFMarkInt'],'Reject')

    def test_send_targets_empty_normal_and_all_discovery_only(self):
        s=establish()
        out=s.handle(request(4,ttt=MASK,data=b'SendTargets=All\0'))[0]
        self.assertEqual(out.opcode,0x3f)
        self.assertEqual(s.exp_cmdsn,100)
        out=s.handle(request(4,ttt=MASK,data=b'SendTargets=\0'))[0]
        self.assertEqual(parse_text(out.data)['TargetName'],TARGET_IQN)
        self.assertEqual(s.exp_cmdsn,101)

    def test_malformed_scsi_and_text_do_not_consume_cmdsn(self):
        for pdu in (request(1,itt=MASK),request(1,flags=0xe0),
                    request(4,ttt=0,data=b'SendTargets=All\0'),
                    request(4,ttt=MASK,data=b'broken')):
            s=establish()
            self.assertEqual(s.handle(pdu)[0].opcode,0x3f)
            self.assertEqual(s.exp_cmdsn,100)

    def test_wrong_target_and_digest_rejected(self):
        for values in ({'InitiatorName':'iqn.test','TargetName':'iqn.wrong'},
                       {'InitiatorName':'iqn.test','TargetName':TARGET_IQN,'HeaderDigest':'CRC32C'}):
            s=Session(Backend(),emit=lambda *a,**k:None)
            out=s.handle(login_request(values))[0]
            self.assertEqual(out.header[36],2)
            self.assertTrue(s.closed)

    def test_discovery_and_nop_logout_sequence(self):
        s=Session(Backend(),emit=lambda *a,**k:None)
        s.handle(login_request({'InitiatorName':'iqn.test','SessionType':'Discovery'}))
        out=s.handle(request(4,ttt=MASK,data=b'SendTargets=All\0'))[0]
        keys=parse_text(out.data)
        self.assertEqual(keys['TargetName'],TARGET_IQN)
        self.assertEqual(keys['TargetAddress'],'127.0.0.1:32610,1')
        self.assertEqual(u32(out.header,24),1)
        self.assertEqual(u32(out.header,28),101)
        nop=s.handle(request(0,cmdsn=101,ttt=MASK,data=b'ping',immediate=True))[0]
        self.assertEqual(nop.opcode,0x20)
        self.assertEqual(nop.data,b'ping')
        self.assertEqual(s.exp_cmdsn,101)
        self.assertEqual(s.handle(request(0,itt=MASK,ttt=MASK,immediate=True)),[])
        logout=s.handle(request(6,flags=0x80,cmdsn=101))[0]
        self.assertEqual(logout.opcode,0x26)
        self.assertEqual(logout.header[2],0)
        self.assertTrue(s.closed)

    def test_segmented_data_has_offsets_bursts_and_one_status(self):
        data=bytes(range(250))*10
        backend=Backend(ScsiResult(data=data))
        s=establish(backend)
        s.peer_max_recv=512
        s.max_burst=1024
        result=s.handle(request(1,flags=0xc0,expected=len(data),cdb=bytes([0x28])+bytes(15)))
        chunks=result[:-1]
        self.assertEqual([len(p.data) for p in chunks],[512,512,512,512,452])
        self.assertEqual([p.header[1] for p in chunks],[0,0x80,0,0x80,0x80])
        self.assertEqual([u32(p.header,36) for p in chunks],list(range(5)))
        self.assertEqual([u32(p.header,40) for p in chunks],[0,512,1024,1536,2048])
        self.assertTrue(all(u32(p.header,24)==0 for p in chunks))
        self.assertEqual(b''.join(p.data for p in chunks),data)
        status=result[-1]
        self.assertEqual(status.opcode,0x21)
        self.assertEqual(status.header[3],0)
        self.assertEqual(u32(status.header,36),5)
        self.assertEqual(u32(status.header,24),1)
        self.assertEqual(u32(status.header,28),101)
        self.assertEqual(u32(status.header,32),101)
        self.assertEqual(len(backend.calls),1)

    def test_underflow_and_overflow(self):
        for actual,expected,flags,residual in ((8,36,0x82,28),(12,8,0x84,4)):
            s=establish(Backend(ScsiResult(data=b'x'*actual)))
            out=s.handle(request(1,flags=0xc0,expected=expected,cdb=b'\x12'+bytes(15)))
            self.assertEqual(sum(len(p.data) for p in out[:-1]),min(actual,expected))
            self.assertEqual(out[-1].header[1],flags)
            self.assertEqual(u32(out[-1].header,44),residual)

    def test_check_condition_autosense(self):
        sense=bytes.fromhex('700002000000000a000000003a0000000000')
        s=establish(Backend((2,b'',sense)))
        out=s.handle(request(1,cdb=bytes(16)))[0]
        self.assertEqual(out.header[3],2)
        self.assertEqual(out.data,b'\0\x12'+sense)

    def test_write_eject_large_and_unknown_cdb_never_reach_backend(self):
        cases=[(0xa0,512,b'\x2a'+bytes(15)),
               (0x80,0,bytes.fromhex('1b0000000200')+bytes(10)),
               (0xc0,MAX_TRANSFER+1,b'\x28'+bytes(15)),
               (0x80,0,b'\xff'+bytes(15))]
        for flags,size,cdb in cases:
            backend=Backend()
            s=establish(backend)
            out=s.handle(request(1,flags=flags,expected=size,cdb=cdb))[-1]
            self.assertEqual(out.header[3],2)
            self.assertEqual(backend.calls,[])

    def test_nonzero_lun_never_reaches_backend(self):
        backend=Backend()
        s=establish(backend)
        out=s.handle(request(1,lun=1,cdb=bytes(16)))[0]
        self.assertEqual(out.header[3],2)
        self.assertEqual(out.data[14],0x25)
        self.assertEqual(backend.calls,[])

    def test_duplicate_and_future_cmdsn_not_executed(self):
        backend=Backend()
        s=establish(backend)
        p=request(1,cdb=bytes(16))
        self.assertEqual(s.handle(p)[0].header[3],0)
        self.assertEqual(s.handle(p),[])
        self.assertEqual(s.handle(request(1,cmdsn=500,cdb=bytes(16))),[])
        self.assertEqual(len(backend.calls),1)

    def test_cmdsn_wraparound(self):
        s=Session(Backend(),emit=lambda *a,**k:None)
        s.handle(login_request({'InitiatorName':'iqn.test','TargetName':TARGET_IQN},cmdsn=MASK))
        out=s.handle(request(1,cmdsn=MASK,cdb=bytes(16)))[0]
        self.assertEqual(u32(out.header,28),0)
        self.assertEqual(s.handle(request(1,cmdsn=0,cdb=bytes(16)))[0].header[3],0)

    def test_future_status_ack_rejected(self):
        s=establish()
        out=s.handle(request(1,cdb=bytes(16),expstatsn=10))[0]
        self.assertEqual(out.opcode,0x3f)
        self.assertTrue(s.closed)

    def test_task_management_is_virtual_only(self):
        backend=Backend()
        s=establish(backend)
        out=s.handle(request(2,flags=0x85,immediate=True))[0]
        self.assertEqual(out.opcode,0x22)
        self.assertEqual(out.header[2],0)
        self.assertEqual(backend.resets,1)
        out=s.handle(request(2,flags=0x86,immediate=True))[0]
        self.assertEqual(out.header[2],5)

    def test_backend_exception_becomes_hardware_error_sense(self):
        s=establish(Backend(RuntimeError('bounded backend failure')))
        out=s.handle(request(1,cdb=bytes(16)))[0]
        self.assertEqual(out.header[3],2)
        self.assertEqual(out.data[4],4)
        self.assertEqual(out.data[14],0x44)

    def test_single_normal_session_claim_and_release(self):
        calls=[]
        s=establish(claim_normal=lambda: calls.append('claim') or True,
                    release_normal=lambda:calls.append('release'))
        s.close();s.close()
        self.assertEqual(calls,['claim','release'])
        busy=Session(Backend(),emit=lambda *a,**k:None,claim_normal=lambda:False)
        out=busy.handle(login_request({'InitiatorName':'iqn.test','TargetName':TARGET_IQN}))[0]
        self.assertEqual(out.header[36:38],b'\x02\x06')

    def test_wire_fragmentation_padding_and_bounds(self):
        p=request(0,data=b'abc',ttt=MASK)
        parsed=recv_pdu(FragmentedSocket(p.encode()))
        self.assertEqual(parsed,p)
        corrupt=p.encode()[:-1]+b'x'
        with self.assertRaises(ProtocolError):recv_pdu(FragmentedSocket(corrupt))
        header=bytearray(48);header[5:8]=(MAX_RECV_SEGMENT+1).to_bytes(3,'big')
        with self.assertRaises(ProtocolError):recv_pdu(FragmentedSocket(bytes(header)))
        with self.assertRaises(EOFError):recv_pdu(FragmentedSocket(b'partial'))

    def test_unrequested_data_out_rejected_and_connection_closed(self):
        s=establish()
        out=s.handle(request(5,cmdsn=0,data=b'blocked'))[0]
        self.assertEqual(out.opcode,0x3f)
        self.assertTrue(s.closed)

    def test_reserved_nop_tag_requires_immediate(self):
        s=establish()
        out=s.handle(request(0,itt=MASK,ttt=MASK))[0]
        self.assertEqual(out.opcode,0x3f)
        self.assertTrue(s.closed)
        self.assertEqual(s.exp_cmdsn,100)

    def test_optical_frontend_inquiry_and_exact_fake_read(self):
        from optical_lun import OpticalLun
        calls=[]
        data=bytes(range(256))*8
        def read_blocks(lba,count):
            calls.append((lba,count))
            return data*count
        s=establish(OpticalLun(read_blocks=read_blocks,block_count=100))
        inquiry=s.handle(request(1,flags=0xc0,expected=36,cdb=bytes.fromhex('120000002400')+bytes(10)))
        self.assertEqual(inquiry[0].data[0]&31,5)
        self.assertEqual(inquiry[-1].header[3],0)
        cdb=bytearray(16);cdb[0]=0x28;put32(cdb,2,16);cdb[8]=1
        response=s.handle(request(1,flags=0xc0,cmdsn=101,expected=2048,cdb=cdb))
        self.assertEqual(response[-1].header[3],0)
        self.assertEqual(b''.join(p.data for p in response[:-1]),data)
        self.assertEqual(calls,[(16,1)])

    def test_server_constructor_does_not_create_listener(self):
        from unittest.mock import patch
        with patch('iscsi_target.socket.socket',side_effect=AssertionError('No sockets in tests')):
            server=TargetServer(Backend())
            server.stop()
            self.assertTrue(server.join_clients(0))
        self.assertEqual(server.port,32610)

    def test_full_256k_read_is_one_bounded_ordered_socket_batch(self):
        from unittest.mock import patch
        self.assertEqual(MAX_TRANSFER,256*1024)
        data=bytes(range(256))*(MAX_TRANSFER//256)
        backend=Backend(ScsiResult(data=data))
        login=login_request({'InitiatorName':'iqn.test','TargetName':TARGET_IQN,
                             'MaxRecvDataSegmentLength':'512','MaxBurstLength':'513'})
        read=request(1,flags=0xc0,expected=MAX_TRANSFER,cdb=b'\x28'+bytes(15))
        no_reply=request(0,itt=MASK,ttt=MASK,immediate=True)
        conn=RecordedSocket(login.encode()+read.encode()+no_reply.encode())
        server=TargetServer(backend,emit=lambda *a,**k:None)
        with patch('iscsi_target.socket.socket',side_effect=AssertionError('No real sockets')):
            server.serve_connection(conn,('127.0.0.1',12345))
        self.assertEqual(conn.operations[0],('option',(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)))
        self.assertEqual(len(conn.sent),2)  # Login, then all Data-In plus status.
        self.assertTrue(conn.closed)
        wire=conn.sent[1]
        self.assertLessEqual(len(wire),MAX_RESPONSE_BATCH)
        stream=FragmentedSocket(wire);pdus=[]
        while True:
            try:pdus.append(recv_pdu(stream))
            except EOFError:break
        self.assertEqual(pdus[-1].opcode,0x21)
        self.assertEqual(pdus[-1].header[3],0)
        self.assertEqual(b''.join(p.data for p in pdus[:-1]),data)
        burst=offset=0
        for datasn,p in enumerate(pdus[:-1]):
            self.assertEqual(p.opcode,0x25)
            self.assertLessEqual(len(p.data),512)
            self.assertEqual(u32(p.header,36),datasn)
            self.assertEqual(u32(p.header,40),offset)
            offset+=len(p.data);burst+=len(p.data)
            self.assertLessEqual(burst,513)
            if p.header[1]&0x80:burst=0
        self.assertEqual(offset,256*1024)
        self.assertEqual(burst,0)
        self.assertEqual(u32(pdus[-1].header,36),len(pdus)-1)

    def test_above_256k_is_rejected_without_backend_call(self):
        backend=Backend(ScsiResult(data=b'unused'))
        s=establish(backend)
        response=s.handle(request(1,flags=0xc0,expected=256*1024+1,cdb=b'\x28'+bytes(15)))
        self.assertEqual(backend.calls,[])
        self.assertEqual(len(response),1)
        self.assertEqual(response[0].header[3],2)
        self.assertEqual(response[0].data[14],0x24)

    def test_oversized_response_batch_sends_no_partial_status(self):
        from unittest.mock import patch
        class OversizedSession:
            closed=False
            def __init__(self,*a,**k):pass
            def handle(self,request):
                return [make_pdu(bytes(48)),make_pdu(bytes(48),bytes(MAX_RESPONSE_BATCH))]
            def close(self):self.closed=True
        conn=RecordedSocket(request(0,ttt=MASK).encode())
        events=[]
        server=TargetServer(Backend(),emit=lambda event,**kw:events.append((event,kw)))
        with patch('iscsi_target.Session',OversizedSession), \
             patch('iscsi_target.socket.socket',side_effect=AssertionError('No real sockets')):
            server.serve_connection(conn,('127.0.0.1',12345))
        self.assertEqual(conn.sent,[])
        self.assertTrue(conn.closed)
        self.assertTrue(any('bounded transfer envelope' in e[1].get('reason','') for e in events))


class AuthenticationTests(unittest.TestCase):
    def begin(self, backend=None, fmt=1):
        backend = backend or AuthBackend()
        session = establish(backend)
        size = 16 if fmt == 1 else 12
        command = request(1, flags=0xa0, expected=size, cdb=auth_cdb(fmt, size))
        r2t = session.handle(command)[0]
        self.assertEqual(r2t.opcode, 0x31)
        self.assertEqual(backend.calls, [])
        return session, backend, r2t

    def test_r2t_segmented_challenge_sequences_and_exact_backend_payload(self):
        s, backend, r2t = self.begin()
        self.assertEqual(r2t.data, b'')
        self.assertEqual(r2t.header[8:16], bytes(8))
        self.assertEqual(r2t.itt, 9)
        self.assertNotEqual(u32(r2t.header, 20), MASK)
        self.assertEqual([u32(r2t.header, n) for n in (24, 28, 32, 36, 40, 44)],
                         [1, 101, 100, 0, 0, 16])
        self.assertEqual(s.statsn, 1)
        payload = auth_payload()
        self.assertEqual(s.handle(data_out(r2t, payload[:5], final=False)), [])
        self.assertEqual(s.handle(data_out(r2t, b'', offset=5, datasn=1, final=False)), [])
        self.assertEqual(backend.calls, [])
        result = s.handle(data_out(r2t, payload[5:], offset=5, datasn=2, expstatsn=1))
        self.assertEqual(len(result), 1)
        status = result[0]
        self.assertEqual((status.opcode, status.header[1], status.header[3]), (0x21, 0x80, 0))
        self.assertEqual([u32(status.header, n) for n in (24, 28, 32, 36, 44)], [1, 101, 101, 0, 0])
        self.assertEqual(backend.calls, [(auth_cdb(), 16, 'out', payload)])
        self.assertIsNone(s.pending_auth)
        self.assertFalse(s.active)

    def test_key2_and_empty_final_segment_are_accepted(self):
        s, backend, r2t = self.begin(fmt=3)
        payload = auth_payload(3)
        self.assertEqual(s.handle(data_out(r2t, payload, final=False)), [])
        status = s.handle(data_out(r2t, b'', offset=12, datasn=1))[0]
        self.assertEqual(status.header[3], 0)
        self.assertEqual(backend.calls, [(auth_cdb(3, 12), 12, 'out', payload)])

    def test_closed_command_window_and_immediate_nop_keep_pending_task(self):
        s, backend, r2t = self.begin()
        self.assertEqual(s.handle(request(1, cmdsn=101, cdb=bytes(16))), [])
        rejected = s.handle(request(1, cmdsn=101, cdb=bytes(16), immediate=True))[0]
        self.assertEqual(rejected.opcode, 0x3f)
        self.assertIsNotNone(s.pending_auth)
        nop = s.handle(request(0, immediate=True, cmdsn=101, itt=10, ttt=MASK))[0]
        self.assertEqual(nop.opcode, 0x20)
        self.assertEqual(u32(nop.header, 32), 100)
        self.assertEqual(s.exp_cmdsn, 101)
        status = s.handle(data_out(r2t, auth_payload()))[0]
        self.assertEqual(status.header[3], 0)
        self.assertEqual(len(backend.calls), 1)

    def test_invalid_send_formats_lengths_cdb_fields_and_directions_never_request_data(self):
        invalid = [auth_cdb(fmt, 16) for fmt in (0, 2, 6, 0x3f)]
        invalid += [auth_cdb(1, 12), auth_cdb(3, 16)]
        for offset in (1, 2, 6, 7, 11, 12, 15):
            bad = bytearray(auth_cdb()); bad[offset] = 1
            invalid.append(bytes(bad))
        cases = [(cdb, 16, 0xa0, 0) for cdb in invalid]
        cases += [(auth_cdb(), 12, 0xa0, 0), (auth_cdb(), 16, 0xc0, 0),
                  (auth_cdb(), 0, 0x80, 0), (auth_cdb(), 16, 0xa0, 1)]
        for cdb, length, flags, lun in cases:
            with self.subTest(cdb=cdb.hex(), length=length, flags=flags, lun=lun):
                backend = AuthBackend(); s = establish(backend)
                status = s.handle(request(1, flags=flags, expected=length, cdb=cdb, lun=lun))[0]
                self.assertEqual((status.opcode, status.header[3]), (0x21, 2))
                self.assertEqual(backend.calls, [])
                self.assertIsNone(s.pending_auth)

    def test_immediate_data_and_unsolicited_sequence_flags_are_rejected_before_cmdsn(self):
        for flags, data in ((0xa0, auth_payload()), (0x20, b'')):
            backend = AuthBackend(); s = establish(backend)
            status = s.handle(request(1, flags=flags, expected=16, cdb=auth_cdb(), data=data))[0]
            self.assertEqual(status.opcode, 0x3f)
            self.assertEqual(s.exp_cmdsn, 100)
            self.assertEqual(backend.calls, [])

    def test_data_out_identifiers_reserved_fields_offsets_and_lengths_are_strict(self):
        changes = [(0, 0x45, 1), (1, 0x81, 1), (2, 1, 1), (8, 1, 1),
                   (16, 10, 4), (20, MASK, 4), (24, 1, 4), (32, 1, 4),
                   (36, 1, 4), (40, 1, 4), (44, 1, 4)]
        for offset, value, size in changes:
            with self.subTest(offset=offset):
                s, backend, r2t = self.begin()
                pdu = data_out(r2t, auth_payload())
                header = bytearray(pdu.header)
                header[offset:offset+size] = value.to_bytes(size, 'big')
                status = s.handle(make_pdu(header, pdu.data))[0]
                self.assertEqual(status.opcode, 0x3f)
                self.assertTrue(s.closed)
                self.assertIsNone(s.pending_auth)
                self.assertEqual(backend.calls, [])
        for payload in (auth_payload()[:-1], auth_payload() + b'x'):
            s, backend, r2t = self.begin()
            self.assertEqual(s.handle(data_out(r2t, payload))[0].opcode, 0x3f)
            self.assertTrue(s.closed)
            self.assertEqual(backend.calls, [])

    def test_invalid_parameter_list_is_sense_and_never_reaches_backend(self):
        for offset in (0, 1, 2, 3, 14, 15):
            s, backend, r2t = self.begin()
            payload = bytearray(auth_payload()); payload[offset] ^= 1
            status = s.handle(data_out(r2t, payload))[0]
            self.assertEqual(status.header[3], 2)
            self.assertEqual((status.data[4], status.data[14]), (5, 0x26))
            self.assertEqual(u32(status.header, 44), 0)
            self.assertFalse(s.closed)
            self.assertEqual(backend.calls, [])

    def test_completed_data_out_cannot_be_replayed(self):
        s, backend, r2t = self.begin()
        pdu = data_out(r2t, auth_payload())
        self.assertEqual(s.handle(pdu)[0].header[3], 0)
        self.assertEqual(s.handle(pdu)[0].opcode, 0x3f)
        self.assertTrue(s.closed)
        self.assertEqual(len(backend.calls), 1)

    def test_abort_and_virtual_reset_discard_partial_auth(self):
        for function in (1, 5):
            s, backend, r2t = self.begin()
            self.assertEqual(s.handle(data_out(r2t, auth_payload()[:4], final=False)), [])
            tmf = request(2, flags=0x80 | function, itt=10, cmdsn=101, immediate=True, ttt=9)
            header = bytearray(tmf.header); put32(header, 32, 100)
            status = s.handle(make_pdu(header))[0]
            self.assertEqual((status.opcode, status.header[2]), (0x22, 0))
            self.assertEqual(u32(status.header, 32), 101)
            self.assertIsNone(s.pending_auth)
            self.assertFalse(s.active)
            self.assertEqual(backend.calls, [])
            self.assertEqual(backend.resets, int(function == 5))

    def test_wrong_abort_reference_does_not_cancel_auth(self):
        s, backend, r2t = self.begin()
        tmf = request(2, flags=0x81, itt=10, cmdsn=101, immediate=True, ttt=9)
        status = s.handle(tmf)[0]  # Wrong RefCmdSN (zero, rather than 100).
        self.assertEqual(status.header[2], 1)
        self.assertIsNotNone(s.pending_auth)
        self.assertEqual(s.handle(data_out(r2t, auth_payload()))[0].header[3], 0)

    def test_logout_close_and_timeout_discard_auth_without_execution(self):
        from unittest.mock import patch
        for how in ('logout', 'close', 'timeout'):
            s, backend, r2t = self.begin()
            s.handle(data_out(r2t, b'\0', final=False))
            if how == 'logout':
                status = s.handle(request(6, itt=10, immediate=True, cmdsn=101))[0]
                self.assertEqual(status.opcode, 0x26)
            elif how == 'close':
                s.close()
            else:
                with patch('iscsi_target.time.monotonic', return_value=s.pending_auth.started + 31):
                    self.assertEqual(s.handle(data_out(r2t, auth_payload()[1:], offset=1, datasn=1))[0].opcode, 0x3f)
            self.assertTrue(s.closed)
            self.assertIsNone(s.pending_auth)
            self.assertEqual(backend.calls, [])

    def test_backend_sense_and_failures_do_not_return_data_or_false_success(self):
        from iscsi_target import check_condition
        for result, sense_key in ((check_condition(5, 0x6f, 1), 5),
                                  (RuntimeError('auth unavailable'), 4),
                                  (ScsiResult(data=b'not permitted'), 4)):
            s, backend, r2t = self.begin(AuthBackend(result))
            status = s.handle(data_out(r2t, auth_payload()))[0]
            self.assertEqual(status.header[3], 2)
            self.assertEqual(status.data[4], sense_key)
            self.assertEqual(u32(status.header, 44), 0)
            self.assertEqual(len(backend.calls), 1)

    def test_report_key_and_zero_length_invalidation_keep_three_argument_contract(self):
        for fmt, length, flags in ((0, 8, 0xc0), (0x3f, 0, 0x80)):
            backend = Backend(ScsiResult(data=bytes(length)))
            s = establish(backend)
            cdb = auth_cdb(fmt, length, op=0xa4)
            status = s.handle(request(1, flags=flags, expected=length, cdb=cdb))[-1]
            self.assertEqual(status.header[3], 0)
            self.assertEqual(backend.calls, [(cdb, length, 'in' if length else 'none')])

    def test_report_key_invalid_format_or_outbound_direction_is_blocked(self):
        for fmt, flags, length in ((6, 0xc0, 8), (0x3f, 0xc0, 8), (0, 0xa0, 8)):
            backend = AuthBackend(); s = establish(backend)
            status = s.handle(request(1, flags=flags, expected=length,
                                      cdb=auth_cdb(fmt, length, op=0xa4)))[0]
            self.assertEqual(status.header[3], 2)
            self.assertEqual(backend.calls, [])

    def test_windows_invalidation_has_no_r2t_and_preserves_actual_result(self):
        from iscsi_target import check_condition
        cdb=auth_cdb(0x3f,0,op=0xa3)
        for result in (ScsiResult(),check_condition(5,0x6f,0)):
            backend=Backend(result);s=establish(backend)
            responses=s.handle(request(1,cdb=cdb))
            self.assertEqual([p.opcode for p in responses],[0x21])
            self.assertEqual(responses[0].header[3],result.status)
            self.assertEqual(responses[0].data[2:] if result.sense else responses[0].data,
                             result.sense)
            self.assertEqual(backend.calls,[(cdb,0,'none')])
            self.assertIsNone(s.pending_auth)
            self.assertFalse(s.active)
            self.assertEqual(s.exp_cmdsn,101)

    def test_windows_invalidation_bad_envelope_never_reaches_backend(self):
        cdb=auth_cdb(0x3f,0,op=0xa3)
        malformed=[]
        for offset in (*range(1,10),11,15):
            bad=bytearray(cdb);bad[offset]=1;malformed.append(bytes(bad))
        for flags,size,bad in [(0xc0,0,cdb),(0xa0,0,cdb),(0x80,1,cdb)]+[
                (0x80,0,bad) for bad in malformed]:
            backend=Backend();s=establish(backend)
            responses=s.handle(request(1,flags=flags,expected=size,cdb=bad))
            self.assertEqual([p.opcode for p in responses],[0x21])
            self.assertEqual(responses[0].header[3],2)
            self.assertEqual(backend.calls,[])
            self.assertIsNone(s.pending_auth)

    def test_windows_invalidation_unexpected_backend_data_is_not_good(self):
        backend=Backend(ScsiResult(data=b'bad'));s=establish(backend)
        response=s.handle(request(1,cdb=auth_cdb(0x3f,0,op=0xa3)))[0]
        self.assertEqual((response.header[3],response.data[4],response.data[14]),(2,4,0x44))
        self.assertEqual(len(backend.calls),1)

    def test_real_optical_frontend_passes_only_auth_messages_to_fake_backend(self):
        from optical_lun import OpticalLun
        calls = []
        def auth(cdb, length, direction, *, data_out=b''):
            calls.append((cdb, length, direction, data_out))
            return ScsiResult(data=bytes(length) if direction == 'in' else b'')
        lun = OpticalLun(read_blocks=lambda lba, count: bytes(count * 2048),
                         block_count=100, auth_command=auth)
        s = establish(lun)
        for cmdsn, fmt, length in ((100, 1, 16), (101, 3, 12)):
            cdb = auth_cdb(fmt, length)
            r2t = s.handle(request(1, flags=0xa0, cmdsn=cmdsn, expected=length, cdb=cdb))[0]
            self.assertEqual(r2t.opcode, 0x31)
            status = s.handle(data_out(r2t, auth_payload(fmt)))[0]
            self.assertEqual(status.header[3], 0)
            self.assertEqual(calls[-1], (cdb[:12], length, 'out', auth_payload(fmt)))
        cdb = auth_cdb(0x3f, 0, op=0xa4)
        status = s.handle(request(1, cmdsn=102, cdb=cdb))[0]
        self.assertEqual(status.header[3], 0)
        self.assertEqual(calls[-1], (cdb[:12], 0, 'none', b''))
        cdb = auth_cdb(0x3f, 0, op=0xa3)
        status = s.handle(request(1, cmdsn=103, cdb=cdb))[0]
        self.assertEqual(status.header[3],0)
        self.assertEqual(calls[-1],(cdb[:12],0,'none',b''))
        status = s.handle(request(1, flags=0xa0, cmdsn=104, expected=2048,
                                  cdb=b'\x2a' + bytes(15)))[0]
        self.assertEqual((status.header[3], status.data[4]), (2, 7))
        self.assertEqual(len(calls), 4)


if __name__=='__main__':
    unittest.main()
