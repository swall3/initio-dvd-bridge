"""Offline auth transport replay. No hardware module or Windows API imports."""
import ast
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from dvd_auth_commands import (validate_auth_cdb, REPORT_FORMATS,
                               STRUCTURE_FORMATS, SEND_FORMATS)


SOURCE = Path(__file__).with_name('live_usb_transport.py')
NAMES = {'classify_cdb', 'service_data_out_auth', 'service_data_in', 'service_tur',
         'service_pending', 'check_bound', 'usb_gate', 'settle_csw'}
CODE = compile(ast.Module(body=[n for n in ast.parse(SOURCE.read_text()).body
                              if isinstance(n, ast.FunctionDef) and n.name in NAMES],
                          type_ignores=[]), str(SOURCE), 'exec')


def command(op=0xa3, fmt=1, size=16):
    cdb = bytearray(12)
    cdb[0], cdb[10] = op, fmt
    cdb[8:10] = size.to_bytes(2, 'big')
    return bytes(cdb)


def namespace():
    ns = dict(time=time, disk=SimpleNamespace(result=None),
              MAX_BLOCKS=16, CAPACITY_BLOCKS=10000,
              validate_auth_cdb=validate_auth_cdb,
              AUTH_DATA_IN_KINDS=frozenset(
                  [k for k, _ in REPORT_FORMATS.values()] +
                  [k for k, _ in STRUCTURE_FORMATS.values()] + ['capability_probe']),
              AUTH_DATA_OUT_KINDS=frozenset(k for k, _ in SEND_FORMATS.values()))
    exec(CODE, ns)
    return ns


class OutReplay:
    def __init__(self, *, task=0x50, residual=0, sata=4, usb=4,
                 out_control=0, out_status=0, phy=9, initial_usb=0,
                 sata_after_ack=None, e040=0):
        self.task, self.residual, self.sata, self.usb = task, residual, sata, usb
        self.out_control, self.phy, self.initial_usb = out_control, phy, initial_usb
        self.out_status, self.sata_after_ack = out_status, sata_after_ack
        self.e040 = e040
        self.armed = False
        self.usb_acked = False
        self.writes = []
        self.logs = []
        self.ns = namespace()
        self.ns.update(read=self.read, write=self.write, mem=self.mem,
                       verified_protocol=lambda *a: None,
                       translate_pending=lambda *a: None,
                       log=lambda stage, **kw: self.logs.append((stage, kw)))

    def read(self, handle, address):
        if address == 0xd100:
            return (self.usb & ~0x24 if self.usb_acked else self.usb) if self.armed else self.initial_usb
        if address == 0xd118:
            return self.out_control if self.armed else 0
        if address == 0xe000:
            return self.sata_after_ack if self.usb_acked and self.sata_after_ack is not None else self.sata
        return {0xd114: 0x22, 0xd11a: self.out_status, 0xe08c: self.task,
                0xe040: self.e040,
                0xe08d: 0x50 if self.task & 1 else 0, 0xe014: self.phy,
                0xc04c: 7, 0xe165: 0, 0xd119: 2, 0xc988: 0}[address]

    def write(self, handle, address, value):
        self.writes.append((address, value))
        if (address, value) == (0xc988, 0x63):
            self.armed = True
        if address == 0xd100 and value in (4, 0x24):
            self.usb_acked = True

    def mem(self, handle, address, length):
        if address != 0x1d12c or length != 4:
            raise AssertionError('OUT must use the real D12C residual')
        return self.residual.to_bytes(4, 'little')

    def run(self, kind='send_challenge', size=16):
        self.ns['service_data_out_auth'](
            None, dict(context=7, kind=kind, length=size,
                       cdb=command(fmt=1 if kind == 'send_challenge' else 3, size=size)),
            time.monotonic() + .03, False)


class AuthTransportTests(unittest.TestCase):
    def test_exact_auth_classifier_and_capability_probe(self):
        classify = namespace()['classify_cdb']
        self.assertEqual(classify(command(), 16, 0, True), 'send_challenge')
        self.assertEqual(classify(command(fmt=3, size=12), 12, 0, True), 'send_key2')
        self.assertEqual(classify(command(0xa4, 8, 8), 8, 0x80, True), 'report_rpc')
        self.assertEqual(classify(command(0xa4, 0x3f, 0), 0, 0, True), 'invalidate_agid')
        self.assertEqual(classify(bytes.fromhex('460201060000000010000000'), 16, 0x80, True), 'capability_probe')
        for cdb, size, direction in ((command(fmt=6),16,0), (command(),16,0x80),
                                     (command(),12,0), (command(0x2a),16,0),
                                     (bytes.fromhex('460200000000000010000000'),16,0x80)):
            with self.subTest(cdb=cdb.hex()):
                with self.assertRaises(RuntimeError): classify(cdb,size,direction,True)

    def test_out_success_uses_rom_order_and_actual_zero_residual(self):
        r = OutReplay(); r.run()
        self.assertLess(r.writes.index((0xe024,1)),r.writes.index((0xe08c,0x80)))
        self.assertLess(r.writes.index((0xd130,7)),r.writes.index((0xc988,0x63)))
        self.assertLess(r.writes.index((0xd100,4)),r.writes.index((0xe165,0x40)))
        self.assertLess(r.writes.index((0xd11f,0)),r.writes.index((0xd119,2)))
        self.assertLess(r.writes.index((0xd119,2)),r.writes.index((0xd117,0)))
        self.assertLess(r.writes.index((0xd117,0)),r.writes.index((0xe000,6)))
        self.assertFalse(any(a == 0xd138 for a, _ in r.writes))
        self.assertEqual(r.logs[-1][1]['status'],0)

    def test_out_key2_actual_error_returns_failure_and_residual(self):
        r = OutReplay(task=0x51,residual=12);r.run('send_key2',12)
        self.assertIn((0xcc32,0x51),r.writes);self.assertIn((0xcc33,0x50),r.writes)
        self.assertIn((0xd117,1),r.writes);self.assertNotIn((0xd117,0),r.writes)
        self.assertEqual(r.logs[-1][1]['residual'],12)
        self.assertIn((0xd11c,12),r.writes)

    def test_out_bit5_ack_precedes_later_sata_completion(self):
        r=OutReplay(usb=0x20,sata=0,sata_after_ack=4);r.run()
        self.assertIn((0xd100,0x24),r.writes)
        self.assertNotIn((0xd100,4),r.writes)
        self.assertLess(r.writes.index((0xd100,0x24)),r.writes.index((0xe165,0x40)))
        self.assertIn((0xd117,0),r.writes)
        self.assertEqual(r.logs[-1][1]['completion'],'bit5')
        acknowledgement=next(fields for stage,fields in r.logs if stage=='auth_out_bit5_completed')
        self.assertEqual(acknowledgement['sata_event'],0)
        self.assertEqual(acknowledgement['residual'],0)

    def test_out_bit5_ack_never_substitutes_for_sata_completion(self):
        r=OutReplay(usb=0x20,sata=0)
        with self.assertRaises(RuntimeError):r.run()
        self.assertIn((0xd100,0x24),r.writes)
        self.assertNotIn((0xe165,0x40),r.writes)
        self.assertFalse(any(a==0xd117 for a,_ in r.writes))

    def test_out_bit5_active_or_error_status_is_not_acknowledged(self):
        for changes in ({'out_control':1},{'out_status':1},{'usb':0x30}):
            with self.subTest(changes=changes):
                r=OutReplay(**({'usb':0x20}|changes))
                with self.assertRaises(RuntimeError):r.run()
                self.assertNotIn((0xd100,0x24),r.writes)
                self.assertFalse(any(a==0xd117 for a,_ in r.writes))
                sample=next(fields for stage,fields in r.logs if stage=='auth_out_sample')
                self.assertEqual(sample['out_status'],r.out_status)
                self.assertEqual(sample['out_control'],r.out_control)

    def test_out_bit5_preserves_failed_residual_and_rejects_false_success(self):
        r=OutReplay(usb=0x24,task=0x51,residual=12);r.run('send_key2',12)
        self.assertIn((0xd11c,12),r.writes)
        self.assertIn((0xcc32,0x51),r.writes)
        self.assertIn((0xd117,1),r.writes)
        for residual in (1,17):
            r=OutReplay(usb=0x20,residual=residual)
            with self.assertRaises(RuntimeError):r.run()
            self.assertFalse(any(a==0xd117 for a,_ in r.writes))

    def test_out_nonzero_e040_never_returns_good_csw(self):
        for usb in (4,0x20):
            for e040 in (1,2,0x80):
                with self.subTest(usb=usb,e040=e040):
                    r=OutReplay(usb=usb,e040=e040)
                    with self.assertRaisesRegex(RuntimeError,'E040 is nonzero'):r.run()
                    self.assertFalse(any(a==0xd117 for a,_ in r.writes))
                    sample=next(fields for stage,fields in r.logs if stage=='auth_out_sample')
                    self.assertEqual(sample['sata_status_e040'],e040)

    def test_out_missing_or_busy_completion_never_sends_csw(self):
        for changes in ({'sata':0},{'usb':0},{'out_control':1},
                        {'task':0x80},{'task':0x58}):
            with self.subTest(changes=changes):
                r=OutReplay(**changes)
                with self.assertRaises(RuntimeError):r.run()
                self.assertFalse(any(a==0xd117 for a,_ in r.writes))

    def test_out_faults_and_invalid_residual_remain_fatal(self):
        for changes in ({'sata':0x14},{'usb':0x24,'out_status':1},{'usb':0x14},{'phy':0},
                        {'residual':17},{'residual':1},{'initial_usb':4},{'initial_usb':0x20}):
            with self.subTest(changes=changes):
                r=OutReplay(**changes)
                with self.assertRaises(RuntimeError):r.run()
                self.assertFalse(any(a==0xd117 for a,_ in r.writes))

    def test_invalidation_dispatches_real_nodata_not_synthetic_status(self):
        ns=namespace();calls=[]
        ns.update(check_bound=lambda *a:None,usb_gate=lambda *a:None,
                  read=lambda h,a:7,write=lambda *a:None,
                  service_tur=lambda *a:calls.append('physical'),
                  service_bridge_nodata=lambda *a:calls.append('synthetic'))
        item=dict(context=7,kind='invalidate_agid',cdb=command(0xa4,0x3f,0),
                  length=0,key=(7,b'tag',b'invalidate'))
        ns['service_pending'](None,item,time.monotonic()+1,False,set())
        self.assertEqual(calls,['physical'])

    def test_send_key_invalidation_classifies_and_preserves_physical_cdb(self):
        ns=namespace();cdb=command(0xa3,0x3f,0)
        self.assertEqual(ns['classify_cdb'](cdb,0,0,True),'invalidate_agid')
        for bad,size,direction in ((cdb,0,0x80),(command(0xa3,0x3f,16),16,0)):
            with self.assertRaises(RuntimeError):ns['classify_cdb'](bad,size,direction,True)
        calls=[]
        ns.update(check_bound=lambda *a:None,usb_gate=lambda *a:None,
                  read=lambda h,a:7,write=lambda *a:None,
                  service_tur=lambda h,item,*a:calls.append(item['cdb']),
                  service_bridge_nodata=lambda *a:self.fail('Must not synthesize invalidation'))
        item=dict(context=7,kind='invalidate_agid',cdb=cdb,length=0,key=(7,b'tag',cdb))
        ns['service_pending'](None,item,time.monotonic()+1,False,set())
        self.assertEqual(calls,[cdb])

    def test_both_invalidation_opcodes_return_actual_physical_error(self):
        for op in (0xa3,0xa4):
            with self.subTest(op=op):
                ns=namespace();writes=[];translated=[]
                registers={0xe000:2,0xe030:1,0xe08c:0x51,0xe08d:0x50,
                           0xe014:9,0xc04c:7,0xd100:0,0xd114:0x22}
                ns.update(verified_protocol=lambda *a:None,
                          translate_pending=lambda h,item,*a:translated.append(item['cdb']),
                          read=lambda h,a:registers[a],write=lambda h,a,v:writes.append((a,v)),
                          mem=lambda h,a,n:bytes(n),log=lambda *a,**k:None)
                cdb=command(op,0x3f,0)
                ns['service_tur'](None,dict(context=7,kind='invalidate_agid',length=0,cdb=cdb),
                                  time.monotonic()+1,False)
                self.assertEqual(translated,[cdb])
                self.assertIn((0xe024,1),writes)
                self.assertIn((0xd117,1),writes)
                self.assertNotIn((0xd117,0),writes)

    def test_report_key_error_returns_actual_failed_csw(self):
        ns=namespace();writes=[]
        registers={0xe000:0x88,0xe08c:0x51,0xe08d:0x50,0xd100:0x48,
                   0xd114:0x22,0xe014:9,0xc04c:7,0xc988:0x40,0xc98b:1,0xd115:2}
        ns.update(verified_protocol=lambda *a:None,translate_pending=lambda *a:None,
                  read=lambda h,a:registers[a],write=lambda h,a,v:writes.append((a,v)),
                  mem=lambda h,a,n:(8).to_bytes(4,'little'),log=lambda *a,**k:None)
        ns['service_data_in'](None,dict(context=7,kind='report_rpc',length=8),
                              time.monotonic()+1,False)
        self.assertIn((0xd117,1),writes);self.assertNotIn((0xd117,0),writes)

    def test_physical_invalidation_can_finish_worker_immediately_after_csw(self):
        ns=namespace();writes=[]
        registers={0xe000:2,0xe030:1,0xe08c:0x50,0xe08d:0,
                   0xe014:9,0xc04c:7,0xd100:0,0xd114:0x22}
        def write(h,a,v):
            writes.append((a,v))
            if (a,v)==(0xd114,4):ns['disk'].result={'scsi_status':0}
        ns.update(verified_protocol=lambda *a:None,translate_pending=lambda *a:None,
                  read=lambda h,a:registers[a],write=write,
                  mem=lambda h,a,n:bytes(n),log=lambda *a,**k:None)
        ns['service_tur'](None,dict(context=7,kind='invalidate_agid',length=0),
                          time.monotonic()+1,True)
        self.assertIn((0xe024,1),writes)
        self.assertIn((0xe08c,0x80),writes)
        self.assertIn((0xd117,0),writes)


if __name__ == '__main__':
    unittest.main()
