import unittest
from unittest.mock import patch
from types import SimpleNamespace
import time
import concurrent.futures
import threading
import live_usb_transport as t
from live_usb_reader import LiveUsbReader, completed_read_error
from optical_lun import ScsiError, fixed_sense

def read_cdb(lba, count, opcode=0x28):
    return bytes((opcode,0))+lba.to_bytes(4,'big')+bytes((0,))+count.to_bytes(2,'big')+bytes(3)

class ReadScope(unittest.TestCase):
    def setUp(self):
        t.CAPACITY_BLOCKS = 1000

    def test_only_completed_current_media_command_sense_is_recoverable(self):
        for key in (3, 5, 7):
            result={'ioctl_success':True,'scsi_status':2,
                    'sense':fixed_sense(key,0x6f,3).hex()}
            error=completed_read_error(result)
            self.assertEqual((error.key,error.asc,error.ascq),(key,0x6f,3))
        for result in (
            {'ioctl_success':False,'scsi_status':2,'sense':fixed_sense(5,0x6f,3).hex()},
            {'ioctl_success':True,'scsi_status':0,'sense':fixed_sense(5,0x6f,3).hex()},
            {'ioctl_success':True,'scsi_status':2,'sense':'not hex'},
            {'ioctl_success':True,'scsi_status':2,'sense':'700005'},
            *({'ioctl_success':True,'scsi_status':2,'sense':fixed_sense(key,0x28).hex()}
              for key in (0,2,4,6,0xb)),
        ):
            with self.subTest(result=result):self.assertIsNone(completed_read_error(result))
        descriptor={'ioctl_success':True,'scsi_status':2,'sense':'72056f0300000000'}
        self.assertEqual(completed_read_error(descriptor).asc,0x6f)

    def test_failed_read_discards_partial_data_and_next_request_succeeds(self):
        reader=object.__new__(LiveUsbReader)
        reader.chunk_blocks=1
        reader.stop_event=threading.Event()
        reader.error=None
        failure=ScsiError(5,0x6f,3)
        calls=[]
        def read(lba,count):
            calls.append((lba,count))
            if lba==1123:raise failure
            return b'x'*2048
        reader._read=read
        failed=concurrent.futures.Future()
        following=concurrent.futures.Future()
        with patch.object(t,'log'):
            reader._complete_request(1122,3,failed)
            reader._complete_request(16,1,following)
        self.assertIs(failed.exception(),failure)
        self.assertEqual(following.result(),b'x'*2048)
        self.assertEqual(calls,[(1122,1),(1123,1),(16,1)])
        self.assertIsNone(reader.error)
        self.assertFalse(reader.stop_event.is_set())

    def test_transport_error_still_escapes_request_handler(self):
        reader=object.__new__(LiveUsbReader)
        reader.chunk_blocks=1
        reader.stop_event=threading.Event()
        reader._read=lambda *args:(_ for _ in ()).throw(OSError('USB transport failure'))
        with self.assertRaisesRegex(OSError,'USB transport failure'):
            reader._complete_request(16,1,concurrent.futures.Future())

    def test_last_sector_and_multiblock(self):
        self.assertEqual(t.classify_cdb(read_cdb(999,1),2048,0x80,True),'read_blocks')
        self.assertEqual(t.classify_cdb(read_cdb(984,16),32768,0x80,True),'read_blocks')

    def test_read_only_mode_sense_allocation(self):
        cdb=bytes.fromhex('1a003f00c000000000000000')
        self.assertEqual(t.classify_cdb(cdb,192,0x80,True),'mode_sense6')
        for size,direction in ((193,0x80),(192,0)):
            with self.assertRaises(RuntimeError):t.classify_cdb(cdb,size,direction,True)

    def test_only_standard_prevent_allow_without_payload(self):
        for flag in (0,1):
            cdb=bytes((0x1e,0,0,0,flag))+bytes(7)
            self.assertEqual(t.classify_cdb(cdb,0,0,True),'prevent_allow')
        with self.assertRaises(RuntimeError):
            t.classify_cdb(bytes.fromhex('1e0000000300000000000000'),0,0,True)

    def test_reject_writes_out_of_bounds_and_mismatched_lengths(self):
        for cdb,size,direction in (
            (read_cdb(0,1,0x2a),2048,0),
            (read_cdb(0,1),2048,0),
            (read_cdb(1000,1),2048,0x80),
            (read_cdb(999,2),4096,0x80),
            (read_cdb(0,17),34816,0x80),
            (read_cdb(0,1),4096,0x80),
            (read_cdb(0,0),0,0x80),
        ):
            with self.subTest(cdb=cdb.hex(),size=size,direction=direction):
                with self.assertRaises(RuntimeError):
                    t.classify_cdb(cdb,size,direction,True)

    def test_continuous_background_work_does_not_starve_own_read(self):
        reader=object.__new__(LiveUsbReader)
        calls=[]
        worker=SimpleNamespace(result=None)
        worker.start=lambda lba,count:calls.append(('start',lba,count))
        worker.wait=lambda seconds:None
        def service(deadline,seen,watch=False):
            calls.append(('service',watch))
            if watch and sum(c==('service',True) for c in calls)==9:
                worker.result={'ioctl_success':True,'scsi_status':0,
                               'transferred':2048,'data':b'x'*2048}
            return True
        reader._service_pending=service
        with patch.object(t,'disk',worker),patch.object(t,'read',return_value=0x10), \
             patch.object(t,'check_bound'),patch.object(t,'log'):
            self.assertEqual(reader._read(16,1),b'x'*2048)
        self.assertEqual(calls[:3],[('service',False),('service',False),('start',16,1)])

    def test_claimed_background_request_finishes_when_own_worker_completes(self):
        reader=object.__new__(LiveUsbReader)
        worker=SimpleNamespace(cdb=read_cdb(16,1)[:10],result=None)
        item={'cdb':read_cdb(0,1)}
        def claim(*args):
            worker.result={'ioctl_success':True}
            return item
        with patch.object(t,'disk',worker),patch.object(t,'claim_pending',side_effect=claim), \
             patch.object(t,'service_pending') as service:
            self.assertTrue(reader._service_pending(time.monotonic()+2,set(),True))
            self.assertFalse(service.call_args.args[3])
            item['cdb']=read_cdb(16,1)
            reader._service_pending(time.monotonic()+2,set(),True)
            self.assertTrue(service.call_args.args[3])

    def test_completed_mode_error_returns_failed_csw_with_actual_residual(self):
        registers={0xe000:0x88,0xe08c:0x51,0xe08d:0x50,0xd100:0x48,
                   0xd114:0x22,0xe014:9,0xc04c:0,0xc988:0x40,0xc98b:1,0xd115:2}
        writes=[]
        item={'context':0,'length':192,'kind':'mode_sense6'}
        with patch.object(t,'verified_protocol'),patch.object(t,'translate_pending'), \
             patch.object(t,'check_bound'),patch.object(t,'usb_gate'), \
             patch.object(t,'settle_csw'),patch.object(t,'log'), \
             patch.object(t,'read',side_effect=lambda h,a:registers[a]), \
             patch.object(t,'mem',return_value=(192).to_bytes(4,'little')), \
             patch.object(t,'write',side_effect=lambda h,a,v:writes.append((a,v))):
            t.service_data_in(None,item,time.monotonic()+2,False)
        self.assertIn((0xd117,1),writes)
        self.assertNotIn((0xd117,0),writes)
        self.assertIn((0xd11c,192),writes)
        self.assertLess(writes.index((0xcc32,0x51)),writes.index((0xd117,1)))

    def test_completed_context_ring_can_wrap_without_false_duplicate(self):
        seen=set();current=[0]
        with patch.object(t,'check_bound'),patch.object(t,'usb_gate'), \
             patch.object(t,'read',side_effect=lambda h,a:current[0]), \
             patch.object(t,'write'),patch.object(t,'service_bridge_nodata'),patch.object(t,'log'):
            for i in range(33):
                current[0]=i%32
                item={'context':current[0],'kind':'tur','cdb':bytes(12),'key':(current[0],b'tag',bytes(12))}
                t.service_pending(None,item,time.monotonic()+2,False,seen)
            self.assertEqual(len(seen),1)
            with self.assertRaises(RuntimeError):
                t.service_pending(None,item,time.monotonic()+2,False,seen)

    def test_nodata_status_is_reread_after_fresh_status_ack(self):
        acked=[False];writes=[]
        def read(h,address):
            if address==0xe08c:return 0x50 if acked[0] else 0x80
            return {0xe000:2,0xe030:1,0xe08d:0,0xe014:9,0xc04c:7}[address]
        def write(h,address,value):
            writes.append((address,value))
            if address==0xe030 and value==1:acked[0]=True
        item={'context':7,'kind':'tur','length':0}
        with patch.object(t,'verified_protocol'),patch.object(t,'translate_pending'), \
             patch.object(t,'check_bound'),patch.object(t,'usb_gate'), \
             patch.object(t,'settle_csw'),patch.object(t,'log'), \
             patch.object(t,'read',side_effect=read),patch.object(t,'write',side_effect=write), \
             patch.object(t,'mem',side_effect=lambda h,a,n:bytes(n)):
            t.service_tur(None,item,time.monotonic()+2,False)
        self.assertIn((0xd117,0),writes)
        self.assertLess(writes.index((0xe030,1)),writes.index((0xd117,0)))

    def test_bridge_housekeeping_never_issues_a_sata_command(self):
        writes=[]
        item={'context':7,'kind':'prevent_allow','length':0,
              'cdb':bytes.fromhex('1e0000000100000000000000')}
        with patch.object(t,'verified_protocol'),patch.object(t,'usb_gate'), \
             patch.object(t,'check_bound'),patch.object(t,'settle_csw'),patch.object(t,'log'), \
             patch.object(t,'read',side_effect=lambda h,a:{0xe014:9,0xe08c:0x50}[a]), \
             patch.object(t,'mem',return_value=bytes(4)), \
             patch.object(t,'write',side_effect=lambda h,a,v:writes.append((a,v))):
            t.service_bridge_nodata(None,item,time.monotonic()+2,False)
        self.assertIn((0xd117,0),writes)
        self.assertIn((0xd138,7|0x80),writes)
        self.assertFalse(any(a>=0xe000 for a,v in writes))

if __name__=='__main__':
    unittest.main()
