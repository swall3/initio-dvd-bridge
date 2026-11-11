"""Offline SPTI/auth wiring checks: no native libraries or devices opened."""
import ctypes as C
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scsi_block_worker import ScsiRead
from live_usb_reader import LiveUsbReader
import live_usb_transport as t


def cdb(op,fmt,size):
    return bytes((op,0))+bytes(6)+size.to_bytes(2,'big')+bytes((fmt,0))


class PhysicalAuthTests(unittest.TestCase):
    def test_worker_passes_only_exact_outgoing_parameter_bytes(self):
        worker=object.__new__(ScsiRead)
        worker.thread=None
        payload=b'\x00\x0e\0\0'+bytes(range(10))+bytes(2)
        captured=[]
        worker._begin=lambda *args:captured.append(args)
        worker.start_auth(cdb(0xa3,1,16),16,'out',payload)
        self.assertEqual(captured,[(cdb(0xa3,1,16),16,'out',payload)])
        with self.assertRaises(ValueError):worker.start_auth(cdb(0xa3,6,8),8,'out',bytes(8))
        self.assertEqual(len(captured),1)

    def test_spti_out_direction_and_payload_no_returned_input_data(self):
        worker=object.__new__(ScsiRead)
        worker.cdb=cdb(0xa3,3,12)
        worker.size=12;worker.direction='out';worker.data_out=b'\0\x0a\0\0abcde\0\0\0'
        worker.h=123
        calls=[]
        def ioctl(handle,code,pointer,*args):
            packet=pointer._obj
            calls.append((handle,code,packet.s.DataIn,packet.s.CdbLength,
                          C.string_at(packet.s.DataBuffer,packet.s.DataTransferLength)))
            return True
        worker.k=SimpleNamespace(DeviceIoControl=ioctl)
        worker._run()
        self.assertEqual(calls,[(123,0x4d014,0,12,worker.data_out)])
        self.assertEqual(worker.result['data'],b'')
        self.assertEqual(worker.result['transferred'],12)

    def test_auth_result_preserves_actual_check_condition(self):
        reader=object.__new__(LiveUsbReader)
        actual=bytes.fromhex('700005000000000a000000006f030000000000')
        worker=SimpleNamespace(result=None)
        def start(*args):
            worker.result=dict(ioctl_success=True,scsi_status=2,sense=actual.hex(),transferred=0,data=b'')
        worker.start_auth=start;worker.wait=lambda timeout:None
        with patch.object(t,'disk',worker),patch.object(t,'read',return_value=0),patch.object(t,'log'):
            result=reader._auth(cdb(0xa4,4,12),12,'in')
        self.assertEqual(result.status,2)
        self.assertEqual(result.sense,actual)
        self.assertEqual(result.data,b'')

    def test_auth_in_short_response_and_transport_failure_are_distinct(self):
        reader=object.__new__(LiveUsbReader)
        worker=SimpleNamespace(result=None)
        response=dict(ioctl_success=True,scsi_status=0,transferred=8,data=bytes(8))
        worker.start_auth=lambda *args:setattr(worker,'result',response)
        worker.wait=lambda timeout:None
        with patch.object(t,'disk',worker),patch.object(t,'read',return_value=0),patch.object(t,'log'):
            result=reader._auth(cdb(0xa4,1,16),16,'in')
            self.assertEqual(result.data,bytes(8))
            response['ioctl_success']=False
            with self.assertRaises(OSError):reader._auth(cdb(0xa4,1,16),16,'in')

if __name__=='__main__':unittest.main()
