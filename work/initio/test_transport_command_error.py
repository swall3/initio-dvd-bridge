"""Offline replay of completed ATAPI errors; imports no device/Win32 module."""
import ast
from pathlib import Path
from types import SimpleNamespace
import time
import unittest


SOURCE = Path(__file__).with_name('live_usb_transport.py')
TREE = ast.parse(SOURCE.read_text())
CODE = compile(ast.Module(body=[
    node for node in TREE.body
    if isinstance(node, ast.FunctionDef)
    and node.name in ('service_data_in', 'check_bound', 'usb_gate', 'settle_csw')
], type_ignores=[]), str(SOURCE), 'exec')


class CommandErrorTests(unittest.TestCase):
    def replay(self, kind='read_blocks', size=32768, residual=32768,
               task=0x51, event=0x88, usb_event=0x48, phy=9, control=0x22):
        # Hardware-completion snapshots from the failing READ(10). Issue writes
        # are recorded, while reads expose the completed state supplied here.
        registers = {0xe000: event, 0xe08c: task, 0xe08d: 0x50,
                     0xd100: usb_event, 0xd114: control, 0xe014: phy,
                     0xc04c: 24, 0xc988: 0x40, 0xc98b: 1, 0xd115: 2}
        self.writes = []
        self.events = []
        tasks=iter(task) if isinstance(task,list) else None
        def read(handle,address):
            if address==0xe08c and tasks is not None:
                return next(tasks,task[-1])
            return registers[address]

        def mem(handle, address, length):
            self.assertEqual(length, 4)
            self.assertIn(address, (0x1d134, 0x1cc08))
            value = residual if address == 0x1d134 or not usb_event & 0x40 else size
            return value.to_bytes(4, 'little')

        namespace = dict(
            time=time, disk=SimpleNamespace(result=None),
            read=read, mem=mem,
            write=lambda handle, address, value: self.writes.append((address, value)),
            verified_protocol=lambda *args: None,
            translate_pending=lambda *args: None,
            log=lambda stage, **values: self.events.append((stage, values)),
        )
        exec(CODE, namespace)
        namespace['service_data_in'](
            None, {'context': 24, 'length': size, 'kind': kind},
            time.monotonic() + .03, False)

    def assert_failed_csw(self, residual):
        self.assertIn((0xcc32, 0x51), self.writes)
        self.assertNotIn((0xd117, 0), self.writes)
        self.assertEqual([v for a, v in self.writes if a == 0xd117], [1])
        copied = bytes(next(v for a, v in self.writes if a == address)
                       for address in range(0xd11c, 0xd120))
        self.assertEqual(int.from_bytes(copied, 'little'), residual)
        self.assertLess(self.writes.index((0xe165, 0x20)),
                        self.writes.index((0xd100, 0x48)))
        residual_end = self.writes.index((0xd11f, copied[3]))
        # Initial buffer-slot configuration also writes C98B=1. The terminal
        # flush must occur after copying residual, not before SATA completion.
        self.assertLess(residual_end,
                        self.writes.index((0xc98b, 1), residual_end))
        self.assertLess(self.writes.index((0xd115, 2)),
                        self.writes.index((0xd117, 1)))
        self.assertLess(self.writes.index((0xd117, 1)),
                        self.writes.index((0xd114, 4)))
        self.assertEqual(self.events[-1][1]['status'], 1)

    def test_observed_read_error_returns_failure_and_full_actual_residual(self):
        self.replay()
        self.assert_failed_csw(32768)

    def test_partial_read_error_preserves_partial_residual(self):
        self.replay(residual=2048)
        self.assert_failed_csw(2048)

    def test_capacity_error_returns_failed_csw(self):
        self.replay(kind='read_capacity', size=8, residual=8)
        self.assert_failed_csw(8)

    def test_successful_read_with_nonzero_residual_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'nonzero residual'):
            self.replay(task=0x50, event=0xc8, residual=1)
        self.assertFalse(any(a == 0xd117 for a, _ in self.writes))

    def test_completion_event_waits_for_actual_not_busy_status(self):
        self.replay(task=[0x80,0x50],event=0xc8,residual=0)
        samples=[values for name,values in self.events if name=='queued_bulk_sample']
        self.assertEqual([item['task'] for item in samples],[0x80,0x50])
        self.assertEqual([v for a,v in self.writes if a==0xd117],[0])
        self.assertFalse(any(a==0xe08c for a,v in self.writes))

    def test_failed_read_with_impossible_residual_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Residual exceeds'):
            self.replay(residual=32769)
        self.assertFalse(any(a == 0xd117 for a, _ in self.writes))

    def test_transport_faults_remain_fatal(self):
        for change in ({'event': 0x98}, {'phy': 0}, {'usb_event': 0x58},
                       {'task': 0x81}):
            with self.subTest(change=change):
                with self.assertRaises(RuntimeError):
                    self.replay(**change)
                issue = self.writes.index((0xe024, 1))
                self.assertFalse(any(a in (0xd117, 0xc98b) for a, _ in self.writes[issue+1:]))

    def test_failed_sata_command_without_usb_completion_never_gets_csw(self):
        with self.assertRaisesRegex(RuntimeError, 'deadline exceeded'):
            self.replay(usb_event=0, control=2)
        issue = self.writes.index((0xe024, 1))
        self.assertFalse(any(a in (0xd117, 0xc98b) for a, _ in self.writes[issue+1:]))


if __name__ == '__main__':
    unittest.main()
