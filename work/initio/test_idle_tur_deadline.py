"""Fake-clock idle TUR guards; source extraction avoids all native imports."""
import ast
from pathlib import Path
from types import SimpleNamespace
import unittest


HERE = Path(__file__).resolve().parent


def extracted_transport():
    tree = ast.parse((HERE / 'live_usb_transport.py').read_text())
    names = {'check_bound', 'require_idle_worker', 'revalidate_idle_tur'}
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                and node.name in names]
    assert len(selected) == len(names)
    return compile(ast.Module(body=selected, type_ignores=[]), '<transport guards>', 'exec')


def extracted_reader():
    tree = ast.parse((HERE / 'live_usb_reader.py').read_text())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef)
               and node.name == 'LiveUsbReader')
    names = {'_service_idle_pending', '_service_pending'}
    cls.body = [node for node in cls.body if isinstance(node, ast.FunctionDef)
                and node.name in names]
    assert len(cls.body) == len(names)
    return compile(ast.Module(body=[cls], type_ignores=[]), '<reader guards>', 'exec')


TRANSPORT = extracted_transport()
READER = extracted_reader()


class FakeClock:
    def __init__(self): self.now = 100.0
    def monotonic(self): return self.now


class Replay:
    def __init__(self, acquisition=15.0):
        self.clock = FakeClock()
        self.acquisition = acquisition
        self.h = object()
        self.disk = SimpleNamespace(thread=None, result=None, cdb=bytes(10))
        metadata = bytes.fromhex('200024f0705a4e750000000000060000')
        self.item = dict(context=7, kind='tur', length=0, direction=0,
                         metadata=metadata, cdb=bytes(12),
                         key=(7, metadata[4:8], bytes(12)))
        self.fresh_metadata, self.fresh_cdb = metadata, bytes(12)
        self.registers = {0xc04c: 7, 0xd100: 0, 0xd114: 0x22,
                          0xe014: 9, 0xe08c: 0x50}
        self.context_reads = []
        self.reads = []
        self.claims = []
        self.services = []
        self.revalidations = []
        self.on_claim = None
        self.on_mem = None
        self.ns = dict(time=self.clock, disk=self.disk, CAPACITY_BLOCKS=10000,
                       read=self.read, mem=self.mem)
        exec(TRANSPORT, self.ns)
        self.check_bound = self.ns['check_bound']
        self.require_idle_worker = self.ns['require_idle_worker']
        reader_ns = dict(time=self.clock, t=self)
        exec(READER, reader_ns)
        self.reader = reader_ns['LiveUsbReader']()

    def read(self, handle, address):
        self.reads.append(address)
        if address == 0xc04c and self.context_reads:
            return self.context_reads.pop(0)
        return self.registers[address]

    def mem(self, handle, address, length):
        self.reads.append(address)
        if self.on_mem: self.on_mem()
        if address == 0x1cc00 and length == 16: return self.fresh_metadata
        if address == 0x1cc10 and length == 12: return self.fresh_cdb
        raise AssertionError('Unexpected native-memory read')

    def claim_pending(self, handle, allow_own, deadline, watch):
        self.claims.append((deadline, watch))
        self.clock.now += self.acquisition
        if self.on_claim: self.on_claim()
        return self.item

    def revalidate_idle_tur(self, handle, item, deadline):
        self.revalidations.append(deadline)
        return self.ns['revalidate_idle_tur'](handle, item, deadline)

    def service_pending(self, handle, item, deadline, watch, seen):
        self.services.append((deadline, watch))
        self.check_bound(deadline, watch)

    def run(self): return self.reader._service_idle_pending(set())

    def active_worker(self):
        self.disk.thread = SimpleNamespace(is_alive=lambda: True)


class IdleTurDeadlineTests(unittest.TestCase):
    def test_fifteen_second_exact_idle_tur_gets_fresh_eight_seconds(self):
        r = Replay()
        self.assertTrue(r.run())
        self.assertEqual(r.claims, [(120.0, False)])
        self.assertEqual(r.revalidations, [120.0])
        self.assertEqual(r.services, [(123.0, False)])
        self.assertNotIn(0xd03a, r.reads)  # Revalidation never consumes a new CBW.

    def test_twenty_second_acquisition_limit_is_absolute(self):
        for duration in (20.0, 20.001, 30.0):
            with self.subTest(duration=duration):
                r = Replay(duration)
                with self.assertRaises(RuntimeError): r.run()
                self.assertEqual(r.services, [])

    def test_revalidation_time_is_part_of_twenty_second_limit(self):
        r = Replay(19)
        r.on_mem = lambda: setattr(r.clock, 'now', r.clock.now + 1)
        with self.assertRaises(RuntimeError): r.run()
        self.assertEqual(r.services, [])

    def test_non_tur_cannot_receive_extended_budget(self):
        r = Replay()
        r.item['kind'] = 'read_capacity'
        with self.assertRaises(RuntimeError): r.run()
        self.assertEqual(r.services, [])
        self.assertEqual(r.revalidations, [])

    def test_fast_non_tur_keeps_original_eight_second_deadline(self):
        r = Replay(3)
        r.item['kind'] = 'read_capacity'
        self.assertTrue(r.run())
        self.assertEqual(r.services, [(108.0, False)])
        self.assertEqual(r.revalidations, [])

    def test_no_pending_context_does_not_send_status(self):
        r = Replay(1); r.item = None
        self.assertFalse(r.run())
        self.assertEqual(r.services, [])

    def test_native_acquisition_error_is_not_retried_or_serviced(self):
        r = Replay()
        def failure(*args):
            r.claims.append('failed_once')
            raise OSError('native timeout')
        r.claim_pending = failure
        with self.assertRaisesRegex(OSError, 'native timeout'): r.run()
        self.assertEqual(r.claims, ['failed_once'])
        self.assertEqual(r.services, [])
        self.assertEqual(r.revalidations, [])

    def test_active_worker_prevents_any_idle_claim(self):
        r = Replay(); r.active_worker()
        with self.assertRaises(RuntimeError): r.run()
        self.assertEqual(r.claims, [])

    def test_worker_appearing_during_claim_or_revalidation_rejects(self):
        for stage in ('claim', 'revalidation'):
            with self.subTest(stage=stage):
                r = Replay()
                if stage == 'claim': r.on_claim = r.active_worker
                else: r.on_mem = r.active_worker
                with self.assertRaises(RuntimeError): r.run()
                self.assertEqual(r.services, [])

    def test_finished_worker_result_is_not_mistaken_for_active_io(self):
        r = Replay()
        r.disk.thread = SimpleNamespace(is_alive=lambda: False)
        r.disk.result = {'ioctl_success': True}
        self.assertTrue(r.run())

    def test_every_metadata_byte_is_revalidated_including_tag(self):
        for index in range(16):
            with self.subTest(index=index):
                r = Replay()
                changed = bytearray(r.fresh_metadata); changed[index] ^= 1
                r.fresh_metadata = bytes(changed)
                with self.assertRaises(RuntimeError): r.run()
                self.assertEqual(r.services, [])

    def test_cdb_and_selector_changes_reject(self):
        for mutation in ('cdb', 'selector_before', 'selector_after'):
            with self.subTest(mutation=mutation):
                r = Replay()
                if mutation == 'cdb': r.fresh_cdb = b'\x12' + bytes(11)
                elif mutation == 'selector_before': r.registers[0xc04c] = 8
                else: r.context_reads = [7, 8]
                with self.assertRaises(RuntimeError): r.run()
                self.assertEqual(r.services, [])

    def test_original_cc00_fault_flags_reject_even_when_snapshot_matches(self):
        for fault in (2, 4, 8, 16):
            with self.subTest(fault=fault):
                r = Replay()
                data = bytearray(r.item['metadata']); data[0] |= fault
                r.item['metadata'] = r.fresh_metadata = bytes(data)
                with self.assertRaises(RuntimeError): r.run()
                self.assertEqual(r.services, [])

    def test_invalid_original_identity_or_direction_cannot_extend(self):
        for change in ({'length': 1}, {'direction': 0x80}, {'cdb': b'\x12' + bytes(11)},
                       {'metadata': bytes(15)}, {'key': (7, b'BAD!', bytes(12))}):
            with self.subTest(change=change):
                r = Replay(); r.item.update(change)
                with self.assertRaises(RuntimeError): r.run()
                self.assertEqual(r.services, [])

    def test_usb_reset_busy_or_unready_sata_reject(self):
        for address, value in ((0xd100, 0x10), (0xd114, 1), (0xe014, 0),
                               (0xe08c, 0x80), (0xe08c, 0x51), (0xe08c, 0x58),
                               (0xe08c, 0x70), (0xe08c, 0x10)):
            with self.subTest(address=hex(address), value=value):
                r = Replay(); r.registers[address] = value
                with self.assertRaises(RuntimeError): r.run()
                self.assertEqual(r.services, [])

    def test_missing_capacity_rejects_cached_ready_claim(self):
        r = Replay(); r.ns['CAPACITY_BLOCKS'] = 0
        with self.assertRaises(RuntimeError): r.run()
        self.assertEqual(r.services, [])

    def test_active_service_path_never_extends_its_deadline(self):
        r = Replay()
        with self.assertRaises(RuntimeError):
            r.reader._service_pending(108.0, set(), True)
        self.assertEqual(r.claims, [(108.0, True)])
        self.assertEqual(r.services, [(108.0, True)])
        self.assertEqual(r.revalidations, [])

    def test_normal_fast_active_service_retains_requested_deadline(self):
        r = Replay(1)
        self.assertTrue(r.reader._service_pending(108.0, set(), True))
        self.assertEqual(r.services, [(108.0, True)])
        self.assertEqual(r.revalidations, [])


if __name__ == '__main__':
    unittest.main()
