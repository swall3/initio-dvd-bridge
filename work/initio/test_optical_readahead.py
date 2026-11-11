"""Offline verified-sector cache tests; no native, socket or hardware imports."""
import unittest

from optical_lun import OpticalLun, ScsiError, ScsiResult


def sectors(lba, count):
    return b''.join(i.to_bytes(4, 'big') * 512 for i in range(lba, lba + count))


def read_cdb(lba, count=1, flags=0, opcode=0x28):
    cdb = bytearray(10)
    cdb[0], cdb[1] = opcode, flags
    cdb[2:6], cdb[7:9] = lba.to_bytes(4, 'big'), count.to_bytes(2, 'big')
    return bytes(cdb)


class Backend:
    def __init__(self):
        self.calls = []
        self.behavior = None

    def __call__(self, lba, count):
        self.calls.append((lba, count))
        if self.behavior is not None:
            return self.behavior(lba, count)
        return sectors(lba, count)


class ReadAheadTests(unittest.TestCase):
    def setUp(self):
        self.backend = Backend()
        self.healthy = True
        self.lun = OpticalLun(self.backend, 1000, read_chunk_blocks=16,
                              read_ahead_blocks=16, backend_health=lambda: self.healthy)

    def read(self, lba, count=1, **flags):
        return self.lun.execute(read_cdb(lba, count, **flags),
                                0 if flags.get('opcode') == 0x2F else count * 2048,
                                'none' if flags.get('opcode') == 0x2F else 'in')

    def good(self, lba, count=1):
        result = self.read(lba, count)
        self.assertEqual(result.status, 0)
        self.assertEqual(result.data, sectors(lba, count))

    def test_default_is_disabled(self):
        self.lun = OpticalLun(self.backend, 1000)
        for lba in range(4): self.good(lba)
        self.assertEqual(self.backend.calls, [(n, 1) for n in range(4)])

    def test_second_sequential_request_fetches_one_verified_window(self):
        for lba in range(33): self.good(lba)
        self.assertEqual(self.backend.calls, [(0, 1), (1, 16), (17, 16)])
        self.assertLessEqual(len(self.lun._read_cache_data), 16 * 2048)

    def test_random_single_reads_do_not_trigger_prefetch(self):
        for lba in (0, 30, 70, 12): self.good(lba)
        self.assertEqual(self.backend.calls, [(0, 1), (30, 1), (70, 1), (12, 1)])

    def test_media_end_and_backend_chunk_limit(self):
        self.lun = OpticalLun(self.backend, 10, read_chunk_blocks=4, read_ahead_blocks=16)
        for lba in range(6, 10): self.good(lba)
        self.assertEqual(self.backend.calls, [(6, 1), (7, 3)])
        self.assertEqual(self.read(10).status, 2)
        self.assertEqual(self.lun._read_cache_data, b'')

    def test_multi_sector_request_does_not_seed_prefetch(self):
        self.good(0, 4); self.good(4)
        self.assertEqual(self.backend.calls, [(0, 4), (4, 1)])

    def test_fua_dpo_and_verify_bypass_cached_data(self):
        for flags in ({'flags': 8}, {'flags': 16}, {'opcode': 0x2F}):
            with self.subTest(flags=flags):
                self.setUp(); self.good(0); self.good(1)
                result = self.read(2, **flags)
                self.assertEqual(result.status, 0)
                self.assertEqual(self.backend.calls[-1], (2, 1))
                self.good(3)
                self.assertEqual(self.backend.calls[-1], (3, 1))

    def test_auth_attempt_discards_cache_and_sequential_trigger(self):
        self.good(0); self.good(1)
        self.lun.auth_command = lambda *a, **kw: ScsiResult(data=bytes(8))
        cdb = bytes.fromhex('a40000000000000000080800')
        self.assertEqual(self.lun.execute(cdb, 8, 'in').status, 0)
        self.good(2)
        self.assertEqual(self.backend.calls[-1], (2, 1))

    def test_auth_failure_discards_cache(self):
        self.good(0); self.good(1)
        def failure(*args, **kw): raise ScsiError(5, 0x6F, 2)
        self.lun.auth_command = failure
        self.assertEqual(self.lun.execute(bytes.fromhex('a40000000000000000080800'), 8, 'in').status, 2)
        self.good(2)
        self.assertEqual(self.backend.calls[-1], (2, 1))

    def test_reset_and_media_replacement_discard_cache(self):
        for replace in (False, True):
            with self.subTest(replace=replace):
                self.setUp(); self.good(0); self.good(1)
                if replace: self.lun.set_media(self.backend, 1000)
                else: self.lun.reset()
                self.assertEqual(self.read(2).status, 2)  # real virtual unit attention
                self.good(2)
                self.assertEqual(self.backend.calls[-1], (2, 1))

    def test_unhealthy_backend_cannot_serve_cached_success(self):
        self.good(0); self.good(1); self.healthy = False
        result = self.read(2)
        self.assertEqual(result.status, 2)
        self.assertEqual(result.sense[2] & 15, 2)
        self.healthy = True; self.good(2)
        self.assertEqual(self.backend.calls[-1], (2, 1))

    def test_speculative_sense_falls_back_only_to_requested_sector(self):
        self.good(0)
        def read(lba, count):
            if lba <= 5 < lba + count: raise ScsiError(3, 0x11)
            return sectors(lba, count)
        self.backend.behavior = read
        self.good(1)
        self.assertEqual(self.backend.calls, [(0, 1), (1, 16), (1, 1)])
        for lba in (2, 3, 4): self.good(lba)
        self.assertEqual(self.backend.calls[-3:], [(2, 1), (3, 1), (4, 1)])
        result = self.read(5)
        self.assertEqual(result.status, 2); self.assertEqual(result.sense[12], 0x11)
        self.good(6)
        self.assertEqual(self.backend.calls[-1], (6, 1))
        self.assertEqual(self.lun._read_cache_data, b'')

    def test_known_failed_window_is_not_crossed_from_earlier_lba(self):
        self.good(10)
        def read(lba, count):
            if count > 1 and lba <= 15 < lba + count: raise ScsiError(5, 0x6F)
            return sectors(lba, count)
        self.backend.behavior = read
        self.good(11)  # marks the speculative11..26 window unsuitable
        self.good(8); self.good(9)
        self.assertEqual(self.backend.calls[-1], (9, 2))  # stops before11

    def test_fallback_actual_error_controls_requested_result(self):
        self.good(0)
        def read(lba, count):
            raise ScsiError(5, 0x6F) if count > 1 else ScsiError(3, 0x11, 4)
        self.backend.behavior = read
        result = self.read(1)
        self.assertEqual(result.status, 2)
        self.assertEqual((result.sense[2] & 15, result.sense[12], result.sense[13]), (3, 0x11, 4))
        self.assertEqual(result.data, b'')

    def test_terminal_sense_and_transport_faults_are_not_retried(self):
        for fault in (ScsiError(2, 4), ScsiError(4, 0x44), ScsiError(6, 0x28),
                      OSError('transport timeout')):
            with self.subTest(fault=fault):
                self.setUp(); self.good(0)
                def fail(lba, count): raise fault
                self.backend.behavior = fail
                self.assertEqual(self.read(1).status, 2)
                self.assertEqual(self.backend.calls, [(0, 1), (1, 16)])
                self.assertEqual(self.lun._read_cache_data, b'')

    def test_short_or_invalid_prefetch_never_falls_back_or_caches(self):
        for value in (bytes(2048), None, bytes(17 * 2048)):
            with self.subTest(length=None if value is None else len(value)):
                self.setUp(); self.good(0)
                self.backend.behavior = lambda lba, count: value
                result = self.read(1)
                self.assertEqual(result.status, 2); self.assertEqual(result.data, b'')
                self.assertEqual(self.backend.calls, [(0, 1), (1, 16)])
                self.assertEqual(self.lun._read_cache_data, b'')

    def test_option_is_strictly_bounded(self):
        for value in (True, -1, 1, 32, 16.0):
            with self.assertRaises(ValueError):
                OpticalLun(self.backend, 100, read_ahead_blocks=value)


if __name__ == '__main__':
    unittest.main()
