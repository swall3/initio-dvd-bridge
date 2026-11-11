"""Offline protocol tests. No imports or access to the hardware backend."""
import struct
import unittest

from optical_lun import OpticalLun, ScsiError, ScsiResult, fixed_sense
from dvd_auth_commands import validate_auth_cdb, validate_auth_command


def command(op, length=10, **fields):
    data = bytearray(length)
    data[0] = op
    for key, value in fields.items():
        data[int(key)] = value
    return data


class OpticalLunTests(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def reader(lba, count):
            self.calls.append((lba, count))
            return b"".join(bytes([x % 251]) * 2048 for x in range(lba, lba + count))

        self.reader = reader
        self.lun = OpticalLun(reader, 4147211)

    def run_cdb(self, cdb, length=128, direction="in", lun=None):
        return (lun or self.lun).execute(bytes(cdb), length, direction)

    def assert_sense(self, result, key, asc, ascq=0):
        self.assertEqual(result.status, 2)
        self.assertEqual(result.data, b"")
        self.assertEqual((result.sense[2], result.sense[12], result.sense[13]),
                         (key, asc, ascq))

    def test_identity_is_virtual_optical_and_allocation_is_honored(self):
        cdb = command(0x12, 6, **{"4": 96})
        result = self.run_cdb(cdb)
        self.assertEqual(len(result.data), 36)
        self.assertEqual(result.data[:5], bytes((5, 0x80, 5, 2, 31)))
        self.assertEqual(result.data[8:32], b"CODEX   USB DVD Bridge  ")
        cdb[4] = 5
        self.assertEqual(len(self.run_cdb(cdb).data), 5)
        self.assertEqual(len(self.run_cdb(cdb, 3).data), 3)
        self.assertEqual(self.calls, [])

    def test_vpd_lengths_and_identifier(self):
        for page in (0, 0x80, 0x83):
            cdb = command(0x12, 6, **{"1": 1, "2": page, "4": 255})
            data = self.run_cdb(cdb, 255).data
            self.assertEqual(data[:2], bytes((5, page)))
            self.assertEqual(int.from_bytes(data[2:4], "big"), len(data) - 4)
        data = self.run_cdb(command(0x12, 6, **{"1": 1, "2": 0x83, "4": 255}), 255).data
        self.assertEqual(data[4:7], bytes((2, 1, 0)))
        self.assertEqual(data[7], len(data) - 8)
        self.assert_sense(self.run_cdb(command(0x12, 6, **{"1": 1, "2": 0xB0})), 5, 0x24)

    def test_report_luns_length_and_single_lun(self):
        cdb = command(0xA0, 12)
        cdb[6:10] = (16).to_bytes(4, "big")
        data = self.run_cdb(cdb, 16).data
        self.assertEqual(data, b"\x00\x00\x00\x08" + bytes(12))
        cdb[2] = 1
        self.assertEqual(self.run_cdb(cdb, 16).data, bytes(8))

    def test_capacity_exact_known_disc_and_endianness(self):
        data = self.run_cdb(command(0x25), 8).data
        self.assertEqual(struct.unpack(">II", data), (4147210, 2048))
        cdb = command(0x9E, 16, **{"1": 0x10})
        cdb[10:14] = (32).to_bytes(4, "big")
        data = self.run_cdb(cdb, 32).data
        self.assertEqual(struct.unpack(">QI", data[:12]), (4147210, 2048))
        self.assertEqual(len(data), 32)
        cdb = command(0x23)
        cdb[7:9] = (12).to_bytes(2, "big")
        data = self.run_cdb(cdb, 12).data
        self.assertEqual(data[3], 8)
        self.assertEqual(int.from_bytes(data[4:8], "big"), 4147211)
        self.assertEqual(data[8:], b"\x02\x00\x08\x00")

    def test_real_read10_and_read12_not_generated_data(self):
        for op, size in ((0x28, 10), (0xA8, 12), (0x88, 16)):
            self.calls.clear()
            cdb = command(op, size)
            if op == 0x88:
                cdb[2:10], cdb[10:14] = (259).to_bytes(8, "big"), (2).to_bytes(4, "big")
            else:
                cdb[2:6] = (259).to_bytes(4, "big")
                if op == 0x28:
                    cdb[7:9] = (2).to_bytes(2, "big")
                else:
                    cdb[6:10] = (2).to_bytes(4, "big")
            result = self.run_cdb(cdb, 4096)
            self.assertEqual(result.status, 0)
            self.assertEqual(self.calls, [(259, 2)])
            self.assertEqual(result.data, b"\x08" * 2048 + b"\x09" * 2048)

    def test_chunking_and_bounds(self):
        cdb = command(0x28)
        cdb[7:9] = (64).to_bytes(2, "big")
        self.assertEqual(len(self.run_cdb(cdb, 128 * 1024).data), 128 * 1024)
        self.assertEqual(self.calls, [(0, 32), (32, 32)])
        self.calls.clear()
        cdb[7:9] = (65).to_bytes(2, "big")
        self.assert_sense(self.run_cdb(cdb, 128 * 1024), 5, 0x24)
        cdb[7:9], cdb[2:6] = b"\x00\x02", (4147210).to_bytes(4, "big")
        self.assert_sense(self.run_cdb(cdb, 4096), 5, 0x21)
        self.assertEqual(self.calls, [])
        cdb[7:9] = bytes(2)
        self.assertEqual(self.run_cdb(cdb, 0).status, 0)
        self.assertEqual(self.calls, [])

    def test_short_failed_and_missing_reads_never_become_zero_success(self):
        cdb = command(0x28, **{"8": 1})
        for reader in (lambda l, n: b"", lambda l, n: bytes(2047), lambda l, n: None):
            self.assert_sense(self.run_cdb(cdb, 2048, lun=OpticalLun(reader, 10)), 3, 0x11)
        def failed(lba, count):
            raise ScsiError(2, 0x3A)
        self.assert_sense(self.run_cdb(cdb, 2048, lun=OpticalLun(failed, 10)), 2, 0x3A)
        with self.assertRaises(ValueError):
            OpticalLun(block_count=10)

    def test_no_media_identity_and_sense(self):
        lun = OpticalLun()
        self.assert_sense(self.run_cdb(command(0, 6), 0, "none", lun), 2, 0x3A)
        cdb = command(3, 6, **{"4": 18})
        result = self.run_cdb(cdb, 18, lun=lun)
        self.assertEqual((result.data[2], result.data[12]), (2, 0x3A))
        self.assertEqual(self.run_cdb(cdb, 18, lun=lun).data[2], 0)
        self.assertEqual(self.run_cdb(command(0x12, 6, **{"4": 36}), 36, lun=lun).data[0], 5)
        self.assert_sense(self.run_cdb(command(0x25), 8, lun=lun), 2, 0x3A)

    def test_failed_backend_is_not_ready_without_touching_reader(self):
        health_calls=[]
        lun=OpticalLun(self.reader,100,backend_health=lambda:health_calls.append(1) or False)
        for cdb,length,direction in ((command(0,6),0,'none'),
                                     (command(0x28,**{'8':1}),2048,'in'),
                                     (command(0x25),8,'in')):
            self.assert_sense(self.run_cdb(cdb,length,direction,lun),2,0x04)
        self.assertEqual(self.calls,[])
        self.assertEqual(len(health_calls),3)
        inquiry=self.run_cdb(command(0x12,6,**{'4':36}),36,lun=lun)
        self.assertEqual(inquiry.status,0)
        sense=self.run_cdb(command(3,6,**{'4':18}),18,lun=lun)
        self.assertEqual(sense.status,0)
        self.assertEqual((sense.data[2],sense.data[12],sense.data[13]),(2,4,0))
        event=self.run_cdb(command(0x4a,**{'1':1,'4':0x10,'8':8}),8,lun=lun)
        self.assertEqual(event.data,bytes.fromhex('0006041000020000'))
        self.assertTrue(lun.media_present)
        self.assertEqual(len(health_calls),3)

    def test_healthy_backend_preserves_actual_medium_error_and_ready_tur(self):
        healthy=[True]
        def failed(lba,count):
            raise ScsiError(3,0x11,5)
        lun=OpticalLun(failed,100,backend_health=lambda:healthy[0])
        self.assert_sense(self.run_cdb(command(0x28,**{'8':1}),2048,lun=lun),3,0x11,5)
        self.assertEqual(self.run_cdb(command(0,6),0,'none',lun).status,0)
        healthy[0]=False
        self.assert_sense(self.run_cdb(command(0,6),0,'none',lun),2,0x04)

    def test_backend_health_exception_is_not_ready(self):
        def failed():
            raise RuntimeError('cached health unavailable')
        lun=OpticalLun(self.reader,100,backend_health=failed)
        self.assert_sense(self.run_cdb(command(0,6),0,'none',lun),2,0x04)
        self.assertEqual(self.calls,[])
        with self.assertRaises(ValueError):
            OpticalLun(self.reader,100,backend_health=False)

    def test_mode_headers_write_protect_and_pages(self):
        cdb = command(0x5A, **{"1": 8, "2": 0x2A, "8": 64})
        data = self.run_cdb(cdb, 64).data
        self.assertEqual(int.from_bytes(data[:2], "big"), len(data) - 2)
        self.assertEqual(data[3], 0x80)
        self.assertEqual(data[6:10], bytes((0, 0, 0x2A, 28)))
        self.assertEqual(data[11], 0)  # no write capabilities
        cdb = command(0x1A, 6, **{"2": 0x3F, "4": 128})
        data = self.run_cdb(cdb).data
        self.assertEqual(data[0], len(data) - 1)
        self.assertEqual(data[2:4], b"\x80\x08")
        self.assertEqual(data[9:12], b"\x00\x08\x00")
        cdb[2] = 0xCA
        self.assert_sense(self.run_cdb(cdb), 5, 0x39)

    def test_get_configuration_filter_current_and_length(self):
        cdb = command(0x46, **{"8": 255})
        data = self.run_cdb(cdb, 255).data
        self.assertEqual(int.from_bytes(data[:4], "big"), len(data) - 4)
        self.assertEqual(data[6:8], b"\x00\x10")
        codes, offset = [], 8
        while offset < len(data):
            codes.append(int.from_bytes(data[offset:offset + 2], "big"))
            offset += 4 + data[offset + 3]
        self.assertEqual(offset, len(data))
        self.assertEqual(codes, [0, 1, 2, 3, 0x10, 0x1F, 0x108])
        cdb[1], cdb[3] = 2, 0x10
        data = self.run_cdb(cdb, 255).data
        self.assertEqual(data[8:12], b"\x00\x10\x01\x08")
        self.assertEqual(int.from_bytes(data[12:16], "big"), 2048)
        cdb[1], cdb[3] = 1, 0
        no_media = self.run_cdb(cdb, 255, lun=OpticalLun()).data
        self.assertEqual(no_media[6:8], bytes(2))

    def test_toc_lba_session_leadout_and_msf(self):
        cdb = command(0x43, **{"8": 64})
        data = self.run_cdb(cdb, 64).data
        self.assertEqual(data[:4], b"\x00\x12\x01\x01")
        self.assertEqual(data[4:8], b"\x00\x14\x01\x00")
        self.assertEqual(data[12:16], b"\x00\x14\xaa\x00")
        self.assertEqual(int.from_bytes(data[16:20], "big"), 4147211)
        cdb[6] = 0xAA
        self.assertEqual(len(self.run_cdb(cdb).data), 12)
        cdb[2], cdb[6] = 1, 0
        self.assertEqual(self.run_cdb(cdb).data[:4], b"\x00\x0a\x01\x01")
        cdb[1], cdb[2] = 2, 0
        data = self.run_cdb(cdb, lun=OpticalLun(self.reader, 300)).data
        self.assertEqual(data[8:12], b"\x00\x00\x02\x00")
        self.assertEqual(data[16:20], b"\x00\x00\x06\x00")
        self.assert_sense(self.run_cdb(cdb), 5, 0x24)  # no minute-byte wrap for huge DVD

    def test_events_and_virtual_reset_never_touch_backend(self):
        cdb = command(0x4A, **{"1": 1, "4": 0x10, "8": 8})
        self.assertEqual(self.run_cdb(cdb, 8).data, b"\x00\x06\x04\x10\x00\x02\x00\x00")
        self.lun.reset()
        self.assertEqual(self.run_cdb(command(0x12, 6, **{"4": 36}), 36).status, 0)
        self.assert_sense(self.run_cdb(command(0, 6), 0, "none"), 6, 0x29)
        self.assertEqual(self.run_cdb(command(0, 6), 0, "none").status, 0)
        self.lun.set_media()
        self.assert_sense(self.run_cdb(command(0, 6), 0, "none"), 6, 0x28)
        self.assertEqual(self.run_cdb(cdb, 8).data[4:6], b"\x03\x00")
        self.assertEqual(self.calls, [])

    def test_write_and_unknown_opcodes_never_reach_backend(self):
        for op in OpticalLun.WRITE_OPCODES:
            self.assert_sense(self.run_cdb(command(op, 16), 0, "none"), 7, 0x27)
        self.assert_sense(self.run_cdb(command(0x12, 6), 0, "out"), 7, 0x27)
        self.assert_sense(self.run_cdb(command(0xFF, 16)), 5, 0x20)
        self.assert_sense(self.run_cdb(command(0x1B, 6, **{"4": 2}), 0, "none"), 5, 0x24)
        self.assertEqual(self.calls, [])

    def test_malformed_cdb_length_flags_and_direction(self):
        for cdb in (b"", b"\x28", bytes(command(0x28)) + b"\x01"):
            self.assert_sense(self.run_cdb(cdb), 5, 0x24)
        self.assert_sense(self.run_cdb(command(0x28, **{"1": 0x20, "8": 1}), 2048), 5, 0x24)
        self.assert_sense(self.run_cdb(command(0x25), 8, "none"), 5, 0x24)
        self.assert_sense(self.run_cdb(command(0, 6), 1, "in"), 5, 0x24)
        self.assertEqual(self.calls, [])


class DvdAuthTests(unittest.TestCase):
    @staticmethod
    def auth_cdb(op, fmt, size, agid=0, lba=0, layer=0):
        cdb = command(op, 12)
        cdb[2:6] = lba.to_bytes(4, "big")
        cdb[6] = layer
        cdb[8:10] = size.to_bytes(2, "big")
        if op == 0xAD:
            cdb[7], cdb[10] = fmt, agid << 6
        else:
            cdb[10] = fmt | (agid << 6)
        return bytes(cdb)

    @staticmethod
    def payload(fmt):
        return (b"\x00\x0e\x00\x00" + bytes(range(10)) + bytes(2) if fmt == 1 else
                b"\x00\x0a\x00\x00" + bytes(range(5)) + bytes(3))

    def setUp(self):
        self.calls = []
        self.response = ScsiResult(data=b"\x00\x06\x00\x00\x00\x00\x00\x80")

        def backend(cdb, size, direction, data_out=b""):
            self.calls.append((cdb, size, direction, data_out))
            return self.response

        self.backend = backend
        self.lun = OpticalLun(lambda lba, count: bytes(count * 2048), 10000, auth_command=backend)

    def test_actual_report_agid_payload_and_normalized_cdb(self):
        cdb = self.auth_cdb(0xA4, 0, 8)
        result = self.lun.execute(cdb + bytes(4), 8, "in")
        self.assertEqual(result, self.response)
        self.assertEqual(self.calls, [(cdb, 8, "in", b"")])

    def test_supported_report_and_structure_envelopes(self):
        for fmt, size in ((0, 8), (1, 16), (2, 12), (4, 12), (5, 8), (8, 8)):
            cdb = self.auth_cdb(0xA4, fmt, size, agid=0 if fmt == 8 else 3, lba=321 if fmt == 4 else 0)
            self.assertTrue(validate_auth_cdb(cdb, size, "in").startswith("report_"))
        for fmt, size, agid in ((0, 21, 0), (0, 2052, 0), (1, 8, 0), (2, 2052, 3)):
            cdb = self.auth_cdb(0xAD, fmt, size, agid=agid)
            self.assertEqual(validate_auth_command(cdb, size, "in"), cdb)
        self.assertEqual(validate_auth_cdb(self.auth_cdb(0xA4, 0, 4), 4, "in"), "report_agid")

    def test_challenge_and_key2_exact_payload_forwarded(self):
        self.response = ScsiResult()
        for fmt in (1, 3):
            data = self.payload(fmt)
            cdb = self.auth_cdb(0xA3, fmt, len(data), agid=2)
            self.assertEqual(self.lun.execute(cdb, len(data), "out", data_out=data), self.response)
            self.assertEqual(self.calls[-1], (cdb, len(data), "out", data))

    def test_linux_report_and_windows_send_invalidation_are_forwarded_unchanged(self):
        self.response = ScsiResult()
        for op, directions in ((0xA4, ("none", "in")), (0xA3, ("none",))):
            for agid in range(4):
                cdb = self.auth_cdb(op, 0x3F, 0, agid=agid)
                for direction in directions:
                    self.assertEqual(validate_auth_cdb(cdb, 0, direction), "invalidate_agid")
                    self.assertEqual(self.lun.execute(cdb, 0, direction), self.response)
                    self.assertEqual(self.calls[-1], (cdb, 0, direction, b""))

    def test_windows_invalidation_rejects_reserved_fields_lengths_directions_and_payload(self):
        good = self.auth_cdb(0xA3, 0x3F, 0, agid=3)
        for offset in (*range(1,10), 11):
            bad = bytearray(good); bad[offset] = 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                validate_auth_command(bad, 0, "none")
            self.assertEqual(self.lun.execute(bad, 0, "none").status, 2)
        for size, direction, payload in ((0,"in",b""), (0,"out",b""),
                                         (1,"none",b""), (0,"none",b"x")):
            with self.subTest(size=size,direction=direction), self.assertRaises(ValueError):
                validate_auth_command(good, size, direction, payload)
            self.assertEqual(self.lun.execute(good, size, direction, payload).status, 2)
        with self.assertRaises(ValueError):
            validate_auth_command(good+bytes(3)+b"x",0,"none")
        self.assertEqual(self.calls, [])

    def test_windows_invalidation_preserves_actual_failure_even_without_media(self):
        self.response = ScsiResult(2, sense=fixed_sense(5, 0x6F, 0))
        lun = OpticalLun(auth_command=self.backend)
        cdb = self.auth_cdb(0xA3, 0x3F, 0, agid=2)
        self.assertEqual(lun.execute(cdb,0,"none"),self.response)
        self.assertEqual(self.calls,[(cdb,0,"none",b"")])

    def test_region_changes_and_other_writes_never_forward(self):
        for op, fmt, size in ((0xA3, 6, 8), (0xA3, 2, 12), (0xA4, 6, 8), (0xAD, 0xC0, 8)):
            cdb = self.auth_cdb(op, fmt, size)
            result = self.lun.execute(cdb, size, "out" if op == 0xA3 else "in", data_out=bytes(size) if op == 0xA3 else b"")
            self.assertEqual(result.status, 2)
        self.assertEqual(self.lun.execute(bytes(command(0x2A)), 2048, "out", bytes(2048)).status, 2)
        self.assertEqual(self.calls, [])

    def test_malformed_send_headers_padding_or_lengths_never_forward(self):
        good = self.payload(1)
        cdb = self.auth_cdb(0xA3, 1, 16)
        candidates = [good[:-1], good + b"\x00", b"\x00\x0c" + good[2:],
                      good[:2] + b"\x01" + good[3:], good[:-1] + b"\x01"]
        for data in candidates:
            self.assertEqual(self.lun.execute(cdb, 16, "out", data).status, 2)
        self.assertEqual(self.lun.execute(cdb, 12, "out", good).status, 2)
        self.assertEqual(self.calls, [])

    def test_reserved_cdb_keyclass_and_padding_never_forward(self):
        valid = self.auth_cdb(0xA4, 0, 8)
        for offset in (1, 2, 6, 7, 11):
            malformed = bytearray(valid)
            malformed[offset] = 1
            self.assertEqual(self.lun.execute(malformed, 8, "in").status, 2)
        self.assertEqual(self.lun.execute(valid + b"\x00\x00\x00\x01", 8, "in").status, 2)
        self.assertEqual(self.lun.execute(valid, 9, "in").status, 2)
        self.assertEqual(self.lun.execute(valid, 8, "in", b"x").status, 2)
        self.assertEqual(self.calls, [])

    def test_actual_fixed_and_descriptor_sense_preserved(self):
        cdb = self.auth_cdb(0xA4, 4, 12, agid=1, lba=1123)
        for sense in (fixed_sense(5, 0x6F, 3), bytes.fromhex("72056f0300000000")):
            self.response = ScsiResult(2, sense=sense)
            result = self.lun.execute(cdb, 12, "in")
            self.assertEqual(result, self.response)
            request = self.lun.execute(bytes(command(3, 6, **{"4": 18})), 18, "in")
            self.assertEqual((request.data[2], request.data[12], request.data[13]), (5, 0x6F, 3))

    def test_callback_exception_and_oversize_never_fabricate_key(self):
        cdb = self.auth_cdb(0xA4, 0, 8)
        self.response = ScsiResult(data=bytes(9))
        result = self.lun.execute(cdb, 8, "in")
        self.assertEqual((result.status, result.data, result.sense[2], result.sense[12]), (2, b"", 4, 0x44))
        def failed(*args, **kwargs):
            raise ScsiError(5, 0x6F, 2)
        self.lun.auth_command = failed
        result = self.lun.execute(cdb, 8, "in")
        self.assertEqual((result.sense[2], result.sense[12], result.sense[13]), (5, 0x6F, 2))

    def test_capability_probe_is_exact_and_discovery_not_callback_alone(self):
        probe = command(0x46, **{"1": 2, "2": 1, "3": 6, "8": 16})
        self.assertEqual(validate_auth_cdb(probe, 16, "in"), "capability_probe")
        self.assertEqual(len(validate_auth_command(probe, 16, "in")), 12)
        for offset in (1, 2, 3, 4, 6, 8, 9):
            changed = bytearray(probe)
            changed[offset] ^= 1
            with self.assertRaises(ValueError):
                validate_auth_cdb(changed, 16, "in")
        without = self.lun.execute(bytes(probe), 16, "in")
        self.assertEqual(len(without.data), 8)
        self.assertEqual(self.calls, [])
        evidence = bytes.fromhex("0106030400000001")
        proven = OpticalLun(lambda lba, count: bytes(count * 2048), 100, auth_command=self.backend, css_feature=evidence)
        self.assertEqual(proven.execute(bytes(probe), 16, "in").data[8:], evidence)
        absent = OpticalLun(auth_command=self.backend, css_feature=evidence)
        self.assertEqual(absent.execute(bytes(probe), 16, "in").data[8:], bytes.fromhex("0106020400000001"))
        with self.assertRaises(ValueError):
            OpticalLun(css_feature=evidence)
        with self.assertRaises(ValueError):
            OpticalLun(auth_command=self.backend, css_feature=bytes(8))

    def test_no_auth_path_and_media_health_guards(self):
        noauth = OpticalLun(lambda lba, count: bytes(count * 2048), 100)
        self.assertEqual(noauth.execute(self.auth_cdb(0xA4, 0, 8), 8, "in").sense[12], 0x20)
        self.assertEqual(noauth.execute(self.auth_cdb(0xA3, 1, 16), 16, "out", self.payload(1)).sense[12], 0x27)
        unready = OpticalLun(lambda lba, count: bytes(count * 2048), 100,
                             auth_command=self.backend, backend_health=lambda: False)
        self.assertEqual(unready.execute(self.auth_cdb(0xA4, 0, 8), 8, "in").sense[12], 4)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
