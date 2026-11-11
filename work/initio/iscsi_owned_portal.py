"""Inspect/remove only this workspace's journal-owned loopback discovery portal.

Default is read-only. --remove requires the exact journal, zero native sessions,
one matching portal with the original unbound source, and a verified post-read.
No registry, service, USB, disk, firewall, or target-login changes are made.

SDK: Windows Kits/10/Include/10.0.26100.0/um/iscsidsc.h (lines 34,47,53,71,551-580).
https://learn.microsoft.com/windows/win32/api/iscsidsc/nf-iscsidsc-reportiscsisendtargetportalsw
https://learn.microsoft.com/windows/win32/api/iscsidsc/nf-iscsidsc-removeiscsisendtargetportalw
"""
from __future__ import annotations

import argparse
from collections import Counter
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import uuid

from iscsi_windows_inventory import native_report, TARGET_HOST, TARGET_PORT, TARGET_IQN

ANY_INITIATOR_PORT = 0xFFFFFFFF
JOURNAL = Path(__file__).resolve().parents[2] / "outputs/initio/iscsi-windows-session.json"
AUDIT_LOG = JOURNAL.with_name("iscsi-native-portal.jsonl")


class ISCSI_TARGET_PORTALW(C.Structure):
    _fields_ = [("SymbolicName", W.WCHAR * 256), ("Address", W.WCHAR * 256), ("Socket", W.USHORT)]


class ISCSI_TARGET_PORTAL_INFOW(C.Structure):
    _fields_ = [("InitiatorName", W.WCHAR * 256), ("InitiatorPortNumber", W.ULONG),
                ("SymbolicName", W.WCHAR * 256), ("Address", W.WCHAR * 256), ("Socket", W.USHORT)]


FIELDS = tuple(name for name, _ in ISCSI_TARGET_PORTAL_INFOW._fields_)


class NativePortals:
    def __init__(self):
        if (C.sizeof(W.WCHAR), C.sizeof(W.ULONG), C.sizeof(ISCSI_TARGET_PORTALW),
                C.sizeof(ISCSI_TARGET_PORTAL_INFOW)) != (2, 4, 1026, 1544):
            raise RuntimeError("Unexpected Windows SDK structure layout")
        self.dll = C.WinDLL("iscsidsc.dll")
        self.query = self.dll.ReportIScsiSendTargetPortalsW
        self.query.argtypes = [C.POINTER(W.ULONG), C.POINTER(ISCSI_TARGET_PORTAL_INFOW)]
        self.query.restype = W.ULONG
        self.remove_fn = self.dll.RemoveIScsiSendTargetPortalW
        self.remove_fn.argtypes = [W.LPWSTR, W.ULONG, C.POINTER(ISCSI_TARGET_PORTALW)]
        self.remove_fn.restype = W.ULONG

    def report(self):
        count = W.ULONG(0)
        entries = None
        for _ in range(4):
            capacity = 0 if entries is None else len(entries)
            status = int(self.query(C.byref(count), entries))
            if status == 0:
                if count.value > capacity:
                    raise RuntimeError("Portal report exceeded the supplied array")
                return [{name: getattr(entries[i], name) for name in FIELDS} for i in range(count.value)]
            if status != 122 or count.value > 4096:
                raise RuntimeError(f"Native portal report failed: status={status:#x}, count={count.value}")
            capacity = max(1, count.value)
            entries = (ISCSI_TARGET_PORTAL_INFOW * capacity)()
            count.value = capacity
        raise RuntimeError("Native portal count did not stabilize")

    def remove(self, record):
        portal = ISCSI_TARGET_PORTALW()
        portal.SymbolicName = record["SymbolicName"]
        portal.Address = record["Address"]
        portal.Socket = record["Socket"]
        return int(self.remove_fn(record["InitiatorName"] or None,
                                  record["InitiatorPortNumber"], C.byref(portal)))


def is_endpoint(record):
    return record["Address"] == TARGET_HOST and record["Socket"] == TARGET_PORT


def identities(records):
    return Counter(tuple(record[name] for name in FIELDS) for record in records)


def validate_journal(journal):
    if (journal.get("schema") != 1 or journal.get("host") != TARGET_HOST or
            journal.get("port") != TARGET_PORT or journal.get("iqn") != TARGET_IQN or
            journal.get("portal_created") is not True):
        raise RuntimeError("Exact owned loopback portal journal is required")
    uuid.UUID(journal["owner"])
    if journal.get("portal_initiator_instance") != "" or journal.get("portal_initiator_address") != "":
        raise RuntimeError("This helper supports only the journaled unbound initiator source")


def require_no_sessions(session_query):
    report = session_query()
    if (report.get("api") != "GetIScsiSessionListW" or report.get("ok") is not True or
            report.get("status") != 0 or report.get("count") != 0):
        raise RuntimeError("Native session report does not establish zero sessions")
    return report


def remove_owned(journal, api, session_query, audit=None):
    validate_journal(journal)
    sessions = require_no_sessions(session_query)
    before = api.report()
    if audit:
        audit("before_owned_portal_cleanup", {"owner": journal["owner"], "host": TARGET_HOST,
              "port": TARGET_PORT, "native_sessions": sessions, "count": len(before), "portals": before})
    matches = [record for record in before if is_endpoint(record)]
    if len(matches) > 1:
        raise RuntimeError("Multiple matching loopback portals; ownership is ambiguous")
    result = {"schema": 1, "owner": journal["owner"], "host": TARGET_HOST,
              "port": TARGET_PORT, "iqn": TARGET_IQN, "native_sessions": sessions,
              "before_count": len(before), "before_portals": before, "remove_status": None}
    if matches:
        record = matches[0]
        if record["InitiatorName"] != "" or record["InitiatorPortNumber"] != ANY_INITIATOR_PORT:
            raise RuntimeError("Native portal source binding differs from the journaled unbound source: "
                               + json.dumps(record))
        # Recheck immediately before the one permitted mutation.
        require_no_sessions(session_query)
        result["record"] = record
        result["remove_status"] = api.remove(record)
    after = api.report()
    if any(is_endpoint(record) for record in after):
        raise RuntimeError("Exact loopback portal still present after native cleanup: " + json.dumps(result))
    expected_other = identities(record for record in before if not is_endpoint(record))
    if identities(after) != expected_other:
        raise RuntimeError("Other portal configuration changed concurrently; cleanup cannot be certified")
    require_no_sessions(session_query)
    result.update(ok=True, absent=True, after_count=len(after),
                  action="removed" if matches and result["remove_status"] == 0 else "already_absent")
    # A nonzero API status is not itself success. The authoritative repeat report
    # above proves absence; preserve the status so concurrent disappearance is visible.
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remove", action="store_true", help="Remove only the exact journal-owned portal")
    args = parser.parse_args()
    api = NativePortals()
    if args.remove:
        journal = json.loads(JOURNAL.read_text(encoding="utf-8-sig"))
        def audit(event, data):
            with AUDIT_LOG.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"time_utc": datetime.now(timezone.utc).isoformat(),
                                        "event": event, "data": data}) + "\n")
        result = remove_owned(journal, api, lambda: native_report("sessions"), audit)
        audit("owned_portal_cleanup_result", result)
    else:
        records = api.report()
        result = {"schema": 1, "ok": True, "read_only": True, "count": len(records), "portals": records}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1)
