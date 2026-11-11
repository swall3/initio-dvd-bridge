"""Read-only local Windows iSCSI inventory; never starts a service or refreshes discovery.

Only query access is requested. Native reports return counts (not login secrets).
The registry fallback is grounded in the installed Microsoft iscsi.inf AddReg
section and the discovery paths embedded in iscsidsc.dll/iscsiexe.dll. Unknown
layouts, denied reads, saved targets, discovery configuration, or native reports
contradicting an empty registry fail the start guard.
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import winreg

TARGET_IQN = "iqn.2026-11.local.codex:initio-dvd"
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 32610
CLASS_ROOT = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e97b-e325-11ce-bfc1-08002be10318}"
DISCOVERY_ROOT = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\iSCSI"
REG_ACCESS = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
LIMIT = 8 * 1024 * 1024


def error(exc):
    return {"ok": False, "error": str(exc), "winerror": getattr(exc, "winerror", None)}


def service_status():
    class Status(C.Structure):
        _fields_ = [(n, W.DWORD) for n in (
            "service_type", "state_code", "controls_accepted", "win32_exit_code",
            "service_exit_code", "checkpoint", "wait_hint", "pid", "flags")]
    dll = C.WinDLL("advapi32", use_last_error=True)
    dll.OpenSCManagerW.argtypes = [W.LPCWSTR, W.LPCWSTR, W.DWORD]
    dll.OpenSCManagerW.restype = W.HANDLE
    dll.OpenServiceW.argtypes = [W.HANDLE, W.LPCWSTR, W.DWORD]
    dll.OpenServiceW.restype = W.HANDLE
    dll.QueryServiceStatusEx.argtypes = [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)]
    dll.QueryServiceStatusEx.restype = W.BOOL
    dll.CloseServiceHandle.argtypes = [W.HANDLE]
    scm = dll.OpenSCManagerW(None, None, 1)  # SC_MANAGER_CONNECT only
    if not scm:
        return error(C.WinError(C.get_last_error()))
    service = None
    try:
        service = dll.OpenServiceW(scm, "MSiSCSI", 4)  # SERVICE_QUERY_STATUS only
        if not service:
            raise C.WinError(C.get_last_error())
        status, needed = Status(), W.DWORD()
        if not dll.QueryServiceStatusEx(service, 0, C.byref(status), C.sizeof(status), C.byref(needed)):
            raise C.WinError(C.get_last_error())
        result = {"ok": True, **{n: getattr(status, n) for n, _ in Status._fields_}}
        result["state"] = {1: "Stopped", 2: "StartPending", 3: "StopPending", 4: "Running",
                           5: "ContinuePending", 6: "PausePending", 7: "Paused"}.get(status.state_code, "Unknown")
        return result
    except OSError as exc:
        return error(exc)
    finally:
        if service:
            dll.CloseServiceHandle(service)
        dll.CloseServiceHandle(scm)


def reg_summary(path, recurse=False, depth=0):
    """Record names/counts only, except whether the default value is empty."""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, REG_ACCESS) as key:
            children, values, stamp = winreg.QueryInfoKey(key)
            names, nonempty = [], []
            for i in range(values):
                name, value, kind = winreg.EnumValue(key, i)
                names.append(name)
                # An empty unnamed value is created by the Microsoft INF.
                if not (name == "" and kind == winreg.REG_SZ and value == ""):
                    nonempty.append(name)
            child_names = [winreg.EnumKey(key, i) for i in range(children)]
        result = {"ok": True, "path": path, "exists": True, "subkeys": child_names,
                  "value_names": names, "nonempty_value_names": nonempty,
                  "last_write": stamp, "empty": not children and not nonempty}
        if recurse:
            if depth >= 5 and children:
                result.update(ok=False, error="Registry tree exceeds bounded depth")
            else:
                result["children"] = [reg_summary(path + "\\" + n, True, depth + 1) for n in child_names]
                result["ok"] = all(c["ok"] for c in result["children"])
        return result
    except FileNotFoundError:
        return {"ok": True, "path": path, "exists": False, "empty": True,
                "subkeys": [], "value_names": [], "nonempty_value_names": []}
    except OSError as exc:
        return {"path": path, **error(exc)}


def reg_value(path, name):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, REG_ACCESS) as key:
            return winreg.QueryValueEx(key, name)[0]
    except FileNotFoundError:
        return None


def registry_inventory():
    result = {"ok": False, "adapters": [], "adapter_instance_keys_scanned": [], "errors": []}
    try:
        # Read ALL SCSI adapter instance keys, not a guessed instance number.
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, CLASS_ROOT, 0, REG_ACCESS) as key:
            names = [winreg.EnumKey(key, i) for i in range(winreg.QueryInfoKey(key)[0])]
        for name in names:
            if not name.isdigit():
                continue
            result["adapter_instance_keys_scanned"].append(name)
            path = CLASS_ROOT + "\\" + name
            match = reg_value(path, "MatchingDeviceId")
            desc = reg_value(path, "DriverDesc")
            inf = reg_value(path, "InfPath")
            persistent = reg_summary(path + r"\PersistentTargets", recurse=True)
            microsoft = str(match).lower() == r"root\iscsiprt" and str(inf).lower() == "iscsi.inf"
            if microsoft or persistent.get("exists") or not persistent["ok"]:
                result["adapters"].append({"path": path, "matching_device_id": match,
                    "driver_description": desc, "inf": inf, "microsoft": microsoft,
                    "persistent_targets": persistent})
        # Existence and instance names suffice here; protected per-device
        # Properties keys contain no PersistentTargets and are not traversed.
        result["root_iscsiprt"] = reg_summary(r"SYSTEM\CurrentControlSet\Enum\ROOT\ISCSIPRT")
        result["discovery"] = reg_summary(DISCOVERY_ROOT, recurse=True)
        result["service_parameters"] = reg_summary(r"SYSTEM\CurrentControlSet\Services\MSiSCSI\Parameters")
        result["driver_parameters"] = reg_summary(r"SYSTEM\CurrentControlSet\Services\iScsiPrt\Parameters")
        result["start_type"] = reg_value(r"SYSTEM\CurrentControlSet\Services\MSiSCSI", "Start")
        # These are source evidence, not guessed registry locations.
        system = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        inf_path = system / "INF" / "iscsi.inf"
        inf_bytes = inf_path.read_bytes()
        inf_text = inf_bytes.decode("utf-16" if inf_bytes.startswith(b"\xff\xfe") else "utf-8-sig")
        result["installed_inf"] = {"path": str(inf_path), "sha256": hashlib.sha256(inf_bytes).hexdigest(),
            "persistent_targets_addreg": "HKR,PersistentTargets" in inf_text,
            "root_iscsiprt": r"Root\iSCSIPrt".lower() in inf_text.lower()}
        result["ok"] = (all(a["persistent_targets"]["ok"] for a in result["adapters"])
                        and result["discovery"]["ok"] and result["root_iscsiprt"]["ok"])
    except (OSError, UnicodeError) as exc:
        result["errors"].append(error(exc))
    return result


def native_count_report(name, invoke, count, size):
    """Bound a native count/buffer query and retain every returned diagnostic.

    ERROR_INSUFFICIENT_BUFFER with zero size is not evidence of an empty list.
    Try a non-null, one-byte buffer when both returned size and count are zero;
    only an actual successful call establishes the authoritative count.
    """
    attempts = []
    buf = None
    problem = None
    for attempt in range(4):
        capacity = 0 if buf is None else C.sizeof(buf)
        status = int(invoke(buf))
        attempts.append({"status": status, "size_bytes": size.value,
                         "reported_count": count.value, "buffer_bytes": capacity})
        if status != 122:
            if status == 0 and count.value and (not capacity or not size.value):
                problem = "Successful nonempty report did not provide a data buffer"
            elif status == 0 and capacity and size.value > capacity:
                problem = "Successful report exceeded the supplied data buffer"
            break
        if attempt == 3:
            problem = "Native output buffer did not stabilize within bounded retries"
            break
        if size.value > LIMIT or (size.value == 0 and count.value != 0):
            problem = "Invalid native output buffer size"
            break
        # Some empty-list implementations reject NULL even when required size
        # is zero. Supply a valid pointer rather than accepting status122 as empty.
        capacity = max(1, size.value)
        buf = C.create_string_buffer(capacity)
        size.value = capacity
    result = {"api": name, "ok": status == 0 and problem is None,
              "status": status, "status_hex": hex(status),
              "count": count.value if status == 0 and problem is None else None,
              "reported_count": count.value, "size_bytes": size.value,
              "attempts": attempts}
    if problem:
        result["error"] = problem
    return result


def native_report(kind):
    """Documented read APIs only; no refresh, login, or service-control call."""
    dll = C.WinDLL("iscsidsc.dll")
    count, size = W.ULONG(0), W.ULONG(0)
    if kind in ("persistent_logins", "sessions"):
        name = "ReportIScsiPersistentLoginsW" if kind == "persistent_logins" else "GetIScsiSessionListW"
        fn = getattr(dll, name)
        fn.restype = W.ULONG
        if kind == "persistent_logins":
            fn.argtypes = [C.POINTER(W.ULONG), C.c_void_p, C.POINTER(W.ULONG)]
            invoke = lambda buf: fn(C.byref(count), buf, C.byref(size))
        else:
            fn.argtypes = [C.POINTER(W.ULONG), C.POINTER(W.ULONG), C.c_void_p]
            invoke = lambda buf: fn(C.byref(size), C.byref(count), buf)
        return native_count_report(name, invoke, count, size)
    if kind == "portals":
        # Only count is needed for the refusal guard. Avoid parsing credential-bearing options.
        fn = dll.ReportIScsiSendTargetPortalsW
        fn.argtypes = [C.POINTER(W.ULONG), C.c_void_p]
        fn.restype = W.ULONG
        status = int(fn(C.byref(count), None))
        if status == 122 and count.value:
            return {"api": "ReportIScsiSendTargetPortalsW", "ok": True, "status": status,
                    "count": count.value, "nonempty_count_query": True}
        return {"api": "ReportIScsiSendTargetPortalsW", "ok": status == 0, "status": status,
                "status_hex": hex(status), "count": count.value if status == 0 else None}
    name = {"isns": "ReportISNSServerListW", "persistent_devices": "ReportPersistentIScsiDevicesW"}[kind]
    fn = getattr(dll, name)
    fn.argtypes = [C.POINTER(W.ULONG), C.c_void_p]
    fn.restype = W.ULONG
    status = int(fn(C.byref(size), None))
    buf = None
    for _ in range(3):
        if status != 122:
            break
        if not 0 < size.value <= LIMIT // 2:
            raise ValueError("Invalid native string buffer size")
        buf = C.create_unicode_buffer(size.value)
        status = int(fn(C.byref(size), buf))
    items = [v for v in buf[:].split("\0") if v] if status == 0 and buf is not None else []
    return {"api": name, "ok": status == 0, "status": status, "status_hex": hex(status),
            "count": len(items) if status == 0 else None, "items": items}


def empty_discovery_containers(node):
    """Allow only the observed value-free Microsoft discovery scaffolding.

    Report calls create Send Targets; starting MSiSCSI additionally created the
    other four named empty containers in the 2026-11-11 03:36:37 UTC inventory.
    Unknown child names, values (even empty/default values), unreadable nodes,
    or incomplete child snapshots are not an empty configuration.
    """
    root = DISCOVERY_ROOT.casefold()
    empty_leaves = {"authentication cache", "grouppolicy", "send targets",
                    "static targets", "tunnel address"}
    permitted = {root: {"discovery"}, root + r"\discovery": empty_leaves,
                 **{root + "\\discovery\\" + name: set() for name in empty_leaves}}
    path = str(node.get("path", "")).casefold()
    if path not in permitted or not node.get("ok") or node.get("value_names") != []:
        return False
    names = node.get("subkeys")
    children = node.get("children", [])
    if not isinstance(names, list) or not isinstance(children, list):
        return False
    if not all(isinstance(name, str) for name in names):
        return False
    folded = [name.casefold() for name in names]
    if len(set(folded)) != len(folded) or not set(folded) <= permitted[path]:
        return False
    if node.get("exists") is False:
        return not names and not children
    if node.get("exists") is not True or len(children) != len(names):
        return False
    expected = {path + "\\" + name for name in folded}
    if {str(child.get("path", "")).casefold() for child in children} != expected:
        return False
    return all(empty_discovery_containers(child) for child in children)


def evaluate_start_guard(service, registry, reports):
    reasons = []
    if not service.get("ok") or service.get("state") not in ("Stopped", "Running"):
        reasons.append("Service state is inaccessible or transitional")
    if registry.get("start_type") == 4:
        reasons.append("MSiSCSI is disabled; startup type will not be changed")
    saved = ("persistent_logins", "portals", "isns", "persistent_devices")
    if any(reports[k].get("ok") and reports[k].get("count") != 0 for k in saved):
        reasons.append("Native report found saved targets, portals, iSNS, or persistent devices")
    if any(not reports[k].get("ok") and reports[k].get("reported_count", 0) > 0 for k in saved):
        reasons.append("Incomplete native report indicated nonzero saved configuration")
    adapters = registry.get("adapters", [])
    if any(a["persistent_targets"].get("ok") and not a["persistent_targets"].get("empty") for a in adapters):
        reasons.append("Registry contains adapter-specific persistent targets")
    discovery = registry.get("discovery", {})
    discovery_empty = empty_discovery_containers(discovery)
    if discovery.get("ok") and not discovery_empty:
        reasons.append("Registry discovery tree contains values, unknown containers, or incomplete entries")
    # Known installed Microsoft layout, readable exact target containers, and NO
    # discovery root configuration establish a usable pre-service fallback.
    inf = registry.get("installed_inf", {})
    software_adapter_accounted = (any(a["microsoft"] for a in adapters)
                                  or registry.get("root_iscsiprt", {}).get("exists") is False)
    fallback = (registry.get("ok") and inf.get("persistent_targets_addreg") and inf.get("root_iscsiprt")
                and software_adapter_accounted
                and all(a["persistent_targets"].get("empty") for a in adapters)
                and discovery_empty)
    native_empty = all(reports[k].get("ok") and reports[k].get("count") == 0 for k in saved)
    if not (native_empty or fallback):
        reasons.append("Neither complete native reports nor verified empty registry layout establishes no saved configuration")
    if reports["sessions"].get("ok") and reports["sessions"].get("count") != 0:
        reasons.append("Existing iSCSI sessions are present")
    # A running service must provide authoritative live session information.
    if service.get("state") == "Running" and not reports["sessions"].get("ok"):
        reasons.append("Live sessions could not be read")
    return {"allowed": not reasons, "reasons": reasons,
            "evidence": "native_empty" if native_empty else "registry_empty" if fallback else "insufficient",
            "scope": "No concurrent administrator changes; recheck immediately before start"}


def collect():
    before = service_status()
    registry = registry_inventory()
    reports = {}
    for kind in ("persistent_logins", "sessions", "portals", "isns", "persistent_devices"):
        try:
            # Bound RPC queries independently; subprocess has no start/login code.
            proc = subprocess.run([sys.executable, __file__, "--native", kind],
                                  capture_output=True, text=True, timeout=4, check=False)
            reports[kind] = json.loads(proc.stdout) if proc.returncode == 0 else {"ok": False, "error": proc.stderr.strip()}
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            reports[kind] = error(exc)
    after = service_status()
    guard = evaluate_start_guard(before, registry, reports)
    if before != after:
        guard["allowed"] = False
        guard["reasons"].append("Service changed during inventory; snapshot is not stable")
    return {"schema": 1, "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target": {"host": TARGET_HOST, "port": TARGET_PORT, "iqn": TARGET_IQN},
            "service_before": before, "service_after": after, "registry": registry,
            "native_reports": reports, "start_guard": guard, "read_only": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional JSON report path")
    parser.add_argument("--native", choices=("persistent_logins", "sessions", "portals", "isns", "persistent_devices"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    report = native_report(args.native) if args.native else collect()
    encoded = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)


if __name__ == "__main__":
    main()
