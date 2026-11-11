"""Offline runtime wiring checks: all native/device/network operations mocked."""
from contextlib import ExitStack
import base64
import json
import ctypes
from pathlib import Path
import runpy
import subprocess
import tempfile
import threading
import types
import unittest
from unittest.mock import Mock, patch

import dvd_bridge_runtime as runtime


class RuntimeTests(unittest.TestCase):
    def run_mocked(self, *, no_media=False, listener_error=False,
                   connect_error=False, clients_done=True, readable=True,
                   terminal_reader_error=False):
        events=[]
        instances={}
        fake_admin=types.SimpleNamespace(windll=types.SimpleNamespace(
            shell32=types.SimpleNamespace(IsUserAnAdmin=lambda:1)))

        class FakeReader:
            def __init__(self, chunk_blocks):
                events.append(('reader_open',chunk_blocks))
                self.chunk_blocks=chunk_blocks
                self.info={'blocks':100,'block_size':2048}
                self.error=None
                self.stop_event=threading.Event()
                self.css_feature=None
                instances['reader']=self
            def auth_command(self,*args,**kwargs):
                raise AssertionError('Runtime tests do not send authentication commands')
            def read_blocks(self,lba,blocks):
                events.append(('read',lba,blocks,self.chunk_blocks))
                return b''.join(bytes([n&255])*2048 for n in range(lba,lba+blocks))
            def close(self):
                events.append(('reader_close',))

        class FakeServer:
            def __init__(self,backend,emit):
                events.append(('server_construct',backend))
                instances['lun']=backend
                self.emit=emit
                self.stopped=threading.Event()
                self.join_results=iter([True] if clients_done else [False,False,True])
            def serve_forever(self):
                if listener_error:
                    raise RuntimeError('mock bind failed')
                events.append(('server_listening',))
                self.emit('listening',address='127.0.0.1',port=32610)
                self.stopped.wait(3)
            def stop(self):
                events.append(('server_stop',))
                self.stopped.set()
            def join_clients(self,timeout=30):
                done=next(self.join_results,True)
                events.append(('clients_join',timeout,done))
                return done

        workspace=Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(prefix='dvd-runtime-offline-',dir=workspace) as temp:
            out=Path(temp).resolve()
            if not out.is_relative_to(workspace):
                raise AssertionError('Test output must remain inside its workspace')
            def fake_powershell(script,*args):
                events.append(('powershell',script,args))
                if script=='verify_virtual_dvd.ps1':
                    (out/'stop.request').write_text('offline test stop')
                    return json.dumps({'devices':[{'readable':readable,'name':'mock optical'}],
                                       'verification_complete':7})
                if args==('-Action','Connect') and connect_error:
                    raise RuntimeError('mock connect failed')
                if args==('-Action','Connect') and terminal_reader_error:
                    instances['reader'].error=RuntimeError('mock terminal reader failure')
                    instances['reader'].stop_event.set()
                if args==('-Action','Cleanup') and terminal_reader_error:
                    lun=instances['lun']
                    # Exercise the same virtual commands Windows was retrying
                    # while logout was blocked, before the target is stopped.
                    responses=[lun.execute(bytes(6),0,'none'),
                               lun.execute(bytes.fromhex('28000000000000000100'),2048,'in'),
                               lun.execute(bytes.fromhex('25000000000000000000'),8,'in')]
                    events.append(('media_at_cleanup',lun.media_present,
                                   [(r.status,r.sense[2],r.sense[12],r.sense[13])
                                    for r in responses]))
                return '{}'
            fake_modules={
                'iscsi_windows_inventory':types.SimpleNamespace(collect=lambda:{'start_guard':{'allowed':True}}),
                'live_usb_reader':types.SimpleNamespace(LiveUsbReader=FakeReader),
            }
            with ExitStack() as stack:
                stack.enter_context(patch.dict('sys.modules',fake_modules))
                stack.enter_context(patch('iscsi_target.TargetServer',FakeServer))
                stack.enter_context(patch.object(runtime,'ctypes',fake_admin))
                stack.enter_context(patch.object(runtime,'powershell',fake_powershell))
                stack.enter_context(patch.object(runtime.os,'chdir'))
                stack.enter_context(patch.object(runtime.time,'sleep'))
                stack.enter_context(patch('socket.socket',side_effect=AssertionError('No sockets in offline tests')))
                stack.enter_context(patch('subprocess.run',side_effect=AssertionError('No processes in offline tests')))
                stack.enter_context(patch('sys.argv',['dvd_bridge_runtime.py']+(['--no-media'] if no_media else [])))
                for name,path in {'OUT':out,'LOG':out/'runtime.jsonl','STATE':out/'state.json',
                                  'STOP':out/'stop.request'}.items():
                    stack.enter_context(patch.object(runtime,name,path))
                error=None
                try:
                    runtime.main()
                except RuntimeError as exc:
                    error=str(exc)
                state=json.loads((out/'state.json').read_text())
                logs=[json.loads(line) for line in (out/'runtime.jsonl').read_text().splitlines()]
        return events,state,logs,error

    def test_physical_wiring_calibrates_and_orders_cleanup(self):
        events,state,logs,error=self.run_mocked()
        self.assertIsNone(error)
        self.assertEqual(state['status'],'stopped')
        self.assertTrue(any(row.get('status')=='ready' for row in logs))
        self.assertEqual([row['blocks'] for row in logs if row['event']=='transfer_calibrated'],[2,4,8,16])
        cleanup=events.index(('powershell','iscsi_windows_session.ps1',('-Action','Cleanup')))
        self.assertLess(cleanup,events.index(('server_stop',)))
        self.assertLess(events.index(('clients_join',95,True)),events.index(('reader_close',)))
        self.assertTrue(next(row[1] for row in events if row[0]=='server_construct').media_present)

    def test_terminal_reader_failure_removes_virtual_media_before_cleanup(self):
        events,state,logs,error=self.run_mocked(terminal_reader_error=True)
        self.assertIn('mock terminal reader failure',error)
        self.assertEqual(state['status'],'stopped')
        self.assertIn(('media_at_cleanup',False,[(2,6,0x28,0),
                                               (2,2,0x3A,0),
                                               (2,2,0x3A,0)]),events)
        self.assertTrue(any(row['event']=='virtual_media_removed' for row in logs))
        self.assertIn(('reader_close',),events)

    def test_no_media_never_constructs_physical_reader(self):
        events,state,logs,error=self.run_mocked(no_media=True,readable=False)
        self.assertIsNone(error)
        self.assertEqual(state['status'],'stopped')
        self.assertFalse(any(row[0].startswith('reader') or row[0]=='read' for row in events))
        self.assertTrue(any(row.get('status')=='optical_interface_verified_no_media' for row in logs))
        self.assertFalse(any(row.get('status')=='ready' for row in logs))

    def test_listener_failure_does_not_connect_windows(self):
        events,state,logs,error=self.run_mocked(listener_error=True)
        self.assertIn('listener failed',error)
        self.assertFalse(any(row[0]=='powershell' for row in events))
        self.assertIn(('reader_close',),events)
        self.assertEqual(state['status'],'stopped')

    def test_connection_failure_still_uses_ordered_cleanup(self):
        events,state,logs,error=self.run_mocked(connect_error=True)
        self.assertEqual(error,'mock connect failed')
        self.assertIn(('powershell','iscsi_windows_session.ps1',('-Action','Cleanup')),events)
        self.assertIn(('reader_close',),events)
        self.assertEqual(state['status'],'stopped')

    def test_active_client_prevents_backend_close(self):
        events,state,logs,error=self.run_mocked(clients_done=False)
        self.assertIsNone(error)
        self.assertEqual(state['status'],'stopped')
        self.assertTrue(any(row.get('status')=='cleanup_incomplete' for row in logs))
        self.assertLess(events.index(('clients_join',5,True)),events.index(('reader_close',)))

    def test_launcher_builds_fixed_hidden_runtime_command_without_native_calls(self):
        captured=[]
        class Function:
            def __init__(self,callback):self.callback=callback
            def __call__(self,*args):return self.callback(*args)
        def shell_execute(pointer):
            info=pointer._obj
            captured.append(dict(verb=info.lpVerb,parameters=info.lpParameters,
                                 directory=info.lpDirectory,show=info.nShow,owner=info.hwnd))
            info.hProcess=1234
            return True
        libraries={
            'shell32':types.SimpleNamespace(ShellExecuteExW=Function(shell_execute)),
            'kernel32':types.SimpleNamespace(WaitForSingleObject=Function(lambda *a:258),
                                             CloseHandle=Function(lambda *a:True)),
            'user32':types.SimpleNamespace(GetForegroundWindow=Function(lambda:5678)),
        }
        launcher=Path(runtime.__file__).with_name('launch_dvd_bridge.py')
        for switches in ([],['--no-media']):
            with patch.object(ctypes,'WinDLL',side_effect=lambda name,**kw:libraries[name]), \
                 patch.object(runtime.os,'chdir'),patch('sys.argv',[str(launcher),*switches]), \
                 patch('builtins.print'):
                runpy.run_path(str(launcher),run_name='__main__')
            record=captured[-1]
            self.assertEqual(record['verb'],'runas')
            self.assertEqual(record['show'],0)
            self.assertEqual(record['owner'],5678)
            self.assertIn('dvd_bridge_runtime.py',record['parameters'])
            self.assertNotIn('recover_failed_node.py',record['parameters'])
            self.assertEqual('--no-media --seconds 45' in record['parameters'],bool(switches))


class StaleRuntimeTests(unittest.TestCase):
    def reconcile(self, previous, journal, *, exited=True, allowed=True, cleanup_error=False):
        events=[]
        with tempfile.TemporaryDirectory(prefix='dvd-stale-offline-',dir=Path(__file__).parent) as temp:
            out=Path(temp)
            state=out/'state.json'
            if previous is not None:
                state.write_text(json.dumps(previous))
            if journal is not None:
                (out/'iscsi-windows-session.json').write_text(json.dumps(journal))
            stop=out/'stop.request'
            stop.write_text('preserve manual stop')
            def cleanup(*args):
                events.append(('cleanup',args))
                if cleanup_error:
                    raise RuntimeError('cleanup refused')
            def collect():
                events.append(('inventory',))
                return {'start_guard':{'allowed':allowed}}
            with patch.object(runtime,'OUT',out), patch.object(runtime,'STATE',state), \
                 patch.object(runtime,'STOP',stop), patch.object(runtime,'LOG',out/'log.jsonl'), \
                 patch.object(runtime,'process_has_exited',side_effect=exited if isinstance(exited,Exception) else None,
                              return_value=exited) as owner, \
                 patch.object(runtime,'powershell',side_effect=cleanup):
                problem=None
                try:
                    runtime.reconcile_previous_runtime(collect)
                except RuntimeError as exc:
                    problem=str(exc)
                current=json.loads(state.read_text()) if state.exists() else None
                self.assertEqual(stop.read_text(),'preserve manual stop')
                return events,current,problem,owner.call_count

    def test_stale_ready_cleans_exact_journal_before_fresh_inventory(self):
        events,state,problem,calls=self.reconcile({'status':'ready','pid':123},{'status':'connected'})
        self.assertIsNone(problem)
        self.assertEqual(events,[('cleanup',('iscsi_windows_session.ps1','-Action','Cleanup')),('inventory',)])
        self.assertEqual(state['status'],'stopped')
        self.assertEqual(state['previous_pid'],123)
        self.assertTrue(state['reconciled_previous_cleanup'])
        self.assertEqual(calls,1)

    def test_active_or_unknown_owner_retains_state_without_cleanup(self):
        previous={'status':'ready','pid':123}
        for exited in (False,RuntimeError('access denied')):
            with self.subTest(exited=exited):
                events,state,problem,_=self.reconcile(previous,{'status':'connected'},exited=exited)
                self.assertTrue(problem)
                self.assertEqual(events,[])
                self.assertEqual(state,previous)

    def test_failed_cleanup_or_fresh_guard_retains_stale_evidence(self):
        previous={'status':'cleanup_incomplete','pid':123}
        for options in ({'cleanup_error':True},{'allowed':False}):
            with self.subTest(options=options):
                events,state,problem,_=self.reconcile(previous,{'status':'connected'},**options)
                self.assertTrue(problem)
                self.assertEqual(state,previous)
                self.assertEqual(events[0][0],'cleanup')
                self.assertEqual(len(events),1 if options.get('cleanup_error') else 2)

    def test_no_journal_or_clean_journal_needs_only_fresh_inventory(self):
        for journal in (None,{'status':'cleaned'}):
            with self.subTest(journal=journal):
                events,state,problem,_=self.reconcile({'status':'initializing','pid':123},journal)
                self.assertIsNone(problem)
                self.assertEqual(events,[('inventory',)])
                self.assertEqual(state['status'],'stopped')

    def test_clean_stop_does_not_depend_on_old_pid_reuse(self):
        previous={'status':'stopped','pid':123}
        events,state,problem,calls=self.reconcile(previous,{'status':'cleaned'},exited=False)
        self.assertIsNone(problem)
        self.assertEqual(events,[('inventory',)])
        self.assertEqual(state,previous)
        self.assertEqual(calls,0)

    def test_orphan_unclean_journal_and_unknown_status_fail_closed(self):
        for previous in (None,{'status':'unexpected','pid':123}):
            with self.subTest(previous=previous):
                events,state,problem,_=self.reconcile(previous,{'status':'connected'})
                self.assertTrue(problem)
                self.assertEqual(events,[])
                self.assertEqual(state,previous)

    def test_native_exit_probe_is_read_only_and_conservative(self):
        class Function:
            def __init__(self,result):self.mock=Mock(return_value=result)
            def __call__(self,*args):return self.mock(*args)
        for handle,error,wait,expected in ((None,87,None,True),(None,5,None,None),
                                           (77,0,0,True),(77,0,258,False),(77,0,0xffffffff,None)):
            with self.subTest(handle=handle,error=error,wait=wait):
                kernel=types.SimpleNamespace(OpenProcess=Function(handle),
                    WaitForSingleObject=Function(wait),CloseHandle=Function(True))
                with patch.object(ctypes,'WinDLL',return_value=kernel), \
                     patch.object(ctypes,'get_last_error',return_value=error):
                    if expected is None:
                        with self.assertRaises(RuntimeError):runtime.process_has_exited(123)
                    else:
                        self.assertIs(runtime.process_has_exited(123),expected)
                kernel.OpenProcess.mock.assert_called_once_with(0x00100000,False,123)
                if handle:
                    kernel.WaitForSingleObject.mock.assert_called_once_with(77,0)
                    kernel.CloseHandle.mock.assert_called_once_with(77)
                else:
                    kernel.WaitForSingleObject.mock.assert_not_called()
        for bad in (None,True,0,-1,'123',2**32):
            with self.subTest(pid=bad),patch.object(ctypes,'WinDLL') as native:
                with self.assertRaises(RuntimeError):runtime.process_has_exited(bad)
                native.assert_not_called()

    def test_powershell_reconciliation_with_all_external_operations_mocked(self):
        # Parse ONLY the function body: never dot-source or execute the helper's
        # top-level lifecycle. Every invoked external operation is a stub.
        helper=str(Path(runtime.__file__).with_name('iscsi_windows_session.ps1')).replace("'","''")
        harness=r'''
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null; $parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile('__HELPER__',[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { throw 'Helper syntax error' }
$fn=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-OwnedCleanup'},$false))
if ($fn.Count -ne 1) { throw 'Expected one cleanup function' }
Invoke-Expression $fn[0].Extent.Text
$TargetHost='127.0.0.1'; $TargetPort=32610; $TargetIqn='iqn.2026-11.local.codex:initio-dvd'
$PythonPath='NO_EXTERNAL_EXECUTION'; $OwnedPortalPath='NO_EXTERNAL_EXECUTION'
function Get-ServiceIdentity {
    $script:identityCalls++
    $state=if ($script:scenario -eq 'transition') {'Start Pending'} elseif ($script:scenario -eq 'generation') {'Running'} elseif ($script:scenario -eq 'raced' -and $script:identityCalls -gt 1) {'Running'} else {'Stopped'}
    return [pscustomobject]@{status=$state;pid=200;process_started_utc='new';start_mode='Manual'}
}
function Read-Inventory {
    $script:inventoryCalls++
    return [pscustomobject]@{
        start_guard=[pscustomobject]@{allowed=($script:scenario -ne 'refused')}
        service_before=[pscustomobject]@{state='Stopped'}; service_after=[pscustomobject]@{state='Stopped'}
        native_reports=[pscustomobject]@{sessions=[pscustomobject]@{ok=$false;count=$null;reported_count=$(if ($script:scenario -eq 'native_nonempty') {1} else {0})}}
    }
}
function Write-Log($event,$data) { $script:events+=@($event) }
function Save-State { $script:saves++ }
function Get-LiveSessions { return @() }
function Get-CleanupBlockingSessions { throw 'Unexpected live-session query' }
function Read-NativePortalInventory { throw 'Unexpected native portal query' }
function Disconnect-IscsiTarget { throw 'Unexpected disconnect' }
function Get-IscsiConnection { throw 'Unexpected connection query' }
function Stop-Service { throw 'Unexpected service stop' }
function Start-Service { throw 'Unexpected service start' }
function Get-Service { throw 'Unexpected service query' }
$results=@()
foreach ($case in @('stopped','refused','raced','native_nonempty','transition','generation')) {
    $script:scenario=$case; $script:identityCalls=0; $script:inventoryCalls=0; $script:saves=0; $script:events=@()
    $script:State=[pscustomobject]@{
        schema=1;host=$TargetHost;port=$TargetPort;iqn=$TargetIqn;status='connected';owner='offline'
        session_ids=@();portal_created=($case -ne 'generation');service_started=$true
        service_identity=[pscustomobject]@{pid=100;process_started_utc='old'}
    }
    if ($case -ne 'generation') {$script:State.session_ids=@('old-session')}
    $problem=$null
    try { Invoke-OwnedCleanup } catch { $problem=$_.Exception.Message }
    $results+=@([pscustomobject]@{case=$case;problem=$problem;state=$script:State;saves=$script:saves;events=$script:events;inventory_calls=$script:inventoryCalls})
}
ConvertTo-Json -InputObject $results -Depth 12 -Compress
'''.replace('__HELPER__',helper)
        encoded=base64.b64encode(harness.encode('utf-16le')).decode('ascii')
        result=subprocess.run([runtime.POWERSHELL,'-NoProfile','-NonInteractive','-EncodedCommand',encoded],
                              capture_output=True,text=True,timeout=30,creationflags=0x08000000)
        self.assertEqual(result.returncode,0,result.stderr)
        cases={case['case']:case for case in json.loads(result.stdout)}
        for name in ('stopped','generation'):
            case=cases[name]
            self.assertIsNone(case['problem'],case)
            self.assertEqual(case['state']['status'],'cleaned')
            self.assertEqual(case['state']['session_ids'],[])
            self.assertFalse(case['state']['portal_created'])
            self.assertFalse(case['state']['service_started'])
        self.assertIn('service_ownership_relinquished_generation_changed',cases['generation']['events'])
        self.assertEqual(cases['generation']['inventory_calls'],0)
        for name in ('refused','raced','native_nonempty','transition'):
            case=cases[name]
            self.assertTrue(case['problem'],case)
            self.assertEqual(case['state']['status'],'connected')
            self.assertEqual(case['state']['session_ids'],['old-session'])
            self.assertTrue(case['state']['portal_created'])
            self.assertTrue(case['state']['service_started'])
            self.assertEqual(case['saves'],0)


if __name__=='__main__':
    unittest.main()
