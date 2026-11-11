import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import tray_backend as t


class TrayTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root=Path(self.temp.name).resolve()
        self.exe=self.root/'vlc.exe';self.exe.write_bytes(b'fake')
        self.song=self.root/'music & quoted song.wav';self.song.write_bytes(b'fake')
        self.state={'status':'ready','pid':123,'devices':[{'name':'CODEX USB DVD Bridge SCSI CdRom Device','readable':True,'drive':'G:'}]}
    def tearDown(self):self.temp.cleanup()
    def test_valid_ready_drive(self):self.assertEqual(t.select_drive(self.state),'G:')
    def test_unready_ambiguous_or_malformed_drive_rejected(self):
        for state in ({'status':'stopped'}, {**self.state,'devices':self.state['devices']*2},
                      {**self.state,'devices':[{**self.state['devices'][0],'drive':'E:\\data'}]}):
            with self.assertRaises(RuntimeError):t.select_drive(state)
    def test_audio_paths_are_literal_arguments(self):
        with patch.object(t,'find_vlc',return_value=self.exe):
            command=t.vlc_command(files=[str(self.song)])
        self.assertEqual(command[-2:],['--',str(self.song)])
        self.assertNotIn('--aout=dummy',command)
    def test_no_vlc_reports_actionable_error(self):
        with patch.object(t,'find_vlc',return_value=None):
            with self.assertRaisesRegex(RuntimeError,'Choose'):t.vlc_command(files=[str(self.song)])
    def test_remote_or_missing_media_rejected(self):
        with patch.object(t,'find_vlc',return_value=self.exe):
            for files in ([],['https://example.com/a.mp3'],[str(self.root/'missing')]):
                with self.assertRaises(RuntimeError):t.vlc_command(files=files)
    def test_stale_runtime_never_opens_dvd(self):
        with patch.object(t,'read_json',return_value=self.state),patch.object(t,'process_alive',return_value=False),patch.object(t.subprocess,'Popen') as launch:
            with self.assertRaises(RuntimeError):t.execute({'action':'play-disc'})
            launch.assert_not_called()
    def test_wrong_device_identity_never_opens_player(self):
        with patch.object(t,'read_json',return_value=self.state),patch.object(t,'process_alive',return_value=True),patch.object(t,'query_identity',return_value=(0,'Other','Disk')),patch.object(t.subprocess,'Popen') as launch:
            with self.assertRaises(RuntimeError):t.execute({'action':'play-disc'})
            launch.assert_not_called()
    def test_ready_dvd_opens_unelevated_player(self):
        with patch.object(t,'read_json',return_value=self.state),patch.object(t,'process_alive',return_value=True),patch.object(t,'query_identity',return_value=(5,'CODEX','USB DVD Bridge')),patch.object(t,'find_vlc',return_value=self.exe),patch.object(t.subprocess,'Popen') as launch:
            t.execute({'action':'play-disc'})
            self.assertEqual(launch.call_args.args[0][-1],'dvd:///G:/')
            self.assertFalse(launch.call_args.kwargs['shell'])
            self.assertEqual(launch.call_args.kwargs['creationflags'],0)
    def test_stop_only_writes_cooperative_request(self):
        with patch.object(t,'OUT',self.root),patch.object(t,'read_json',return_value=self.state),patch.object(t,'process_alive',return_value=True),patch.object(t.subprocess,'Popen') as launch:
            t.execute({'action':'stop'})
            self.assertTrue((self.root/'dvd-bridge-stop.request').exists())
            launch.assert_not_called()
    def test_settings_accept_only_explicit_vlc_executable(self):
        with patch.object(t,'OUT',self.root),patch.object(t,'CONFIG',self.root/'settings.json'):
            with self.assertRaises(ValueError):t.execute({'action':'set-vlc','path':str(self.song)})
            t.execute({'action':'set-vlc','path':str(self.exe)})
            self.assertEqual(json.loads((self.root/'settings.json').read_text())['vlc'],str(self.exe))
    def test_unknown_command_rejected(self):
        with self.assertRaises(ValueError):t.execute({'action':'run','command':'arbitrary'})
