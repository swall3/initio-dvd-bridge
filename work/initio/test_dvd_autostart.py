"""Offline arrival/removal tests; no native calls, hardware or process launches."""
import unittest
from unittest.mock import patch, Mock
from types import SimpleNamespace
import dvd_autostart as watcher
from dvd_autostart import ConnectionPolicy


class AutostartPolicyTests(unittest.TestCase):
    def step(self, policy, now, present=True, started=True, busy=False):
        return policy.step(now, present=present, started=started, busy=busy)

    def test_waits_for_stable_ready_attachment_then_once_only(self):
        p = ConnectionPolicy()
        self.assertEqual(self.step(p, 0), 'settling')
        self.assertEqual(self.step(p, 3.99), 'settling')
        self.assertEqual(self.step(p, 4), 'launch')
        self.assertEqual(self.step(p, 30), 'waiting_for_reconnect')

    def test_existing_playback_never_gets_restarted_after_manual_stop(self):
        p = ConnectionPolicy()
        self.assertEqual(self.step(p, 0, busy=True), 'runtime_active')
        self.assertEqual(self.step(p, 20, busy=True), 'runtime_active')
        self.assertEqual(self.step(p, 40), 'waiting_for_reconnect')

    def test_failed_start_does_not_loop(self):
        p = ConnectionPolicy()
        self.step(p, 0)
        self.assertEqual(self.step(p, 4), 'launch')
        self.step(p, 5, busy=True)
        self.assertEqual(self.step(p, 90), 'waiting_for_reconnect')

    def test_confirmed_unplug_rearms_exactly_one_new_attempt(self):
        p = ConnectionPolicy(consumed=True)
        self.step(p, 0, present=False, started=False)
        self.step(p, 4, present=False, started=False)
        self.assertEqual(self.step(p, 6), 'settling')
        self.assertEqual(self.step(p, 10), 'launch')
        self.assertEqual(self.step(p, 20), 'waiting_for_reconnect')

    def test_short_disappearance_does_not_rearm(self):
        p = ConnectionPolicy(consumed=True)
        self.step(p, 0, present=False)
        self.assertEqual(self.step(p, 3), 'waiting_for_reconnect')

    def test_problem_code_is_not_an_unplug(self):
        p = ConnectionPolicy(consumed=True)
        self.step(p, 0, started=False)
        self.step(p, 60, started=False)
        self.assertEqual(self.step(p, 80), 'waiting_for_reconnect')

    def test_waits_for_started_device_and_resets_settle_time(self):
        p = ConnectionPolicy()
        self.assertEqual(self.step(p, 0, started=False), 'waiting_for_device_start')
        self.step(p, 4)
        self.step(p, 6, started=False)
        self.assertEqual(self.step(p, 8), 'settling')
        self.assertEqual(self.step(p, 12), 'launch')

    def test_old_cleanup_blocks_new_runtime_even_after_replug(self):
        p = ConnectionPolicy(consumed=True)
        self.step(p, 0, present=False, busy=True)
        self.step(p, 4, present=False, busy=True)
        self.assertEqual(self.step(p, 6, busy=True), 'waiting_for_previous_cleanup')
        self.assertEqual(self.step(p, 20), 'settling')
        self.assertEqual(self.step(p, 24), 'launch')

    def test_discovery_errors_break_debounce_without_rearming(self):
        p = ConnectionPolicy(consumed=True)
        self.step(p, 0, present=False)
        p.interrupted()
        self.step(p, 60, present=False)
        self.assertTrue(p.consumed)
        self.assertEqual(self.step(p, 62), 'waiting_for_reconnect')


class WatcherWiringTests(unittest.TestCase):
    def run_mocked(self, busy, disk_error=None):
        child = Mock(pid=123)
        child.poll.return_value = None
        kernel = Mock()
        kernel.CreateMutexW.return_value = 456
        stop = SimpleNamespace(exists=Mock(side_effect=[False, False, False, True]))
        native = SimpleNamespace(windll=SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda: True)),
                                 get_last_error=lambda: 0)
        device = {'present': True, 'started': True, 'instance': 'offline-exact-device'}
        with patch.object(watcher, 'C', native), \
             patch.object(watcher, 'kernel_api', return_value=kernel), \
             patch.object(watcher, 'mutex_exists', return_value=busy), \
             patch.object(watcher, 'STOP', stop), \
             patch.object(watcher, 'emit') as events, \
             patch.object(watcher, 'write_status') as statuses, \
             patch.object(watcher, 'read_runtime', return_value={'status': 'ready'}), \
             patch.object(watcher, 'launch_runtime', return_value=child) as launch, \
             patch.object(watcher.os, 'chdir'), \
             patch.object(watcher.time, 'sleep'), \
             patch.object(watcher.time, 'monotonic', side_effect=[0, 4, 6]), \
             patch.object(watcher.sys, 'argv', ['dvd_autostart.py']), \
             patch('dvd_device_identity.exact_device_status', return_value=device), \
             patch('dvd_device_identity.discover_disk_interface', side_effect=disk_error):
            watcher.main()
        return child, launch, statuses, kernel

    def test_installed_watcher_observes_current_playback_without_new_process(self):
        child, launch, statuses, kernel = self.run_mocked(True)
        launch.assert_not_called()
        self.assertEqual(statuses.call_args_list[0].args[0], 'runtime_active')
        self.assertEqual(statuses.call_args_list[-1].args[0], 'disabled')
        kernel.ReleaseMutex.assert_called_once_with(456)

    def test_launches_once_and_disabling_never_terminates_playing_child(self):
        child, launch, statuses, kernel = self.run_mocked(False)
        launch.assert_called_once_with()
        child.terminate.assert_not_called()
        child.kill.assert_not_called()
        self.assertEqual([c.args[0] for c in statuses.call_args_list],
                         ['settling', 'runtime_starting', 'runtime_active', 'disabled'])

    def test_usb_arrival_waits_for_disk_child_without_launching(self):
        child, launch, statuses, kernel = self.run_mocked(False, RuntimeError('disk child not ready'))
        launch.assert_not_called()
        self.assertEqual([c.args[0] for c in statuses.call_args_list],
                         ['settling', 'watch_error', 'settling', 'disabled'])
        self.assertFalse(statuses.call_args_list[2].kwargs['attempted_this_connection'])


if __name__ == '__main__':
    unittest.main()
