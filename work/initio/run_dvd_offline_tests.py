"""Run only the explicit offline prototype suites, without discovery of probes."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
names=['test_live_usb_reader','test_idle_tur_deadline','test_transport_command_error','test_physical_auth','test_auth_transport','test_optical_lun','test_optical_readahead','test_iscsi_target','test_dvd_bridge_runtime','test_dynamic_dvd_disk','test_dvd_autostart']
names.append('test_setup')
suite=unittest.defaultTestLoader.loadTestsFromNames(names)
result=unittest.TextTestRunner(verbosity=1).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
