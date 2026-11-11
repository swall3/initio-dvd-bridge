"""Show the native UAC prompt for the prepared, DVD-only runtime."""
from pathlib import Path
import os
import sys
base=Path(__file__).resolve().parents[2]
os.chdir(base)
p=(base/'work/initio/elevate_restart.py').read_text().replace('work/initio/recover_failed_node.py','work/initio/dvd_bridge_runtime.py')
p=p.replace('e.nShow=0','e.nShow=0\nu=C.WinDLL("user32");u.GetForegroundWindow.restype=W.HWND\ne.hwnd=u.GetForegroundWindow()')
# Only the fixed CLI switches below may reach the elevated command line.
if sys.argv[1:]==['--no-media']:
    p=p.replace("e.lpDirectory=str(Path.cwd())", "e.lpParameters += ' --no-media --seconds 45'\ne.lpDirectory=str(Path.cwd())")
elif sys.argv[1:]:
    raise SystemExit('Only --no-media is supported by this launcher')
exec(compile(p,'dvd_bridge_launcher','exec'))
