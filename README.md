# Initio DVD Bridge

Experimental Windows user-space bridge for an Initio USB controller that exposes a DVD drive as unusable USB mass storage. Uses the installed Microsoft USB, storage, CD-ROM, and iSCSI drivers. No custom kernel driver or persistent firmware image is installed.

**Early hardware-specific alpha.** The development prototype has played a protected DVD movie in VLC. This distributable has passed offline tests but has not yet completed a separate live installation, reconnect, reboot, sleep/resume, or full-movie qualification run. Do not infer compatibility from the Initio brand or USB ID alone.

## Supported configuration

- Windows x64, Windows PowerShell 5.1, and the built-in Microsoft iSCSI initiator.
- Observed USB VID `13FD`, PID `3910`, descriptor revision `0104`; INIC-3609 silicon, GU40N optical mechanism revision QX21.
- The current build deliberately retains the tested exact USB/USBSTOR identity and ROM-header guards. Other devices are refused. The zero-filled serial is not a globally unique identifier; this is not broad model support.
- A readable DVD must be inserted before startup. No automatic disc swapping, empty-drive insertion handling, burning, or audio-CD support.
- Existing iSCSI configuration can prevent startup. The bridge does not reset hubs/controllers or change network settings.

## Installation

Download the Windows ZIP from Releases, extract it, and run **Install.cmd**. Approve the Windows administrator prompt. The package includes an application-local Python runtime; no Python installation is needed. VLC is separate: install it from [VideoLAN](https://www.videolan.org/vlc/).

Installation creates `%LOCALAPPDATA%\Programs\InitioDvdBridge`, Start menu shortcuts, an Apps uninstall entry, and the current user's elevated scheduled task **Initio DVD Bridge Autostart**. The watcher starts at sign-in and checks only the exact device's PnP presence every two seconds. It starts an untimed bridge when the supported drive is connected. It never opens VLC automatically.

Insert a movie disc, connect the drive, and allow roughly 30–60 seconds. Open **DVD Controls** from the Start menu and click **Play DVD in VLC** when it says Ready. The app verifies the virtual drive identity before opening VLC. Drive letters can vary. A three-second disc cache was used in the successful prototype playback tests.

## Tray controls and audio

The tray app shows drive status and offers Play DVD, Start, cooperative Stop, automatic startup, VLC selection, and troubleshooting. It runs without administrator privileges; Start and startup-setting changes request Windows approval separately. Playback and volume controls stay in VLC. Closing or minimizing the controls hides the window; double-click the tray icon or open the shortcut again to restore it. **Exit tray** leaves the DVD utility running.

Use **Play audio / video files** to select music or videos, including MP3, FLAC, WAV, AAC and other formats supported by your VLC installation. DVD movie sound is also supported. **Physical audio CDs in the repaired drive are not supported in this release.** They require a separate raw-sector reading path; opening a music file is not evidence that CD playback works.

Setup registers the unelevated tray app at user sign-in, separately from the elevated device-arrival watcher. Choose a portable `vlc.exe` once if VLC is not installed in its usual location. VLC is not bundled. The tray app never opens media automatically.

Close VLC, use **Stop DVD**, and wait for `outputs/initio/dvd-bridge-runtime.json` to report `stopped` before changing media. Manual Stop stays stopped for that attachment. Unplug for at least six seconds and reconnect to rearm automatic startup, or use Start DVD manually. Errors are not retried indefinitely. The watcher waits for old cleanup instead of forcing another reader.

Run **Uninstall** from the Start menu or Windows Apps after stopping playback and the bridge. Removal disables the owned startup task and deletes only manifest-verified application files. Diagnostic logs and empty folders remain. Upgrades currently require uninstalling the previous alpha. Never install this package alongside a running development prototype; setup refuses active reader ownership.

## Development and validation

Use Windows Python 3.13: `python work/initio/run_dvd_offline_tests.py`. The explicit suite mocks hardware and lifecycle mutations. Do not discover and execute arbitrary historical probe scripts. Run `python build_release.py` to fetch the pinned official embeddable runtime, verify its SHA-256 and publisher signature, run the offline suite, and build the ZIP with a file manifest. `Setup.ps1 -Action Verify` verifies the package without installation or device I/O.

See [architecture](docs/architecture.md), [test status](docs/validation.md), and [third-party notices](THIRD_PARTY_NOTICES.md). Source is MIT licensed; the bundled CPython runtime retains its own license. Firmware dumps, movie data, DVD keys, VLC binaries, private machine logs, and personal paths are excluded.
