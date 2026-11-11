# 0.1.0-alpha.2

Adds a native Windows system-tray app and small control window:

- Live DVD status, verified Play DVD in VLC, Start and cooperative Stop.
- Automatic-startup toggle, VLC selection, and readable troubleshooting details.
- Audio/video file picker with literal file arguments and unelevated VLC playback.
- Tray startup at sign-in, close-to-tray, and reopening the existing window from its shortcut.
- Application-local Python, compiled Windows GUI host, and manifest-verified package.

210 offline tests pass. The GUI was checked against the running development DVD bridge, and VLC decoded a generated stereo WAV. DVD movie sound and music-file playback are supported through VLC. **Physical audio CDs remain unsupported**, not merely untested: the current bridge only reads 2,048-byte DVD data sectors. No CD-specific runtime is enabled in this release.

The tray app is unsigned application code. VLC is separate. A clean installer run, reboot/reconnect qualification, and full-movie playback using this packaged version remain pending. Stop the development prototype and disable its watcher before installing this separate package. Extract the ZIP and run Install.cmd; existing installations must be uninstalled before upgrading.

# 0.1.0-alpha.1

First experimental source release of the Initio DVD Bridge.

- Serialized physical DVD reads and bounded physical DVD authentication.
- Virtual optical device through the built-in Windows iSCSI initiator.
- Exact USB ancestry and disk-interface discovery, without a fixed disk number.
- Per-user arrival watcher, duplicate prevention, and owned-session cleanup.
- Install/uninstall scripts, Start menu entries, and application-local Python.
- Offline tests, source documentation, pinned runtime download, and package hashes.

Hardware support is intentionally limited to the examined device identities and firmware signature. The prototype played a movie in VLC; the public installer and full hardware lifecycle still require independent live qualification. Empty-drive insertion, automatic disc changes, burning, and audio CDs are unsupported.

This package is unsigned application code. It contains the signed official Python runtime but has no publisher-signed installer or kernel driver. Extract the ZIP and run Install.cmd. Stop any development prototype first. VLC is installed separately.
