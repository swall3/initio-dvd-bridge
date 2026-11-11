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
