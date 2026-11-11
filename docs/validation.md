# Validation status

The development prototype read a complete DVD navigation file twice with matching hashes, completed the physical DVD authentication exchange, and decoded protected movie audio/video. A measured final window advanced 19.970 media seconds in 20.047 wall seconds, with 946 decoded video frames, 1,330 audio blocks, and no new dropped frames/audio in that window. Startup had drops. The user subsequently confirmed visible VLC playback.

The public source is a separate generalized packaging copy. Those observations are prototype evidence, not a live acceptance test of this release.

| Check | Status |
|---|---|
| Explicit offline transport, auth, lifecycle, identity, watcher, installer and tray suite | 210 passing; repeated on bundled Python during release build |
| Native tray window and file picker | Inspected on development Windows desktop; Ready G: and controls displayed correctly |
| VLC audio-file decoding | Generated stereo WAV decoded to nonzero stereo PCM at 44.1 kHz; speaker output not independently verified |
| Physical audio CDs | Unsupported; raw-sector backend remains unimplemented and no audio CD was available remotely |
| Official Python executable signature | Verified Python Software Foundation |
| Package file hashes and path containment | Verified during build |
| Public installer on a clean Windows account | Pending |
| Actual unplug/replug using public package | Pending |
| Reboot and sleep/resume with public package | Pending |
| Empty drive and automatic disc changes | Unsupported |
| Uninterrupted full movie using public package | Pending |
| Other controllers, mechanisms, or discs | Unqualified |

Hardware qualification must be performed on a spare/test host without valuable shared USB storage. Close the player and stop the bridge before intentional media changes. Record startup, playback, cleanup and reconnect outcomes; redact logs before sharing because authentication traces may contain key material. No raw logs or authentication payloads are required for an issue report.
