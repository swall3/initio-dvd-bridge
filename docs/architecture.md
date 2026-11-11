# Architecture and observed protocol

The physical reader uses the existing USB storage driver and device-specific control transfers. It locates the current disk interface through SetupAPI and verifies its exact USB ancestry and storage descriptor; it does not assume a PhysicalDrive number.

The Initio controller CPU is held while a serialized reader services SATA/ATAPI transactions through the controller's debug-access path. The bridge validates the observed ROM signature before controller access. Register allowlists and transfer limits constrain operations. No firmware image is distributed or persistently written.

`OpticalLun` exposes a read-only optical SCSI device. A loopback iSCSI target on 127.0.0.1:32610 presents it through the built-in Windows initiator. Authentication commands are forwarded to the physical DVD; region-setting commands and arbitrary media writes are rejected. Sector data is read from the physical medium, never synthesized on read failure.

The tested data path uses calibrated 16-sector physical batches/read-ahead, a 256 KiB frontend transfer ceiling, and batched TCP responses. Idle request acquisition has a 20-second cooperative ceiling, with a fresh eight-second service budget only after validating the unchanged zero-data TUR context. Active commands retain their separate budget. Synchronous Windows USB calls cannot be canceled by these cooperative deadlines.

Session and portal ownership are journaled. Cleanup acts only on journaled identities. A service whose process generation changed is left running. Stale runtime recovery requires proof the old process exited and a fresh clean inventory. A live reused PID conservatively blocks recovery. The privileged watcher accepts no arbitrary external commands and never kills a reader or resets a shared hub.

Register sequences were reconstructed during investigation of one device. They are observations, not an official Initio specification or a promise of compatibility with all devices sharing a descriptor.
