# Safety QEMU/libguestfs host/guest GPT experiment (read-only)

**Status:** experimental; PR #267 stacked on #265. Complementary to the
initramfs QEMU probe, not a replacement GPT parser or Linux installation backend.

## Execution and evidence

Workflow: .github/workflows/safety-qemu-gpt-host-guest.yml.
Probe: auto_tests/tools/safety_qemu_gpt_host_guest.py.

The GitHub-hosted disposable runner creates a **synthetic** 64 MiB GPT regular
RAW file inside RUNNER_TEMP. sgdisk writes only to that owned file. A qcow2
overlay with explicit raw backing is created using qemu-img. Format, resolved
backing path, virtual size, file identity and SHA-256 of both backing and
overlay are checked before and after the experiment.

The host observes an explicit read-only conversion of the qcow2 view to a
temporary raw file and inspects it using the existing
libertix_disk_identity_gate.inspect_gpt_image() from PR #265. A real Linux
libguestfs appliance boots in QEMU (backend direct, KVM required), and the
qcow2 is attached via add_drive_opts(format=qcow2, readonly=1) under an
alphabetic libguestfs device label. The guest-side API reads the first and
last 34 sectors through that labelled device; the runner constructs a sparse
raw GPT witness from those bytes, then reuses the same #265 parser to check
both headers, both table CRCs, GUIDs, PARTUUIDs, extents and geometry.

The label prevents relying solely on /dev/sda enumeration but is **not a
hardware virtual serial**. diskHardwareSerialVerified=false is explicit.
A Linux QEMU process, its PID, actual qcow2 file descriptor and open KVM
descriptor are checked while the appliance is running. A further host
observation immediately before the gate is required.

No physical block device is opened, formatted or otherwise modified.
Only disposable, owned synthetic files are created and removed.

## Experimental transaction decision

The existing decide_no_writer() consumes the host/guest/immediate snapshots.
The plan includes qcow2 backing identity, device label and VM evidence.
Separate ephemeral HMAC-SHA256 keys protect host and guest records, with
transactionId, planSha256, vmId and 192-bit nonce. The in-memory nonce
registry rejects replay in the same running process. Neither key is logged
or uploaded. Only ACCEPT_NO_WRITER can be returned: there is no writer.

Negative tests include different GPT disk, PARTUUID, GPT offsets, HMAC and
VM mismatch, immediate mismatch, swapped qcow2 and backing mismatch,
symlink/hardlink/path replacement and challenge replay. Operational positive
and negative outcomes are saved as bounded JSON and SHA-256 sidecars.

## Critical trust limitations

trustBoundary=NOT_INDEPENDENT. The single runner controls QEMU, the
observer, the plan hash, session nonce and the HMAC keys: this is
authenticated consistency **inside one laboratory**, not independent
remote attestation. planSignatureVerified=false; no production signing
verification was performed. In-memory replay protection is not durable.
The write-set ownership is synthetic and supplied by the laboratory,
not a grant for production.

This run is not Windows. It proves neither Windows image provenance,
a real Windows ESP, BCD, WinRE, BitLocker, dual boot, rollback nor
device identity on hardware. The helper may NEVER be wired to a writer.
Until provenance is independent, a production pre-write gate must DENY.

Future requirements: independent remote observer, validated plan signature,
trusted QEMU VM/disc serial and backing mapping, coordinator-owned nonce
ledger, exclusive disk fencing, real Windows read-only probes and recovery
tests under authorized disposable VMs.
