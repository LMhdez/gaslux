# QEMU host/guest Safety GPT witness — experimental, no writer

Workflow: `.github/workflows/safety-qemu-synthetic-host-guest.yml`.
Probe: `auto_tests/tools/safety_qemu_synthetic_host_guest.py`.

The test boots an actual KVM Linux guest from a disposable initramfs,
with a 64 MiB **synthetic** GPT disk. It does not start Windows and does not
reproduce a Windows installation. The host generates GPT using `sgdisk`,
then checks it using the **existing** `inspect_gpt_image` parser from #265.

The guest discovers the attached virtio block device by a unique virtual
serial (not by `/dev/vda` ordering) and reads the first 34 and last 33
sectors without mounting a filesystem. Raw sectors reach the coordinator
over the QEMU serial port. The coordinator reconstructs a temporary sparse
raw disk containing those GPT regions and validates both GPT CRCs and the
partition array using the same Safety parser. It compares the normalized
disk/partition identity against the independently obtained host reading,
then repeats a host snapshot immediately before deciding. An empty
QCOW2 overlay has an explicit raw backing file and is opened by QEMU
with `readonly=on`; the runner compares the backing file SHA-256 before and
after, the overlay SHA-256 before and after and the `qemu-img info` chain.

The `decide_no_writer` call uses runtime-generated host and guest HMAC keys,
transaction ID, VM identifier, plan SHA-256, a challenge nonce and an
explicit synthetic free-space owned write-set. **ACCEPT_NO_WRITER must never
be interpreted as install permission or passed to a writer.** No writer is
present in the test. Negative cases include an independently booted,
different synthetic disk, a changed PARTUUID and a changed transaction.
No secrets, QCOW2, raw disks or VM contents are uploaded.

## Trust boundary

`trust_boundary = NOT_INDEPENDENT`: the GitHub runner controls QEMU, the
host-side inspector, the serial capture, the controller, the synthesized
plan, the ephemeral keys and the HMAC records. These HMACs bind data
within one laboratory session, but do **not** attest an independent remote
observer or the underlying physical storage. Kernel command-line fields
are **not** unforgeable attestations. The same host parser processes the
guest-read GPT sectors. A read-only virtual device prevents writes through
that virtual attachment only; it does not prove external host immutability.

The plan's canonical SHA-256 is computed but **its production signature is
not verified**. The challenge is random, but there is no durable, external
single-use nonce registry. The owned write-set is caller-provided, not a
production ownership grant. No real pre-write gate, Windows backing chain,
BCD, ESP, WinRE, BitLocker, rollback or hardware protection is proven.
The tests remain isolated in disposable, GitHub-hosted KVM with
`RUNNER_TEMP` and must never use physical disks or production writers.

## Failure policy

KVM unavailable, missing serial witness, incompatible kernel drivers,
truncated guest sectors, GPT CRC mismatch, unexpected backing chain,
changed overlay or parent hash, invalid transaction or failed negative
refusal all cause failure. No TCG fallback or write authorization.
