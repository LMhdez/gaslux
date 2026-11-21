# Experimental GPT no-writer gate (PR dependent on #265)

`assets/live/libertix_prewrite_no_writer.py` consumes the **same** GPT snapshot
shape produced by `inspect_gpt_image()`; it does not implement another GPT parser.

## Contract and authority boundary

`decide_no_writer(plan, plan_bytes, transaction_id, vm_id, host_evidence,
guest_evidence, immediate_evidence, host_key, guest_key, fresh_nonce,
owned_regions, write_set)` accepts only GPT/UEFI and compares the complete
host/guest/immediate snapshots. Every evidence record must have the exact six
fields `source, transactionId, planSha256, vmId, nonce, snapshot`, and an
HMAC-SHA256 covering its canonical JSON payload. Independent keys are used
for host and guest. They must never be committed or included in the plan.

The caller **must authenticate** the plan bytes via Gaslux's existing trusted
signing mechanisms, provision the keys independently, attest the VM and backing
QCOW2 identities, record challenge freshness, and collect the observed data
from an independently verified trusted capture runtime. HMAC of arbitrary
JSON is NOT proof that a physical device was observed. The signed plan and
transaction identifier must match. The current read-only GPT verifier only
supports regular raw images: QCOW2 cannot be read directly; use a trusted
read-only, verified conversion/mapping process and preserve chain identity.

Only the exact operation `allocate-free-space` is considered; extents must
be aligned, inside a transaction-owned region, non-overlapping, and outside
all existing partitions and GPT reserved areas. No writer callable exists.
A successful laboratory decision is exactly `ACCEPT_NO_WRITER` and **is
never production authorization to mutate a disk**.

## Limitations

Not integrated into a production pre-write point. The trusted-plan signature,
physical sector size, ESP and BCD file inventory, WinRE, BitLocker, physical
media identity, hypervisor trust, QCOW2 backing chain authentication,
guest-attested observation and real-time TOCTOU fencing are not implemented.
Nor are complex BIOS/MBR layouts or EBR. A fresh nonce alone does not prevent
replay without a coordinator-owned, single-use nonce registry and fencing.
Recheck of a mutable device is not atomic without exclusive access.

In particular, the `owned_regions` input is caller-supplied experimental
evidence, **not authoritative ownership**. Ownership must be verified from
signed transaction checkpoints and independent hypervisor/disk evidence
before this can be connected to any writer.

## Tests

`python -m pytest -q auto_tests/tests/test_disk_identity_gate.py
auto_tests/tests/test_prewrite_no_writer.py`

The tests are synthetic/negative gates only. No QEMU Windows/Linux dual
observation or Windows recovery has been demonstrated. Do not merge or enable
until those obligations are proven.
