# Q4OS — Safety #265 reconciliation and Calamares refusal (experimental)

**No write authorization. No Windows 10 genuine QCOW2 boot/inspection claimed.**
Q4OS PR #266 stays a draft; Safety PR #265 and Observer PR #259 remain separately owned.

## Canonical GPT responsibility

Safety `assets/live/libertix_disk_identity_gate.py` (#265) owns the GPT primary
and backup reading, header and entry-array CRC validation, protective MBR,
partition identity, disk GUID, byte offsets, lengths, partition attributes,
logical sector size, and snapshot equality. It accepts only regular-file
images, not block devices. This contract alone does not prove physical sector
size, running Windows BCD/WinRE status, BitLocker, VM host-to-guest mapping,
or the authenticity of an expected snapshot.

Q4OS `gaslux_q4os_safety_adapter.py` only projects legacy
`{diskGuid,logicalSectorBytes,partitions:[{index,type,guid,first,last,attributes}]}`
into Safety's exact
`{partitionStyle,partitionTableId,sizeBytes,logicalSectorSizeBytes,partitions:[{number,typeGuid,partGuid,offsetBytes,sizeBytes,attributes}]}`
shape. It requires the Safety comparator supplied from #265. **It does not
provide a second GPT parser** and must fail closed if Safety is missing.

Q4OS-specific responsibility: pinned ISO/version, Calamares module inventory,
filesystem/root plan, transaction identity, typed and exclusively-owned
write-set, Windows ESP, MSR, NTFS, WinRE and OEM exclusions, GRUB/EFI policy
and recovery prerequisites. The new bridge is diagnostic and always returns
`decision=refuse`, with every write authorization `false`.

## Calamares anticipated operations and refusal boundary

Prior analysis of pinned Q4OS 6.10 x64 r2 ISO records the native Calamares
configuration, including `installEFIFallback=true`. Anticipated actions
remain **unexecuted**:
1. Create a GPT entry and format an ext4 root: changes both GPT copies/CRCs
   and filesystem blocks and requires proof of exact free-space ownership.
2. Mount the new root and use the selected ESP: mounts alone are not a
   complete write-set; module-generated mount and installation effects must
   be proven in the actual effective configuration.
3. Copy/expand the system, set boot and invoke GRUB: upstream hook references
   `EFI/debian/grub.cfg` and `grub-install --force`, both posing risks to
   shared ESP and loader paths.
4. Install EFI fallback: `installEFIFallback=true` can cause writes to
   `EFI/BOOT/BOOTX64.EFI`, a path shared with Windows and other installers.
   This risk is **not suppressed, controlled or proven removable** by a
   validated effective Calamares configuration. Therefore it is blocked.
5. Any NVRAM BootOrder/BootNext, EFI variables, GRUB hook or GPT update
   not explicitly owned must be refused before input or disk operations.

The diagnostic write-set only accepts root create/format descriptors
bound to a transaction and the exact proposed root byte extent. It is **not**
a complete Calamares write-set: the omitted GPT, mounts, data copy, GRUB,
ESP, EFI and NVRAM operations alone make it ineligible for authorization.
Tests deliberately use a mock equality function to exercise adapter
fail-closed behavior; **they do not prove execution against Safety #265's
actual comparator**.

## Genuine Windows 10 QCOW2 evidence still required

A lab owner must identify an already-authorized Windows 10 image and confirm
the permitted overlay/backing path and immutable baseline digest. There is
no such accessible disk file in this agent's present workspace. Never infer
authorization from the existence of a GitHub Actions run or artifact.

When a lab is available, the independent reader must establish host/QEMU
and guest image provenance, backing chain and immutability, disk and primary/
secondary GPT geometry/CRCs, ESP, NTFS, WinRE and OEM inventories, PARTUUIDs,
byte ranges and integrity; compare Q4OS-derived inventory byte-for-byte to
the authenticated Safety inventory; and rehash the untouched backing before
and after. A live Windows-side authenticated transaction/baseline is also
necessary to establish BCD/WinRE/BitLocker provenance and true Windows boot.
A private read-only overlay must never be treated as a suitable recovery
checkpoint merely because `qemu-img compare` succeeds.

**Required upstream Safety contract**: authenticate host raw/QCOW2 backing
identity and guest disk mapping, physical sector geometry, the signed
transaction/plan and baseline, while distinguishing observed GPT equality
from independent ownership attestation. Do not implement a competing
identity gate in Q4OS.

## Restrictions

No input to Calamares, partition manipulation, NTFS shrink, EFI/GRUB writes,
guest boot, restore, physical-disk action, workflow merge or stable-catalogue
enablement is authorized. Observer #259 exclusively controls input and
continues blocking it pending an atomic, exclusive graphical channel.
