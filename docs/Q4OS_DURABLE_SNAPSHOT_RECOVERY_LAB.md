# Q4OS self-contained synthetic snapshot and restore lab

This host-only laboratory extends the signed 32-GiB synthetic UEFI/GPT fixture. It creates a compressed, self-contained qcow2 snapshot with no backing file, fsyncs it, verifies it with qemu-img, restores it to a new host-side raw file, compares the full virtual disk with qemu-img compare, and independently verifies GPT, ESP identity, geometry and FAT32.

The snapshot and signed manifest are uploaded as a GitHub Actions artifact with seven-day retention. The manifest is Ed25519-signed with an ephemeral laboratory key and binds the snapshot SHA-256, file size, virtual size, signed plan hash, restore result and GPT identity. The private key is never persisted.

## Safety boundary

- The synthetic raw base is read-only during snapshot and restore.
- No QEMU guest is started in this workflow and no guest block device is opened.
- The restore destination is a new host-side temporary file, deleted after verification.
- No Windows disk, ESP, BCD or WinRE is attached.
- No Q4OS ISO or Calamares job runs.
- The evidence explicitly keeps diskWritesAuthorized, installationAuthorized, calamaresJobsAuthorized, windowsEspWritesAuthorized and rollbackVerified false.

## What this proves

It proves that the synthetic GPT image can be captured into a self-contained qcow2 artifact, that the artifact is internally consistent, that it can be restored to a new file with identical virtual contents, and that the restored GPT/ESP/FAT32 identity matches the signed target plan.

The snapshot is fsynced for the runner job and prepared as a seven-day Actions artifact. Successful artifact upload is a separate CI result. This is not proof of recovery after a guest write, power loss, Windows update, BitLocker/Device Encryption, BCD/WinRE changes or physical-disk failure. rollbackVerified remains false.

The next gate requires a separately authorized disposable Windows/Q4OS VM, durable independent recovery of Windows boot/WinRE/BCD and explicit review before any write-enabled Calamares experiment.
