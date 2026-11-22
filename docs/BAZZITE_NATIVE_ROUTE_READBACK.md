# Bazzite 45 native route investigation: pinned official sources

Experimental read-only evidence. This branch is stacked on Bazzite #262 and
does not modify #250, #262, #280, Safety or Observer, Windows or a bootloader.

## Exact upstream byte sources

Workflow bazzite-native-route-readback.yml downloads only five Markdown
sources using immutable commits and compares their Git blob SHA-1 identity
with GitHub API metadata. It emits measured SHA-256 for each document.
The Bazzite docs commit was marked GitHub-verified; the bootc docs
commit was not. A pinned Git blob does not independently attest a live
Anaconda/bootc executable or authorize host/guest activity.

Bazzite docs source:
https://github.com/ublue-os/docs.bazzite.gg/commit/1a9b77a0633443424e9c939cf4bd50718d1c79a5

bootc docs source:
https://github.com/bootc-dev/bootc/commit/0fe7b14f29f1a8e6868462a170b165611992e901

Historical Bazzite 45.20261117.1 ISO signature, OCI signature and embedded
payload readback already exist in Actions #44759529218. They are not rerun
or used as a grant of trust by this source-only job.

## Grounded conclusions

- ISO45: Bazzite documents only automatic partitioning in modern live
  installers; selecting a whole drive is warned as erasing its content.
  It documents a misleading Windows EFI format label. There is no
  demonstrated custom GPT 4-6 route or exact EFI write-set.
- ISO45 automatic Windows dual boot: officially described with pre-shrink
  in Windows, but not demonstrated safe under Gaslux transaction and
  recovery requirements.
- Legacy ISO: Bazzite documents Blivet-GUI manual partitioning. The exact
  legacy ISO42 in the Gaslux historical lab has no independent upstream
  signature and cannot be promoted by signed ISO45 evidence.
- Generic bootc to-disk: its official manual states the entire selected
  device is wiped. Not suitable for Windows-preserving dual boot.
- Generic bootc to-existing-root: upstream states it wipes /boot. Not
  suitable as a conversion of an existing system or Windows partition.
- Generic bootc to-filesystem: can install into externally mounted and
  prepared filesystems and ESP, but its compatibility with the exact
  Bazzite OCI, Btrfs layout, bootloader, updates and dual boot remains
  UNPROVEN. This is the most promising separate research route.

The offline readback returns six classifications but always keeps
installationAuthorized, partitionWriteAuthorized, gptMetadataWriteAuthorized,
windowsEspWriteAuthorized, nvramWriteAuthorized,
secureBootEnrollmentAuthorized and guestCommandChannelAuthorized FALSE.
A valid report exits 2; an altered source/unknown file exits 3.
No action is executed against any guest, QEMU, ISO, disk or NVRAM.

## Next experiment, NOT yet authorized

Ask Safety/Observer to establish independent protected read-only guest
provenance: reviewed bootc executable/version bound to the signed Bazzite
OCI, a disposable isolated QCOW2 with stable physical identity and no
Windows disk, source and destination sector evidence, unique guest
collector channel, restricted methods, bounded one-time transaction, and
immutable post-read measurements. First inspect whether this exact Bazzite
image actually supports bootc install to-filesystem and can target its
own ESP and the intended Btrfs root with no foreign EFI/NVRAM writes.
Do not run installation, Blivet mutators, formatting, bootloader updates
or privileged shell simply to find this out. A separate writer approval,
Windows VM rollback and dual-boot proof would be needed later.

Official references:
https://docs.bazzite.gg/General/Installation_Guide/install-guide/
https://docs.bazzite.gg/General/Installation_Guide/legacy-install/
https://bootc.dev/bootc/man/bootc-install-to-disk.8.html
https://bootc.dev/bootc/man/bootc-install-to-filesystem.8.html
https://bootc.dev/bootc/man/bootc-install-to-existing-root.8.html
