# GASLUX-ZORIN — Synthetic write-set and recovery (DENY_NO_WRITER)

This is a READ-ONLY laboratory, dependent on Zorin PR #264. No Ubiquity,
GRUB, QEMU, physical disk, Windows disk, ESP or NVRAM writer is invoked.

## Reused contracts

The GPT reader is imported UNMODIFIED from Safety PR #265 at the immutable
commit 8ed912c6934c33354b0a814201c7217043bd0197.
CI uses a separate sparse checkout of that exact commit and verifies its SHA.
There is no second GPT parser in this PR. The provenance policy of Safety #267
and Observer #259/#272 remain dependencies; neither is changed.

The Mint #271 A/B checkpoint implementation is the reference design for
separate-copy identity and validation. Mint's actual QCOW2/qemu-img restoration
code is inappropriate for these 16 MiB RAW fixtures. Test-only local atomic
copy/fsync/replace demonstrates restoration; no new rollback subsystem or
production API is introduced.

## Synthetic-only contract

The Draft 2020-12 schema is schemas/zorin-synthetic-writeset-v1.schema.json.
It requires:
- transactionId, checkpointId, pinned disk and checkpoint SHA-256;
- disk GUID and entire GPT identity from the canonical Safety reader;
- logical-sector size, exact image size, PARTUUIDs, offsets, lengths;
- owned Linux partition and separate ESP identity;
- ESP tree and OVMF VARS SHA-256 baseline;
- DENY_NO_WRITER, no transaction ownership or independent attestation,
  empty writeOperations and a Linux-root-only observation interval.

The historical GASLUX-CACHYOS-ROOT remains refused. No automatic relabel.

## Read-only verifier

auto_tests/tools/zorin_synthetic_writeset.py compares every byte of baseline
and trial RAW images in 64 KiB chunks. Every changed byte MUST be within the
pinned synthetic Linux region. Even a single changed sector of protective
MBR/GPT primary/backup, a protected partition, unused space or a canary is
refused. Valid but modified PARTUUID is detected through the pinned Safety
reader, not accepted as a valid new target.

Before and after the byte comparison, the verifier checks reference and
checkpoint hashes, exact independent file identities and immutable
permissions. It rejects block devices, symlinks, hardlinks, ownership and
transaction mismatches, changing evidence and incomplete files. The
synthetic ESP subtree is compared as a path+content digest; all third-party
EFI trees, including EFI/Microsoft, are protected without exception.
Synthetic OVMF variable files must be unchanged.

The returned SYNTHETIC_ONLY_WITHIN_ROOT status means only that this
synthetic byte comparison stayed within the chosen interval. It never
authorizes a writer, an installer or any actual machine transition.
Refusal codes include E_GPT_INVALID, E_GPT_IDENTITY_CHANGED,
E_PARTUUID_CHANGED, E_GPT_BYTES_CHANGED, E_OUTSIDE_LINUX_CHANGED,
E_ESP_PARTITION_CHANGED, E_ESP_FILES_CHANGED, E_OVMF_CHANGED,
E_BASELINE_CHANGED, E_CHECKPOINT_CHANGED, E_FOREIGN_TRANSACTION,
E_FOREIGN_FILE, E_REFERENCE_WRITABLE and E_SOURCE_RACE.

## Test fixtures and recovery scope

auto_tests/test_zorin_synthetic_writeset.py constructs its own 16 MiB RAW
GPT disk with a valid primary and backup header/partition-array CRC.
The disk contains a synthetic ESP partition, Linux root, protected partition
and unallocated sectors. Separate small EFI/Microsoft and vendor file trees,
synthetic OVMF VARS and an independent checkpoint are also created.

Negative tests modify actual bytes or files, never merely JSON claims.
A test-local atomic restore uses an exclusive staging file, fsync, baseline
hash comparison and replacement of only the owned trial file. ENOSPC and
invalid checkpoint injections MUST fail, leaving unrelated transaction
canaries intact. The baseline and checkpoint are not hardlinked.

A synthetic ESP directory is a surrogate path inventory, NOT a parsed FAT32
image. The RAW ESP partition is separately protected byte-for-byte. The
receipt and checkpoint SHA-256 are laboratory pins, NOT externally attested
storage truth. Separate inode, digest and mode checks do not prove immutable
storage or an independent backup authority. The positive synthetic restore
does NOT prove Windows rollback, NTFS shrink reversal, boot repair or WinRE.

## Future approval gates

A future Ubiquity experiment needs synthetic-only QEMU/KVM with an isolated
GPT disk, private OVMF VARS, a checkpoint independently restorable before
writes, authentic transaction and physical/guest identity, a signed plan,
host-enforced write boundaries, Observer isolation, file-level ESP and
firmware monitoring, and separate Safety authority for any write. Safety
#265/#267 ACCEPT_NO_WRITER never grants that authority.

No QEMU or installer was run by this change. P3/P4/P5 and stable status
remain unclaimed.


## Integração isolada no dev (2026-11-22 UTC)

A dependência acima de #264 descreve a origem histórica dos testes, **não** a nova base de integração. A branch `integration/zorin-277-281-fd-nowriter-dev-20261122` copia apenas o verificador sintético, o respetivo schema, dois conjuntos de testes e documentação, partindo de `dev` no commit `8e68a475d6397ba8fef2e0f9f83758545e202a5f`. Não incorpora #264, código de instalação, controlador Observer #259 nem permissões de escrita. O parser GPT executável é o canónico já integrado em `dev` por #307. A integração continua dependente de CI da nova branch e de revisão Safety independente; nenhum resultado anterior justifica promover o backend a estável.
