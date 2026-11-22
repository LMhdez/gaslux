# AUTHENTICATED-DESTINATION-01 — read-only host/FD contract (experimental)

**Date:** 2026-11-22 UTC. **Scope:** isolated Linux runner with a previously
started, paused QEMU and *private disposable* regular-file QCOW2 + RAW backing.
**No Windows guest, OS installation, disk writer, ESP/BCD/WinRE mutation,
firmware changes or production permission.**

## Implemented core

`auto_tests/installer_observer/authenticated_destination.py` exports
`assess_authenticated_destination(...)`. Its name describes the future
authentication goal; the **current result does not authenticate the destination
end-to-end**. It consumes, without reimplementation:

- `QemuLocalDiskWitness` from merged Observer #325, with `ProcessSeal`,
  pidfd, local read-only `/proc/PID/fd` witness and QMP peer identity;
- existing `inspect_gpt_fd` and `assert_snapshot_matches` from `dev`,
  applied to a pinned RAW backing **never to QCOW2 bytes**;
- unchanged experimental Safety #267 `decide_no_writer`, imported from the
  SHA-pinned test checkout, to validate plan/transaction, three MAC-bound
  snapshots and exclusively claimed/owned write extents.

Additionally, the core opens **no files** on behalf of the caller and
accepts only caller-opened read-only FDs, checked against real `fstat` and
`lstat` (device, inode, size, mtime, ctime, owner, one hard link, exact path).
It measures QCOW2/backing SHA-256 from those FDs, checks actual QCOW2 magic,
and invokes `qemu-img info --backing-chain` on inherited
`/proc/self/fd/N` with `pass_fds` to compare observed virtual geometry and
the explicitly pinned RAW backing. It reads actual primary and secondary GPT
through the canonical FD parser on the RAW backing, and checks GUIDs, partition
UUIDs and offsets via the existing snapshot matcher.

A separate caller-opened read-only checkpoint FD has its bytes, SHA-256,
transaction, source hashes and GPT identity compared. It is a *diagnostic
receipt*, not an independently authenticated recovery or proof that Windows
can be restored. The checkpoint `restoreProven` must be explicitly `false`.
The optional ISO/OCI/native ISO source identity is **CLAIMED**, never verified
by this shared component. OCI/RPM checking remains Bazzite-specific.

Any guest claim is refused because no independent collector trust root exists.
The QEMU witness correlates local process, observed open FD and peer-checked
QMP reply, but QMP is still a QEMU claim, not a proof of the *internal backend
pointer* or guest-visible data. A borrowed procfd is a newly opened local
descriptor, not the original QEMU kernel file description. Transient
fd-table ABA and concurrent in-place mutations are not fully prevented.

## Property matrix

| Property | Assessment | Meaning |
|---|---|---|
| Local QEMU process/PID start and SO_PEERCRED of QMP | **PROVEN** | Local measurement only |
| Open read-only QEMU FD and own QCOW2 FD identity | **PROVEN** | Same measured file dev/inode/size at sampled boundaries |
| RAW backing regular-file FD and SHA-256 | **PROVEN** | Sampled local bytes match expected caller hash |
| QCOW2 backing path/virtual geometry | **PROVEN locally** | qemu-img read-only inspection of held QCOW2 FD |
| Signed origin of transaction/plan and source ISO/OCI | **CLAIMED** | #267 HMAC is not an independent plan signature |
| QEMU internal backend to original FD | **UNPROVEN** | QMP claims are not independent backend attestation |
| Guest-effective GPT, ESP/FAT32, BCD, WinRE | **UNPROVEN** | RAW backing GPT is not QCOW2 overlay/guest GPT |
| GPT primary/backup and PARTUUID of RAW backing | **PROVEN locally** | Canonical FD reader verifies both |
| Proposed region ownership | **CLAIMED** | #267 validates declared intervals, not creation provenance |
| Checkpoint bytes and SHA-256 | **PROVEN locally** | Independent trust/Windows restore unproven |
| Independent checkpoint transaction/authenticity | **UNPROVEN** | Hash supplied by caller, may be self-authored |
| Guest origin and collector authentication | **DENIED** | No independent guest root of trust |
| Installation/write/release/stability authority | **DENIED** | Always false |

On a structurally valid input the status is
`READONLY_STRUCTURE_OBSERVED`, authorization `DENY_NO_WRITER` and
`productionStorageWritesAuthorized=false`,
`guestCommandChannelAuthorized=false`, `rollbackProven=false`,
`sameDiskDualBootVerified=false`, `stable=false`.

## Adversarial regressions

The real stopped-QEMU CI reuses the isolated runner conditions and scripts
from #325. It exercises:
`DESTINATION_SWAP`, `FOREIGN_FD` (QCOW2, RAW and checkpoint),
`QCOW2_BACKING_SWAP`, `GPT_GEOMETRY_MISMATCH`,
`TRANSACTION_MISMATCH`, `UNOWNED_WRITESET`,
`CHECKPOINT_TAMPER`, `SPOOFED_GUEST`, and a
`VALID_READONLY_INSPECTION` that **cannot grant writes**. The original
#327 BZD-DEST-01 known-gap suite remains unchanged in its pinned checkout.
Its historical gap tests are **not** reinterpretations of successful denials.
The new suite exercises real fd/path/byte attacks against this new concrete
interface.

Workflow:
`.github/workflows/contracts-authenticated-destination-readonly.yml`.
Pinned #267 `0be04192acd542646a5b6cd952e01620379edf5d`,
BZD #327 `45c430b6861ba3dce3b9e33bf3f9cccfb2b29a52`,
GPT #286 `9aed36cfdb8c09a461dc38811c326c54180273de`.
Only the canonical GPT parser present on `dev` is invoked by the new
destination module; the historical GPT pin is used by reused QEMU fixtures.

**No positive test certifies end-to-end authenticated destination.**
Before a writer, Safety/Observer must prove external plan authority,
the original QEMU backend-FD association, effective guest GPT,
independent collector origin/freshness, checkpoint provenance,
Windows recovery and rollback; do not use this module as a writer gate.

## Exact-head real QEMU and Safety regression execution (2026-11-22)

[Actions #45032388422](https://github.com/LMhdez/gaslux/actions/runs/45032388422)
and [#45032391998](https://github.com/LMhdez/gaslux/actions/runs/45032391998)
**SUCCESS** on implementation HEAD `d2e382a60120d09a0b225e4188309f48f0315845`.
The new 11-test real-QEMU destination suite passed both the valid no-writer
case and all invalid mutation cases; the original QEMU/FD witness suite,
#327 BZD-DEST-01 original 16-case suite, #267 no-writer 22-case suite and
integrated HOST/FD tests also completed successfully. Python compileall,
Ruff lint and format passed. [Windows recovery fixture CI #45032392037](https://github.com/LMhdez/gaslux/actions/runs/45032392037)
and [CachyOS recovery contract CI #45032392005](https://github.com/LMhdez/gaslux/actions/runs/45032392005)
also completed SUCCESS on the same HEAD.

These CI runs prove only *local test-owned stopped-QEMU FD observations*,
a read-only backing RAW GPT, a caller-hash-checked checkpoint and explicit
no-writer refusals. They do NOT prove guest boot, effective overlay GPT,
independent QEMU backend mapping, third-party source or transaction signature,
Windows recovery, rollback or any production authority.

## Additional bounded checkpoint receipt guard

The diagnostic checkpoint is JSON, not a filesystem image or a Windows
recovery volume. The real module now rejects an open checkpoint FD whose
measured file size exceeds **64 KiB before parsing**, even if the caller
updates its claimed SHA-256 to match the oversized file. This prevents
unbounded JSON memory consumption in the diagnostic reader.

The added twelfth real-QEMU test supplies that matching claimed hash and
requires `CHECKPOINT_SIZE_EXCEEDS_LIMIT`. The earlier 11-test results remain
historical evidence for the preceding module HEAD; they are **not** a
substitute for CI on the new checkpoint-bound candidate.


## 128 GiB: separação entre metadados e prova integral (2026-11-22)

**Limite integral inalterado:** `MAX_BYTES = 512 MiB` por ficheiro para a
inspeção autenticada local existente, que faz SHA-256 de todos os bytes de
QCOW2, RAW e checkpoint. Um backing RAW esparso de 128 GiB tem tamanho
lógico de 128 GiB, mesmo que o espaço fisicamente alocado no host seja
pequeno; a função antiga continua a recusar essa dimensão, sem iniciar
hashing de 128 GiB. `_digest` passa a rejeitar também leituras positivas
mas curtas, em vez de avançar pelo offset e ignorar bytes omitidos.

**Novo limite separado, estritamente read-only:**
`probe_destination_scale_metadata` aceita até **128 GiB de dimensão
virtual e lógica do RAW** apenas para inspecionar os primeiros **32 bytes**
do cabeçalho QCOW2, identidade de descritores e metadados do filesystem.
A imagem QCOW2 (ficheiro do host) continua sujeita a 512 MiB de dimensão
lógica e a soma dos blocos alocados do QCOW2 e RAW (`st_blocks*512`) tem
limite de 512 MiB. O RAW grande tem de ser um ficheiro regular esparso,
num workspace absoluto, privado e propriedade do utilizador; os FDs são
abertos read-only pelo chamador, sem symlinks ou hardlinks. Nenhum ficheiro
é criado ou modificado por esta sonda; não abre um caminho para aceder a
outro backing nem executa QEMU. Uma comparação de metadados antes/depois
não exclui mutação simultânea in-place ou troca ABA.

A classificação **READONLY_SCALE_METADATA_ONLY** só confirma medidas
locais não autenticadas externamente. O cabeçalho com magic/version/size
não prova um QCOW2 coerente, `qemu-img --backing-chain` não é executado
neste modo, não há SHA-256 do RAW/overlay, GPT guest, identificação Windows,
origem do checkpoint, nem atestação da associação QEMU→FD. A sonda distingue
explicitamente: dimensão virtual QCOW2, tamanho lógico do ficheiro QCOW2,
blocos alocados no host, tamanho lógico RAW, blocos RAW alocados, bytes
efetivamente lidos (=32), bytes necessários para hash integral e estimativa
livre de `statvfs`. `st_blocks` e `statvfs` são indicadores de recursos,
**não** reservas duráveis ou prova de propriedade histórica.

Para um checkpoint completo, reporta-se como condição **necessária, mas não
suficiente**, uma reserva estimada igual à dimensão virtual; espaço livre
inferior devolve `READONLY_SCALE_CAPACITY_INSUFFICIENT` e
`INSUFFICIENT_CHECKPOINT_SPACE`. Mesmo com espaço estimado suficiente,
`checkpointReserveProven=false`, `fullSha256Performed=false` e todos os
privilegios operacionais ficam falsos. O mínimo de espaço não implica
recuperação Windows, já que checkpoint, GPT/ESP/BCD/WinRE e reboot não foram
medidos nem restabelecidos.

A suite `test_authenticated_destination_scale.py` usa um RAW sintético
esparso de 128 GiB e QCOW2 criado por `qemu-img` numa pasta privada do
runner descartável. Testa `PosixPath` válido, troca de FD, backing/alias,
limites de alocação, espaço insuficiente, leitura curta, symlink e recusa de
writer. **Não utiliza uma instalação Windows real de 128 GiB.** A matriz
A-J do pedido fica dividida entre esta suite e os testes QEMU/FD anteriores
em `test_authenticated_destination_readonly.py`, incluindo checkpoint alias
no contrato integral <=512 MiB. Os testes de escala NÃO substituem os testes
de conteúdo ou a revisão Safety. Branch de qualificação separada da PR #337;
CI do HEAD de escala por comprovar antes de qualquer integração.


### CI de escala — execução GREEN no código exato

A [Action #45034223975](https://github.com/LMhdez/gaslux/actions/runs/45034223975)
terminou **SUCCESS** no commit de implementação
`049f1799a7296e3891dabd8be869cf4de3eb5c85`: 12 novos testes de
metadados, suites QEMU parado, #327 BZD-DEST-01, #267 e regressões HOST/FD,
Ruff e compileall. [Documentação #45034226613](https://github.com/LMhdez/gaslux/actions/runs/45034226613)
também passou. A documentação acrescentada depois deste commit necessita da
própria validação exact-head; não confundir testes de RAW esparso com
Windows genuíno, hash de 128 GiB ou checkpoint/rollback.
