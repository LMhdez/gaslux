# Contratos partilhados — Gaslux

> Revisão documental: 2026-11-19. Autoridade: [ARCHITECTURE.md](https://github.com/LMhdez/gaslux/blob/dev/docs/ARCHITECTURE.md), [AGENTS.md](https://github.com/LMhdez/gaslux/blob/dev/AGENTS.md), [AI_POLICY.md](https://github.com/LMhdez/gaslux/blob/dev/AI_POLICY.md). O presente documento especifica critérios para implementação; não certifica implementações ou testes ausentes.

## Semântica de evidência
- **DOCUMENTADO**: orientação de fonte primária indicada por URL e, quando aplicável, versão.
- **IMPLEMENTADO**: código identificado por caminho/ref; sem implicar execução correcta.
- **COMPROVADO**: resultado real, commit exacto, execução Actions e artefacto verificável; indicar especificamente o que foi provado.
- **PENDENTE**: falta prova ou investigação; nunca preencher parâmetros, hashes ou comandos por conjectura.
- **BLOQUEADO**: preflight deve negar antes de qualquer modificação.
Um CI verde de fixture não é prova de instalação nem de Windows recuperado.

## 1. Preflight e fronteira de autorização
[IMPLEMENTADO — arquitectura] Windows WPF/C# e PowerShell produzem plano; o Linux revalida-o. Validar modo firmware real, tabela real, identidade física (serial/WWN/GPT disk GUID ou assinatura MBR, sempre cruzados), tamanho e sector lógico/físico, geometria em bytes, offsets de todas as partições, tipo e sistema de ficheiros, espaço reservado e shrink NTFS efectivamente suportado. Em vários discos, seleccionar por identidade estável e negar ambiguidades. Capturar Windows Boot Manager, BCD, WinRE, ESP, Recovery/OEM, BitLocker/Device Encryption, estado de hibernação, partição activa BIOS, NVRAM BootOrder/BootNext UEFI, política Secure Boot e chaves de confiança sem alterá-las. Não inferir permissão de escrita do simples facto de uma partição estar vazia.

## 2. Integridade e cadeia de confiança
[IMPLEMENTADO — arquitectura] O catálogo e releases são assinados; resolver uma distribuição por versão exata, tamanho exacto, SHA-256 validado, identidade interna e capacidades permitidas. Para ISO e handoff, ligar todos os artefactos ao transaction ID, hash e disco autorizado. Não substituir uma assinatura upstream por um SHA publicado numa PR. Se a cadeia da assinatura upstream não foi verificada, registar PENDENTE. Sem override da assinatura em produção. Assinar o plano / autenticar o handoff conforme o protocolo que o projecto venha a definir e testar; não declarar que qualquer checksum isolado constitui autenticação.

## 3. Plano tipado, máquina de estados e ownership
[IMPLEMENTADO — arquitectura] [InstallationPlanFactory](https://github.com/LMhdez/gaslux/blob/dev/Installation/InstallationPlanFactory.cs) é a referência nominal do contrato Windows (confirmar localização na revisão). [InstallationExecutionLedger](https://github.com/LMhdez/gaslux/blob/dev/Installation/InstallationExecutionLedger.cs), `Installation/InstallationStateMachine.cs`, `Scripts/modules/Libertix.InstallationState.psm1` e `assets/live/libertix-installation-state.py` mantêm a ordem de transições. O schema em `schemas/` é a autoridade para documentos persistidos. Nenhuma etapa pode ser saltada para declarar sucesso. Revalidar antes/depois de cada escrita e após reboot. Gravar checkpoint durável em duas fronteiras de confiança apropriadas; publicar atomicamente, fazer flush e conferir hash. A posse de uma partição não se infere de label, /dev/sdX ou letra Windows: exige ligação à identidade e geometria fixadas no plano e ao evento de criação transaccional.

## 4. Escritas e rollback
[BLOQUEADO sem prova] Mutação apenas de intervalos autorizados, sobre VM descartável expressamente autorizada, com snapshot/backing imutável, recuperação armada e limites definidos. Proibir apagar/mover/formatar Windows, OEM, Recovery, ESP ou artefactos alheios. Em BIOS/MBR validar os quatro slots, extensão/EBR, assinatura e sector real; não reescrever cadeia EBR sem prova. Em UEFI/GPT proteger ESP existente e Windows EFI, partições GPT reservadas, GUIDs, BootOrder e BootNext; nunca assumir que BootNext reverte sozinho. Verificar compensação de cada etapa completada e comparar geometria, dados/boot críticos, Windows arranca, WinRE/BCD e estado de encriptação com baseline. Remover apenas artefactos cuja ownership seja demonstrada. Falha ou divergência implica estado NÃO RECUPERADO, nunca sucesso baseado em log.

## 5. Boot e handoff
[IMPLEMENTADO — arquitectura] Windows prepara staging e próximo boot; ambiente Live verifica plano e hardware antes de instalar; sistema instalado produz evidência ligada ao plano; Windows valida o regresso. O firmware adapter BIOS e o UEFI têm responsabilidades diferentes; não compartilhar comandos de instalação de bootloader entre distribuições por analogia. Uma estratégia de loopback ISO só é autorizável depois de validar módulos do bootloader, drivers do initramfs, descoberta da ISO e disponibilidade do sistema de ficheiros em teste real da versão exacta. Secure Boot desligado não valida assinatura de cadeia final; Secure Boot ligado requer autoridade aceite e ausência de enrollment manual.

## 6. Falhas obrigatórias
Testar: hash/assinatura falsa, identidade ISO trocada, ISO truncada, perda de rede, falta de espaço, interrupção em cada fronteira, SIGKILL/power-cut, disco permutado ou UUID divergente, GPT alterada, EBR ambíguo, BitLocker activo, NVRAM sem capacidade, EFI ocupada, falha de pacote/bootloader, alteração de kernel e energia cortada durante update. Cada falha tem de terminar sem escrita ou com rollback comprovado.

## 7. Níveis de teste, sem equivalências indevidas
1. Contratos estáticos/fixtures/lint (não escrevem discos).
2. Inspecção de ISO assinada e Live boot (não é instalação).
3. Instalação nativa no disco VM identificado e primeiro arranque sem ISO.
4. Windows real + Linux instalado no mesmo disco/segundo disco, ambos a arrancar.
5. Actualização de kernel e loader, arranque dos dois sistemas.
6. Desinstalação e rollback após falhas, com provas de Windows, WinRE, BCD e geometria.
7. Hardware físico apenas mediante autorização, backups e restauro comprovado.
Prova de execução = commit + workflow/run + artefactos de guest + hashes + relatório de verificações independente. A existência de PR não satisfaz nenhum nível.

## 8. CI e documentação de revisão
[DOCUMENTADO — CONTRIBUTING] Validadores candidatos: `dotnet test`, testes Pester em `PowerShell.Tests/`, `pytest`, `ruff check`, `ruff format --check`, ShellCheck e compilação WPF em runner Windows. Executar os comandos definidos nos workflows do HEAD; não presumir que a máquina local contém PowerShell/.NET/QEMU. Não correr testes que possam escrever disco nesta missão. A integração de CI tem de preservar regressões Mint/Zorin e bloquear catálogo estável para backends experimentais.

## 9. Plano de evidência por transição
| Transição | Evidência exigida | Recuperação se falhar |
|---|---|---|
| Preflight → download | identidade hardware, encriptação, WinRE/BCD e snapshot de geometria | nenhuma escrita permitida |
| Download → staging | catálogo assinado, ISO hash/tamanho, identidade interna | descartar só download possuído |
| Staging → boot Live | intervalos possuídos, estado/boot anterior e handoff autenticado | restaurar estado firmware/BCD e remover staging possuído |
| Live → target | GUID/offset/UUID verificados e checkpoint anterior | remover apenas target possuído e validar Windows |
| Target → bootloader | Windows EFI/BCD intactos, backup transaccional e hash | restaurar exclusivamente alterações possuídas, testar Windows |
| Bootloader → first boot | boot autónomo de Linux instalado, kernel/root/account | rollback se falhar, sem chamar Live boot de sucesso |
| First boot → Windows | Windows real com WinRE/BCD/ESP preservados | reactivar recuperação e estado incompleto |
| Update/uninstall → done | arranques de ambos pós-update ou Windows pós-removal; geometria comparada | NÃO RECUPERADO sem provas finais |

## 10. Regras para executores one-shot
Ao primeiro dado contraditório, STOP antes de escrita; indicar campo, valor esperado, valor real, fase e artefacto de prova. Cada backend deve fornecer adapters específicos para verificação da ISO, handoff, instalação nativa, configuração, bootloader, actualizações, first boot, remoção. Não alterar `release-config.json`, `schemas/`, `Installation/`, `Scripts/`, `assets/live/` numa PR documental. Antes de qualquer PR funcional, confirmar HEAD/PRs dependentes e resultados reais mais recentes. A revisão humana continua obrigatória.


## 11. Inventário de código comprovado na branch `dev` (2026-11-19)

| Contrato | Ficheiro(s) exacto(s) em `dev` | O que **não** provam |
|---|---|---|
| Gates e dispatch | [`Installation/DistributionBackendPolicy.cs`](https://github.com/LMhdez/gaslux/blob/dev/Installation/DistributionBackendPolicy.cs), [`DistributionCapabilityPolicy.cs`](https://github.com/LMhdez/gaslux/blob/dev/Installation/DistributionCapabilityPolicy.cs) | Autoriza **somente Mint e Zorin** no backend legado; perfil validado de candidato não é instalação disponível |
| Capacidade partilhada | [`schemas/distribution-capabilities.schema.json`](https://github.com/LMhdez/gaslux/blob/dev/schemas/distribution-capabilities.schema.json), [`Scripts/modules/Gaslux.DistributionCapabilities.psm1`](https://github.com/LMhdez/gaslux/blob/dev/Scripts/modules/Gaslux.DistributionCapabilities.psm1), [`assets/live/gaslux_distribution_capabilities.py`](https://github.com/LMhdez/gaslux/blob/dev/assets/live/gaslux_distribution_capabilities.py) | Atributo `lab-only` ou `unavailable` não se converte em `released`; backends experimentais ficam bloqueados |
| Aquisição confiável | [`Installation/DistributionCatalogLoader.cs`](https://github.com/LMhdez/gaslux/blob/dev/Installation/DistributionCatalogLoader.cs), [`DistributionCatalogTrust.cs`](https://github.com/LMhdez/gaslux/blob/dev/Installation/DistributionCatalogTrust.cs) | Um SHA de ISO não é uma assinatura upstream; validação catalog v2 é distinta da identidade do SO instalado |
| Plano e estado | [`Installation/InstallationPlanFactory.cs`](https://github.com/LMhdez/gaslux/blob/dev/Installation/InstallationPlanFactory.cs), [`Installation/InstallationExecutionLedger.cs`](https://github.com/LMhdez/gaslux/blob/dev/Installation/InstallationExecutionLedger.cs), [`Installation/InstallationStateMachine.cs`](https://github.com/LMhdez/gaslux/blob/dev/Installation/InstallationStateMachine.cs), [`Scripts/modules/Libertix.InstallationState.psm1`](https://github.com/LMhdez/gaslux/blob/dev/Scripts/modules/Libertix.InstallationState.psm1), [`assets/live/libertix-installation-state.py`](https://github.com/LMhdez/gaslux/blob/dev/assets/live/libertix-installation-state.py) | Atomicidade/ledger não são prova criptográfica de handoff ou de Windows boot |
| Boot mini-ISO actual | [`Scripts/config/Libertix.BootArguments.json`](https://github.com/LMhdez/gaslux/blob/dev/Scripts/config/Libertix.BootArguments.json) e [`Installation/LiveBootArguments.cs`](https://github.com/LMhdez/gaslux/blob/dev/Installation/LiveBootArguments.cs) | `boot=live toram components` e `/live/vmlinuz` dizem respeito à **mini-ISO Libertix**, não à ISO do Mint/Zorin/Archiso/Pop/Bazzite/Q4OS |
| Descoberta SquashFS | [`assets/live/libertix-distribution-common.sh`](https://github.com/LMhdez/gaslux/blob/dev/assets/live/libertix-distribution-common.sh) e [`libertix-install-main.sh`](https://github.com/LMhdez/gaslux/blob/dev/assets/live/libertix-install-main.sh) | A presença de `dpkg` + `update-initramfs` e extracção de raiz não é prova de que instalador Ubuntu/Mint ou Zorin foi executado |
| Diagnóstico e handoff candidato | [`assets/live/gaslux_lab_media_probe.py`](https://github.com/LMhdez/gaslux/blob/dev/assets/live/gaslux_lab_media_probe.py), [`gaslux_candidate_handoff.py`](https://github.com/LMhdez/gaslux/blob/dev/assets/live/gaslux_candidate_handoff.py) | Os próprios outputs declaram `signedCatalogVerified=false`, `installationAuthorized=false`; chave Ed25519 é apenas laboratório |
| Auditoria de target | [`assets/live/gaslux_candidate_target_audit.py`](https://github.com/LMhdez/gaslux/blob/dev/assets/live/gaslux_candidate_target_audit.py) | Ficheiros de instalação presentes **não** provam block-device de root, ESP, NVRAM nem boot Linux/Windows |

### Forma persistida vs assinatura e validação
[IMPLEMENTADO no código inspeccionado] O **catálogo de release** é assinado. O **plano de instalação** é tipado, validado e publicado atomicamente pelo Gaslux, mas **não afirmar que qualquer documento de plano tem assinatura própria** sem prova do algoritmo, chave, localização, anti-replay e ligação ao disco. O *handoff* Ed25519 da PR #248 é uma **autoridade de ensaio isolada**, não de produção. O novo backend necessita de protocolo de autorização documentado e auditado: transaction ID imutável + disco físico + geometria + nonce/expiração + versão do backend + hashes dos programas + provas de protecção Windows + capability assinada; cada runtime valida, nunca confia só em marcador da partição.

### Checkpoints e terminalidade
[IMPLEMENTADO] A ordem actual em `InstallationStateMachine.cs` é `windows.preflight-verified` (ver valor persistido de `InstallationStep`) até `target.installation-verified`, passando pela recuperação armada, criação do staging, Live preflight, root filesystem e bootloader. Os nomes acima são **semântica aproximada**; obter as strings canónicas de `Installation/InstallationExecutionState.cs` e dos módulos PowerShell/Python, nunca fabricá-las em eventos. A actualização de um passo e o checkpoint durável precisam de sobrevivência a reboot e validação independente. Um estado `succeeded` não significa arranque Windows verificado se não houver prova de guest.

### Catálogo de provas reais (19-11-2026)
- **CachyOS, só Linux:** [CI #44563479551](https://github.com/LMhdez/gaslux/actions/runs/44563479551), [artefacto #14554036041](https://github.com/LMhdez/gaslux/actions/runs/44563479551/artifacts/14554036041): Archiso+pacstrap+GRUB EFI, update pacman e boot após rollback por overlay, **sem Windows**.
- **CachyOS + Windows-backed COW:** [CI #44571015093](https://github.com/LMhdez/gaslux/actions/runs/44571015093), [artefacto #14556716731](https://github.com/LMhdez/gaslux/actions/runs/44571015093/artifacts/14556716731): quinta ext4 pacstrap, arranque mínimo e descarte COW, **não rollback in-place**.
- **Zorin só Linux:** [CI #44582546627](https://github.com/LMhdez/gaslux/actions/runs/44582546627), [artefacto #14560995967](https://github.com/LMhdez/gaslux/actions/runs/44582546627/artifacts/14560995967): dois boots após `update-initramfs`, **sem Windows**.
- **Mint:** [CI #44572398014](https://github.com/LMhdez/gaslux/actions/runs/44572398014), **FAILURE** no testemunho de shutdown COW; sem prova de instalação nativa/rollback.
- **Pop:** [CI #44561473570](https://github.com/LMhdez/gaslux/actions/runs/44561473570), **FAILURE** na quinta partição `blkid`; nenhum `distinst` executado.
- **Bazzite:** [CI #44576081171](https://github.com/LMhdez/gaslux/actions/runs/44576081171), **FAILURE** na selecção `Custom`; nenhuma escrita autorizada.
- **Q4OS:** [PR #256](https://github.com/LMhdez/gaslux/pull/256) fornece auditoria da configuração Calamares e segurança de evidências, **não** uma instalação nativa/Windows.
- **PR documental actual:** [CI #44632328684](https://github.com/LMhdez/gaslux/actions/runs/44632328684) e [#44632328671](https://github.com/LMhdez/gaslux/actions/runs/44632328671) passaram *fixtures* de recuperação no HEAD inicial da documentação; não são validação das ISOs nem da documentação recentemente actualizada.

### Regras de recuperação comprovável versus descarte COW
O descarte de um overlay QCOW2 sem mutar a base demonstra que **a base ficou protegida** no laboratório; não demonstra uma compensação in-place de ESP, GPT/EBR ou WinRE após escritas reais sobre o Windows. Estas são provas com níveis diferentes. Exigir antes de autorizar escrita em VM um journal transaccional dos **intervalos exactos**, snapshots, hashes e mecanismo de compensação para esse sistema; comparar EFI/MBR/BCD/WinRE, encriptação e boots Windows de verdade na fase final. Não inferir resistência a power-cut de simples `SIGTERM` ou saída voluntária.

## 2026-11-22 — AUTHENTICATED-DESTINATION-01 (read-only host QEMU FD composition)

[PR Draft #337](https://github.com/LMhdez/gaslux/pull/337) joins existing
#325 Observer ProcessSeal/QemuLocalDiskWitness/QMP read-only diagnostics,
canonical GPT `inspect_gpt_fd` and the SHA-pinned #267 no-writer decision.
New module `auto_tests/installer_observer/authenticated_destination.py`
examines actual private QCOW2, backing RAW and checkpoint **open FDs**,
file identity/size/mtime/ctime, bounded SHA-256, QCOW2 backing configuration
from `qemu-img info`, raw GPT primary/backup and declared transaction,
owned extents and checkpoint. Nine attack classes (plus RAW/checkpoint alias
tests) exercise real disposable files and a stopped QEMU. They reject
destination rename/replacement, foreign FDs, backing swap, GPT geometry
mismatch, transaction/ownership mismatch, altered checkpoint and fabricated
guest provenance. A structurally valid fixture returns
`READONLY_STRUCTURE_OBSERVED` and `DENY_NO_WRITER` **only**.

**Exact CI:** [#45032388422](https://github.com/LMhdez/gaslux/actions/runs/45032388422)
and [#45032391998](https://github.com/LMhdez/gaslux/actions/runs/45032391998)
SUCCESS on `d2e382a60120d09a0b225e4188309f48f0315845`;
[Windows fixture #45032392037](https://github.com/LMhdez/gaslux/actions/runs/45032392037)
and [CachyOS fixture #45032392005](https://github.com/LMhdez/gaslux/actions/runs/45032392005)
also SUCCESS at that HEAD. Host-only observer, test-owned temporary regular
files, **no guest launch**, guest-authentication, installer, disk writer,
boot or in-place rollback. QMP consistency **does not** independently bind
the internal QEMU backend pointer to the original FD. The QCOW2 backing
RAW GPT is **not** the guest-visible GPT. Checkpoint bytes/hash are not
proof of Windows recovery. ISO/OCI signed provenance remains per-backend.
See [detailed property matrix](../AUTHENTICATED_DESTINATION_READONLY.md).

## 2026-11-22 — 128 GiB sparse virtual-capacity diagnostic (dependent #337)

Separate branch `fix/auth-dest-128g-readonly-20261122` preserves the
parent #337 at `7e0d1a27aa16f012fae41e2979fc9791066a7ee7`.
It adds a bounded **structural** read-only observer for 128 GiB sparse RAW
backing behind a small QCOW2 overlay (QEMU stopped). The 128 GiB virtual
capacity is **not** the apparent host QCOW2 length or its allocated disk
blocks. The experiment obtains the GPT via canonical FD parser without
hashing 128 GiB. It **explicitly refuses**
`FULL_BACKING_HASH_NOT_COMPLETED` after measuring structure and returns
`DENY_NO_WRITER` only in bounded failure diagnostics; never claims
authenticated full disk contents or a genuine Windows source/checkpoint.

Independent Safety D-337-01 on the unchanged parent found a real positive
short-`pread` hole in the old full-hash function. The dependent branch
fixes exact length and cumulative-byte accounting, plus full checkpoint
receipt reads, with RED/GREEN regression. It does **not** merge a finding
away or change the parent during its audit. Detailed limits and unproven
trust boundaries: [AUTH_DEST_128G_READONLY](../AUTH_DEST_128G_READONLY.md).

[Read-only CI #45034846402](https://github.com/LMhdez/gaslux/actions/runs/45034846402)
**SUCCESS** at `6a94093271610dbd2ff908c2b8692e332e1585a1`.
No production write, guest boot, Windows restoration, ESP/BCD/WinRE,
firmware changes, full RAW hash or release/stability authority.

## 2026-11-22 — canonical #342/#346 composition (experimental DENY-ONLY)

[Draft PR #356](https://github.com/LMhdez/gaslux/pull/356) selects the
stronger #346 `assess_sparse_128g_readonly` as its **sole proposed**
large-sparse read-only contract. After examining #342, only its unique
32-byte QCOW2 version/capacity checks, `statvfs` full-checkpoint
capacity *estimate*, and final allocated-block remeasurement were
added. `probe_destination_scale_metadata` from #342 is **not imported**
or duplicated, and the newer #337 D-337-01 full-SHA guard and RED
tests are preserved. Both earlier PRs remain open Draft; no merge.

[Actions #45037589606](https://github.com/LMhdez/gaslux/actions/runs/45037589606)
and [#45037640437](https://github.com/LMhdez/gaslux/actions/runs/45037640437)
**SUCCESS on composition code HEAD `72106b2dfe4d38612ea37cdc8b0618a33298fa9e`**,
including unchanged #342 historical tests and current #346 actual
stopped-QEMU 128GiB/GPT/checkpoint negatives, #337 D-337-01,
#327/#267/HOST-FD, schema, Ruff. Even structurally valid 128GiB
resources raise `FULL_BACKING_HASH_NOT_COMPLETED` and deny writes.
No genuine Windows backing, independent guest, rollback or stable claim.
See [comparison and limits](../AUTH_DEST_342_346_CANONICAL.md).

## 2026-11-22 — non-destructive #346 fixed + #356 QCOW2 differential

Draft #356 reconciles original child `83489eee123c124266b0c514b8f20e6e19ca9bc2` with corrected parent #346 `49389810a46d43bee407304a237b912b2faebc07` via a non-destructive two-parent merge. The `_bounded_info()` subprocess cleanup is byte-for-byte identical to the exact #346 version [independently approved for that parent only](https://github.com/LMhdez/gaslux/pull/355#issuecomment-7083769456). #356's 32-byte QCOW2 v2/v3/header capacity checks, `statvfs` checkpoint estimate, final `st_blocks` comparison, dedicated original #342 checks and synthetic regressions remain. The original [Safety-2 #355](https://github.com/LMhdez/gaslux/pull/355) oracle is pinned by immutable ref in the existing #356 workflow, and a new exact-head CI plus fresh independent Safety-2 differential assessment are required. `checkpointReserveProven=false`, `checkpointRestorationProven=false`, `FULL_BACKING_HASH_NOT_COMPLETED`, `DENY_NO_WRITER` and all writer/rollback/guest flags remain denied; no extra API, install, real Windows recovery or release promotion is introduced.

### 2026-11-22 — #356 exact-head composed read-only regressions

#356 code HEAD `a6e2f01ee061f05917eb1930dadbc1dfb099905d` preserves the approved parent #346 process-group cleanup and separate #356 QCOW2 header/statvfs/allocation improvements. [QEMU push #45057466420](https://github.com/LMhdez/gaslux/actions/runs/45057466420), [QEMU PR #45057470701](https://github.com/LMhdez/gaslux/actions/runs/45057470701) and [docs #45057470700](https://github.com/LMhdez/gaslux/actions/runs/45057470700) PASS, including original immutable #355 Safety oracle 15-case suite. This is still a **draft candidate awaiting independent differential Safety**, not writer authority or whole-disk integrity proof. All 128GiB responses remain `FULL_BACKING_HASH_NOT_COMPLETED` / `DENY_NO_WRITER`; checkpoint capacity remains an estimate, never reserved or restored.

## 2026-11-22 — dev chain reconciliation of #356 (still DENY-ONLY)

Original #356 `4886c1e7f1f835c71cf2fe1351ff834e92bea334` carries Safety-2 technical approval for composed blob `a1a6364b12cf9a6b988eb124e2aa66e374c32cfe`. Propagation after #337/#346 dev merges preserves that byte-identical module while retaining the exact historical #355 oracle. The new branch HEAD must independently pass applicable workflows before any dev merge. This host-only contract never authorizes writes, Guest attestation, Windows recovery, checkpoint reservation, or a complete 128GiB RAW digest. Preserve `FULL_BACKING_HASH_NOT_COMPLETED` and `DENY_NO_WRITER`.
