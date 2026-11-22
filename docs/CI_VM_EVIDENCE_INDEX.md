# Gaslux — índice de GitHub Actions, QEMU e níveis de evidência

> Inventário de referência: 2026-11-22 UTC. Obtido por inspeção dos **19 workflows existentes em dev** e de YAMLs referenciados nas PRs históricas/abertas. Não é uma garantia de execução recente, nem um inventário completo de todas as branches antigas. Para cada trabalho, ler o YAML **no HEAD exato da PR** e os scripts chamados; vários títulos mencionam QEMU sem executar um guest.

## Manutenção contínua do índice GitHub Actions / VMs

**Rever e atualizar este índice** quando um workflow/branch de laboratório for criado, modificado, integrado ou encerrado, ou quando uma Action trouxer uma nova prova material. Confirmar o YAML e os scripts de `dev` **e do HEAD de PR relevante**, condições `if`, permissões, `workflow_dispatch`, resultados de cada job, SKIPPED, consents, artifacts e dados de boot. A contagem de 19 workflows abaixo é um **instantâneo de 22-11-2026**, não uma consulta dinâmica.

A atualização deve trazer data UTC, SHA exato, PR e URL da execução, tipo de prova (CONTRACT / SYNTHETIC_DISK / QEMU_PROTOCOL / LIVE_GUEST / INSTALLED_GUEST / WINDOWS_GUEST / SHARED_DISK_DUAL_BOOT / RECOVERY), bloqueios, limitações e regressões. O Integrador mantém coerência pós-merge; os agentes Backend, Safety e Observer atualizam as linhas da sua competência. `qemu-img` não implica guest boot e a palavra QEMU num workflow não substitui uma observação real.

Não voltar a executar QEMU apenas para mudar a data de documentação. A atualização é obrigatória nos eventos relevantes, **não um monitorizador autónomo**. Consultar [AGENTS.md](../AGENTS.md), [AI_POLICY.md](../AI_POLICY.md) e o [manual histórico](AGENT_HISTORICAL_PLAYBOOK.md).

## 1. O que os resultados significam

| Categoria | O que a CI precisa demonstrar | O que NÃO demonstra |
| --- | --- | --- |
| CONTRACT / STATIC | pytest, Pester, .NET, Ruff, ShellCheck, schemas, fontes e fixtures, com logs no HEAD | Boot ou Windows real |
| SYNTHETIC_DISK | qemu-img/qemu-io, GPT/NTFS/ESP sintética, hashes/checkpoints de ficheiros privados | QEMU-system ou sistema operativo iniciado |
| QEMU_PROTOCOL | Processo QEMU/HMP/QMP ou socket local e troca de mensagens com endpoint controlado | Boot do sistema operacional |
| LIVE_GUEST | Processo QEMU-system com ISO verificada, kernel e userspace observados, serial ou outro witness ligado à VM | Root instalado nem primeiro boot sem ISO |
| INSTALLED_GUEST | Install real no QCOW2 e segundo QEMU sem mídia live, kernel/root/bootloader instalados observados | Windows coexistente |
| WINDOWS_GUEST | Setup/boot Windows genuíno em QCOW2 privado, build/proveniência e testemunhas de boot | Instalação Linux no mesmo disco |
| SHARED_DISK_DUAL_BOOT | Windows e Linux instalados no mesmo layout de VM, arrancados em sequência, GPT/ESP/BCD/WinRE e atualização verificadas | Recuperação pós-falha se não ensaiada |
| RECOVERY | Fault injection, restore ao baseline verificável, Boot Manager/WinRE/BCD/EFI, BitLocker e discos alheios preservados | Segurança em hardware físico |

**Não basta grep ao YAML:** considerar `if:`, triggers, dependências, consent variables, conclusões SKIPPED, red/green esperado, SHA da execução, logs, artefactos e witness host/guest. `qemu-img` não é `qemu-system`. `runs-on: windows-2022` não é uma VM Windows convidada dentro de QEMU.

## 2. Workflows identificados em dev (19)

A lista da pasta .github/workflows em dev à data inclui:

| Tipo | Workflows | Inspeção |
| --- | --- | --- |
| Live QEMU real (disponível em dev) | [Mint 22.3 live OVMF](../.github/workflows/mint-223-live-ovmf-boot.yml), [Zorin real ISO preflight](../.github/workflows/zorin-real-iso-preflight.yml), [Q4OS official ISO](../.github/workflows/gaslux-q4os-official-iso.yml) | Os YAML incluem QEMU-system/OVMF e etapas de guest live; não afirmam instalação completa. |
| Windows no runner (contratos, não Windows guest) | [windows-guest-recovery-evidence](../.github/workflows/windows-guest-recovery-evidence.yml), [cachyos-windows-recovery-evidence](../.github/workflows/cachyos-windows-recovery-evidence.yml), [multidistro-legacy-backend](../.github/workflows/multidistro-legacy-backend.yml) | Testes Pester/Python/.NET e fixtures; examinar o job exato. |
| Safety/GPT offline | [gpt-identity-gate](../.github/workflows/gpt-identity-gate.yml), [gpt-fd-crosscheck-compat-offline](../.github/workflows/gpt-fd-crosscheck-compat-offline.yml), [windows-ntfs-safety-regression](../.github/workflows/windows-ntfs-safety-regression.yml), [protected-authority-readiness-offline](../.github/workflows/protected-authority-readiness-offline.yml) | Não inferir QEMU operacional ou writes. |
| Observer offline | [observer-evidence-readonly-subset](../.github/workflows/observer-evidence-readonly-subset.yml), [observer-one-shot-ledger-offline-static](../.github/workflows/observer-one-shot-ledger-offline-static.yml), [observer-synthetic-boundary-offline](../.github/workflows/observer-synthetic-boundary-offline.yml) | Testam fronteiras de confiança sem controlo guest. |
| Distro metadata/qualidade | [gaslux-bazzite-atomic-origin](../.github/workflows/gaslux-bazzite-atomic-origin.yml), [gaslux-bazzite-iso-signature](../.github/workflows/gaslux-bazzite-iso-signature.yml), [gaslux-lab-media-probe](../.github/workflows/gaslux-lab-media-probe.yml), [distro-dossiers-static](../.github/workflows/distro-dossiers-static.yml), [distro-ui-schema-offline](../.github/workflows/distro-ui-schema-offline.yml), [bootstrap-libertix](../.github/workflows/bootstrap-libertix.yml) | Fonte/ISO/CI documental; não pressupor arranque guest. |

A presença de um workflow em dev não garante sucesso no commit mais recente. Ver a [página Actions](https://github.com/LMhdez/gaslux/actions).

## 3. Workflows e laboratórios históricos noutras branches

Estas referências são **pistas para reutilização**. Podem existir apenas em commits/branches históricos, ou ter sido encerradas e substituídas. Alguns YAML foram inspecionados diretamente na branch PR; outros têm apenas a descrição da PR como evidência. **Não os copiar para dev em bloco.**

| Família | Origem | Workflows / experiência observada no código ou PR | Nível máximo a reconfirmar por logs |
| --- | --- | --- | --- |
| CachyOS instalação isolada | [#36](https://github.com/LMhdez/gaslux/pull/36), [#42](https://github.com/LMhdez/gaslux/pull/42) | cachyos-official-iso, cachyos-backend-tests; Archiso, pacstrap, segundo boot sem ISO, updates/GRUB, overlays e SIGKILL | INSTALLED_GUEST, depois atualização isolada — sem Windows |
| CachyOS + Windows | [#180](https://github.com/LMhdez/gaslux/pull/180), [#192](https://github.com/LMhdez/gaslux/pull/192), [#205](https://github.com/LMhdez/gaslux/pull/205), [#248](https://github.com/LMhdez/gaslux/pull/248), [#263](https://github.com/LMhdez/gaslux/pull/263), [#279](https://github.com/LMhdez/gaslux/pull/279) | windows-x64-two-stage-firstboot, cachyos-windows10-real-archiso-readonly, cachyos-win10-shared-archiso-prewrite-e2e, cachyos-windows10-shared-root-pacstrap | WINDOWS_GUEST / read-only Archiso / target COW; mesmo disco dual boot e rollback por verificar por run |
| Windows/QEMU | [#217](https://github.com/LMhdez/gaslux/pull/217) | windows-x64-ovmf-usb-input-smoke; windows-hmp-prompt-ack-regression | HMP em QEMU pode correr **sem guest Windows** |
| Mint | [#204](https://github.com/LMhdez/gaslux/pull/204), [#233](https://github.com/LMhdez/gaslux/pull/233), [#271](https://github.com/LMhdez/gaslux/pull/271), [#274](https://github.com/LMhdez/gaslux/pull/274), [#276](https://github.com/LMhdez/gaslux/pull/276), [#278](https://github.com/LMhdez/gaslux/pull/278) | mint-cow-proof-contracts, mint-ab-forensic-checkpoint, mint-ab-cross-arm-integrity, mint-ab-f03-evidence; Windows+Mint e forense A/B | Distinguir guest real, qemu-img e mocks; relatar ESP/Recovery não atribuídas |
| Zorin | [#264](https://github.com/LMhdez/gaslux/pull/264), [#277](https://github.com/LMhdez/gaslux/pull/277) | zorin-windows10-cow-firstboot, zorin-synthetic-writeset | Live/instalação experimental e write-set sintético não são equivalentes |
| Pop!_OS | [#232](https://github.com/LMhdez/gaslux/pull/232), [#291](https://github.com/LMhdez/gaslux/pull/291), [#298](https://github.com/LMhdez/gaslux/pull/298), [#324](https://github.com/LMhdez/gaslux/pull/324) | windows10-popos-signed-live-same-cow (descrito na PR histórica); popos-six-gpt-preflight-only usa qemu-img/qemu-io mas explicitamente NO QEMU-system | LIVE_GUEST experimental vs SYNTHETIC_DISK — não combinar as provas |
| Q4OS Windows | [#231](https://github.com/LMhdez/gaslux/pull/231), [#299](https://github.com/LMhdez/gaslux/pull/299), [#318](https://github.com/LMhdez/gaslux/pull/318) | gaslux-q4os-windows10-qcow2 e gaslux-q4os-windows-boundary com QEMU/QMP; gaslux-q4os-qmp-offline **sem QEMU-system** | Windows/QMP sintético e offline devem ser classificados separadamente |
| Q4OS UI | [#258](https://github.com/LMhdez/gaslux/pull/258), [#270](https://github.com/LMhdez/gaslux/pull/270) | q4os-summary-repro-2vm, q4os-ui-repro-2vm: dois guests OVMF e screenshots reais da página Users/Summary; STOP antes de Install | LIVE_GUEST + UI observada; não instalação |
| Bazzite | [#250](https://github.com/LMhdez/gaslux/pull/250), [#262](https://github.com/LMhdez/gaslux/pull/262), [#280](https://github.com/LMhdez/gaslux/pull/280), [#320](https://github.com/LMhdez/gaslux/pull/320) | gaslux-bazzite-official-iso-ovmf e bazzite-iso-public-readback; bazzite-iso45-evidence-replay **não executa guest**; Bazzite OCI/bootc readback é host-only | ISO/trust e UI/OCR experimental; não writer nem dual boot |
| Observer | [#259](https://github.com/LMhdez/gaslux/pull/259), [#267](https://github.com/LMhdez/gaslux/pull/267), [#269](https://github.com/LMhdez/gaslux/pull/269), [#273](https://github.com/LMhdez/gaslux/pull/273) | installer-observer-lab (2 QEMU isolados), installer-observer-gpt-readonly, safety-qemu-gpt-host-guest, safety-windows10-qemu-no-writer, observer-gpt-qemu-one-shot (gate restrito) | HOST/QEMU/GPT read-only, sem guest input autorizado |

**Evidências históricas explícitas:** [CachyOS primeiro boot #43954231860](https://github.com/LMhdez/gaslux/actions/runs/43954231860), [Mint live #44147047164](https://github.com/LMhdez/gaslux/actions/runs/44147047164), [Mint Windows forense #44731118098](https://github.com/LMhdez/gaslux/actions/runs/44731118098), [Zorin dois boots #44582546627](https://github.com/LMhdez/gaslux/actions/runs/44582546627). São referências de laboratório com resultado e âmbito descritos em PRs; abrir jobs e artifacts antes de extrapolar. Não declarar que todos têm conclusão SUCCESS.

### CachyOS #314 — execução offline, não VM (22-11-2026)

O workflow `cachyos-bcd-fat32-trace-offline.yml` na [PR #314](https://github.com/LMhdez/gaslux/pull/314) executou [Actions #45020744228](https://github.com/LMhdez/gaslux/actions/runs/45020744228), **SUCCESS, 85 testes offline**, no HEAD `a341bd059916a151fa49fb58435a69945e005d5a`. Classificação: **SYNTHETIC_DISK + CONTRACT**, não `QEMU_SYSTEM`, `INSTALLED_GUEST`, `WINDOWS_GUEST`, `DUAL_BOOT` ou `RECOVERY`. A fixture RAW é esparsa, 128 GiB lógicos, só ficheiro regular temporário; análise QEMU é apenas consistência de claims e parser de trace.

Após essa execução foram adicionados recusa explícita `O_PATH` e um teste adversarial até `f5efccd50507248ca447fa5883900d951289c551`. [Action #45021184614](https://github.com/LMhdez/gaslux/actions/runs/45021184614) confirmou **SUCCESS no HEAD exato**, com 16 FAT32/QEMU + 18 ESP/RAW + 23 ETW + 29 BCD A/B = **86/86 testes offline**, compileall e Ruff; continua **sem QEMU-system nem Windows guest**. Safety diferencial ainda pendente. Captura histórica ESP QCOW2, QMP FD→`blk`, processo escritor e rollback continuam por demonstrar.

## 4. Seleção correta de workflow por missão

1. Selecionar a capacidade em falta (ISO identity, guest live, installed boot, Windows boot, update, dual boot, rollback, trust).
2. Consultar o último código e a lista de workflows em dev e na branch original; verificar também PRs fechadas com commits ainda recuperáveis.
3. Ler as condições `if`, `on`, `workflow_dispatch`, `permissions`, consents `GASLUX_*_CONSENT`, recursos de runner, mídia externa, hashes, script chamado e uploader.
4. Confirmar se a ação exige imagem Windows licenciada, credenciais, KVM, OVMF, swtpm, disco mínimo, nested virt ou fonte upstream disponível. Se faltar, relatar indisponibilidade, não falsificar prova.
5. Só escrever em **QCOW2/RAW privado, regular-file, verificado e descartável**, com snapshot/restore e imagem backing imutável; nunca em host block devices. Autorização permanente limitada em [AI_POLICY](../AI_POLICY.md).
6. Guardar SHA do código, URL/ID Action e job, status/conclusion reais, comando QEMU, host/guest witness, imagens de disco identificadas e hashes antes/depois; não publicar ISO/Windows QCOW2 ou segredos como artefactos.
7. Atualizar o dossier do backend apenas com o novo nível efetivamente provado, mantendo as fases superiores como PENDENTE.

## 5. Anti-padrões encontrados na história

- Workflow com a palavra QEMU e `SKIPPED` a ser reportado como arranque Windows.
- qemu-img/qemu-io ou libguestfs a ser confundido com QEMU-system.
- Concluir sucesso por marcador guest sem validação host de processo, disco, firmware, shutdown e correspondência ao HEAD/transaction.
- COW descartável imutável ser confundido com recuperação de uma alteração no mesmo disco Windows.
- QMP, peer Unix ou /proc PID/FD tratado como prova de guest autenticado.
- Comparar digests ESP/Recovery e afirmar causalidade sem braço Windows-only de controlo.
- Sobrescrever workflows antigos sem consultar a branch de origem e sem preservar o consent gate/segurança.
- Criar outro workflow porque o existente tem nome pouco evidente; preferir adaptar workflow já testado após rever as dependências.


## Observer HOST/FD — integração e reconciliação em dev (22/11/2026)

- [#319](https://github.com/LMhdez/gaslux/pull/319) foi integrada em `dev` por `b57bbf97057a154beeb744bcbeef710687d520b4`: HOST/FD e Local Peer de sockets Unix são diagnóstico local **DENY-ONLY**, não autenticação do guest nem associação independente QEMU→disco.
- [#312](https://github.com/LMhdez/gaslux/pull/312) foi integrada por `e382cad6760ad71df03bebf463f435f682a07508`, preservando as 16 funções históricas de teste da [#294](https://github.com/LMhdez/gaslux/pull/294). A #294 foi encerrada sem merge; a workflow antiga e os seus commits continuam recuperáveis em `e7941ef3eb26c0cae1a2d7fbe1b3009eb050c5c9`, mas não executam em `dev`.
- No HEAD de `dev` `e382cad6760ad71df03bebf463f435f682a07508`, as Actions **SUCCESS** incluem: [HOST/FD #45021654845](https://github.com/LMhdez/gaslux/actions/runs/45021654845), [Windows Recovery #45021654768](https://github.com/LMhdez/gaslux/actions/runs/45021654768), [CachyOS recovery #45021654819](https://github.com/LMhdez/gaslux/actions/runs/45021654819) e [GPT FD #45021654757](https://github.com/LMhdez/gaslux/actions/runs/45021654757). São **testes de contratos/offline**: não demonstram arranque QEMU no percurso Observer, guest autenticado, instalação, dual boot ou rollback Windows.
- **Atualização confirmada a 22/11/2026:** a [#325](https://github.com/LMhdez/gaslux/pull/325) foi **integrada em dev** no commit `8e68a475d6397ba8fef2e0f9f83758545e202a5f`, com [CI QEMU #45022336906](https://github.com/LMhdez/gaslux/actions/runs/45022336906) SUCCESS (QEMU real **parado**, imagens QCOW2/RAW descartáveis, host PID/pidfd/FD, QMP e GPT host; **não** guest boot, guest autenticado, instalação ou rollback). A #294 continua fechada sem merge direto; preservar as provas históricas separadamente.


Para contratos base e critérios de estabilidade, ver [histórico/guia de agentes](AGENT_HISTORICAL_PLAYBOOK.md), [ARCHITECTURE](ARCHITECTURE.md), [issues CachyOS #3](https://github.com/LMhdez/gaslux/issues/3) e [Bazzite #254](https://github.com/LMhdez/gaslux/issues/254).


### Observer — experiência QEMU HOST virtio-serial Guest Peer, **proveniência guest não comprovada** (22/11/2026)

Uma experiência adicional baseada em `dev` `8e68a475d6397ba8fef2e0f9f83758545e202a5f` combina o QEMU real parado de #325 com um chardev Unix associado a hardware virtio-serial, reutilizando `LocalTransportWitness` de #319. O kernel identifica o **servidor HOST QEMU**, mas, sem executar guest nem collector, **nenhum byte pode ser classificado como observação Guest atual autenticada**. Testes negativos: socket ausente, proxy local falso, processo QEMU divergente, transporte interrompido, claims forjadas e replay. Os metadados locais podem ser exportados para JSON + SHA-256 não assinado, explicitamente `NOT_INDEPENDENT` e `BLOCKED_TRUST_ROOT`. Não confundir uma conexão host↔QEMU com canal host↔guest autenticado.

**CI confirmada:** [Action #45030470016](https://github.com/LMhdez/gaslux/actions/runs/45030470016), **SUCCESS**, HEAD `131f330691b299679a46461616b5e7fa115de882`: **28 testes QEMU / Guest Peer reais + 57 regressões Observer = 85 PASS**, Ruff/format/compileall e SHA #267/#286. O [artefacto #14757198793](https://github.com/LMhdez/gaslux/actions/runs/45030470016/artifacts/14757198793) contém manifesto local JSON e SHA-256, **não assinado nem independentemente autenticado**. QEMU PID 3293 foi confirmado como peer HOST do socket `virtio-serial`; `guestBooted=false`, zero observações guest e `guestChannelAuthenticated=false`. Classificação **`QEMU_SYSTEM_STOPPED_HOST_ONLY`**, não `GUEST_BOOTED`, `INSTALLED_GUEST`, `GUEST_COLLECTOR_AUTHENTICATED`, `DUAL_BOOT` ou `WINDOWS_RECOVERY`.

### Observer GUEST-COLLECTOR-ORIGIN-01 (22/11/2026)

Experiência QEMU Linux guest mínimo **em preparação**: initramfs Linux/BusyBox de runner GitHub, collector fixo read-only no virtio-serial, UART independente como observação de boot, desafio nonce externo e ledger SQLite persistente apenas no âmbito do laboratório. O endpoint QEMU continua HOST; não é raiz de confiança Guest. Classificação bloqueada `NOT_INDEPENDENT / BLOCKED_TRUST_ROOT`; **não declarar sucesso de boot, origem independente, instalação ou rollback antes da CI exata**. Ver `docs/OBSERVER_QEMU_REAL_DISK_FD_READONLY.md` para contrato.

### Observer GUEST-COLLECTOR-ORIGIN-01 — **GUEST BOOT + LAB TRANSPORT**, NOT ATTESTED (22/11/2026 14:47 UTC)

A [Action #45034620331](https://github.com/LMhdez/gaslux/actions/runs/45034620331) passou (**SUCCESS**) no HEAD `15167cf7653f7094d83f4fafe3230d1d4d8b6be2`. QEMU real iniciou Linux `7.0.0-1017-azure` a partir de kernel APT package-owned e initramfs BusyBox descartável, com QCOW2 host test-owned read-only, sem rede. O teste confirmou marcadores de boot e execução do collector na UART guest, resposta binária limitada por virtio-serial com nonce externo, hash e contador, e recusa de replay via ledger SQLite local reaberto. O HOST vinculou QEMU PID `7787` a socket peer e dev/inode do QCOW2. Regressões Observer e casos adversariais passaram.

Artefacto: [manifesto #14758869232](https://github.com/LMhdez/gaslux/actions/runs/45034620331/artifacts/14758869232), JSON local e SHA-256, **não assinatura nem atestação independente**. Estado: `guestCollectorExecutedObserved=true`, `guestMessageReceived=true`, `hostQemuPeerAuthenticated=true`, `labReplayConsumptionVerified=true`, mas `guestOriginIndependentlyAttested=false`, `guestChannelAuthenticated=false`, `replayProtectedAgainstCompromisedHost=false`, `diskWriteAuthorized=false`, `rollbackProven=false`, `stable=false`; `BLOCKED_TRUST_ROOT`. **Nível comprovado: QEMU_SYSTEM + GUEST_BOOTED_TEST_IMAGE + LAB_MESSAGE_RECEIVED**, não instalado, atualizações, dual boot, recovery ou hardware real.
