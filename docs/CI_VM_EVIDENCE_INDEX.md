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

Para contratos base e critérios de estabilidade, ver [histórico/guia de agentes](AGENT_HISTORICAL_PLAYBOOK.md), [ARCHITECTURE](ARCHITECTURE.md), [issues CachyOS #3](https://github.com/LMhdez/gaslux/issues/3) e [Bazzite #254](https://github.com/LMhdez/gaslux/issues/254).
