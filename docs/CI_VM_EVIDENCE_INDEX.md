# Gaslux — índice de GitHub Actions, QEMU e níveis de evidência

> Inventário de referência: 2026-11-22 UTC. Obtido por inspeção dos **19 workflows existentes em dev** e de YAMLs referenciados nas PRs históricas/abertas. Não é uma garantia de execução recente, nem um inventário completo de todas as branches antigas. Para cada trabalho, ler o YAML **no HEAD exato da PR** e os scripts chamados; vários títulos mencionam QEMU sem executar um guest.


## 2026-11-24 UTC — SAFETY-1 preferred UEFI staging no-clobber regression (PR #420)

- **Scope:** existing Windows-path EFI updater `assets/live/libertix-preferred-boot-path.py`; not the Windows-side partition writer. Starting `dev` was `d89f1547c50787e4640164e34bfd1863134e2908`. [Draft PR #420](https://github.com/LMhdez/gaslux/pull/420) remains unmerged, pending independent Safety review.
- **RED:** exact [HEAD `b6b35c5c8cd2036aca192b0eb04b3452f2b62b0f`](https://github.com/LMhdez/gaslux/commit/b6b35c5c8cd2036aca192b0eb04b3452f2b62b0f) in [Action #45484218496](https://github.com/LMhdez/gaslux/actions/runs/45484218496): two pytest cases failed with `DID NOT RAISE FileExistsError`. The old `shutil.copyfile(source, temporary)` followed a pre-existing temporary symlink or truncated an existing regular file under an owned synthetic directory. RED confirms the collision condition in the source, **not** an exploit on a Windows device.
- **GREEN:** exact code/test [HEAD `0d261ad48ca611ace1a8ea6147468a1cce398458`](https://github.com/LMhdez/gaslux/commit/0d261ad48ca611ace1a8ea6147468a1cce398458) in [Action #45484428843](https://github.com/LMhdez/gaslux/actions/runs/45484428843): **30/30 preferred-boot tests PASS** (including both new cases); `compileall`, Ruff lint and Ruff format PASS. Payload staging now opens `O_CREAT | O_EXCL | O_NOFOLLOW` and only unlinks a staging inode created by this call. Existing journal/replay behavior passes the suite.
- **SECOND RED (staging inode swap):** exact [HEAD `262a66ff6045fd70c293f6173f54cd63e329338f`](https://github.com/LMhdez/gaslux/commit/262a66ff6045fd70c293f6173f54cd63e329338f) in [Action #45485313717](https://github.com/LMhdez/gaslux/actions/runs/45485313717): an adversarial hook replaced the newly created temporary inode with a symlink before the prior path-based `chmod`. The test exposed unauthorized mode change of an external fixture from `0600` to `0644`. The original destination content remained unchanged. Synthetic local fixture, not a Windows/ESP exploit demonstration.
- **SECOND GREEN:** exact [HEAD `4b9c14ca8a8e796cc145992c2d66735306b82267`](https://github.com/LMhdez/gaslux/commit/4b9c14ca8a8e796cc145992c2d66735306b82267) in [Action #45485571386](https://github.com/LMhdez/gaslux/actions/runs/45485571386): **31/31 preferred-boot pytest PASS**; `compileall`, Ruff lint and format PASS. Code now pins staging `fstat`, uses `fchmod`/`fsync`/SHA256 through the original open FD, rejects an unexpected `lstat` inode before rename and cleans up only if the staging pathname still identifies that inode. Existing journal/resume tests remain in the 31.
- **Remaining known bound:** an untrusted actor capable of modifying the ESP directory between final inode check and `os.replace` can still create a directory-entry TOCTOU race. No cross-process immutable directory fence or authenticated mount was proven; not an authorization to execute this writer on a protected Windows host. Independent reviewer must consider this bound before `dev` integration.

- **Evidence = STATIC/OFFLINE only.** No QEMU guest, EFI physical mutation, authenticated ESP mount, independently checked post-stage pathname race, Windows boot/update/uninstall, BCD/WinRE or rollback demonstration. **Decision:** `DENY` operational/physical writes; at most `ELIGIBLE_FOR_GUEST_TEST` after the independent gate and an owned disposable guest are established. This does not upgrade Mint/Zorin installation certification.


## MINT-LEAN-VM-DESIGN-01 — topologia compacta não admitida (22-11-2026 UTC)

[Despacho Supervisor #7083475088](https://github.com/LMhdez/gaslux/pull/350#issuecomment-7083475088); [relatório técnico na PR #350 #7083591119](https://github.com/LMhdez/gaslux/pull/350#issuecomment-7083591119). **Estado = BLOCKED_SAFETY (pré-admissão, sem quota/restore/Windows comprovados), não BLOCKED_CAPACITY medido para o desenho compacto.** A PR #350 mantém sem alterações o bloqueio forense A/B: seis QCOW2 de 128 GiB exigem 867710795776 bytes; o runner histórico [#45036462842](https://github.com/LMhdez/gaslux/actions/runs/45036462842) tinha 91273920512 bytes e quota não observável. Estes números não são mínimos para Windows+Mint no mesmo disco.

**Proposta B apenas condicional:** uma VM QEMU/OVMF, 56 GiB virtuais (60129542144 bytes), um Windows 10 GPT baseline imutável, um overlay e OVMF_VARS privados, ISO Mint autenticada. Orçamento hipotético de pico de 84 GiB (90194313216 bytes), composto por teto de overlay 57 GiB, baseline <=13 GiB, ISO Mint <=3 GiB, scratch 2 GiB, logs 1 GiB, recuperação 8 GiB. **Os limites de baseline/overlay/scratch e a quota não foram medidos**, logo não existe prova de que caiba nos ~85 GiB históricos, nem débito/shortfall real quantificável. A fase de ISO Windows/derivada deve ser medida separadamente e não pode coexistir com a fase Mint sem novo orçamento. Uma imagem esparsa não é prova de limite.

**Primeiro gate:** inexistem no âmbito desta execução um runner B com quota efetiva, baseline Windows 10 autenticado e congelado, limite de crescimento verificável, write-set e restauro positivo de overlay+OVMF; sem isso o GASLUX-SAFETY não pode emitir LEAN_VM_ADMITTED. Windows ISO/licença e GPT/ESP/BCD/WinRE também não estão autenticados. A alternativa Mint-only é recusada pelo contrato atual `assets/live/libertix-install-main.sh`: carrega plano preparado no Windows e exige NTFS/offsets do manifesto. O [Mint Live workflow](../.github/workflows/mint-223-live-ovmf-boot.yml) continua prova Live somente, não uma instalação no disco.

**Desenvolvimento concorrente observado:** `dev@3b61b1e767883df89626442db21de794ce12e208` adicionou `windows10-vm-host-capacity.yml` e `windows_vm_host_capacity.py`, um preflight host **read-only** que ainda passa `--required-bytes 867710795776` (orçamento A/B) e nunca afirma admissão/boot; **não** é execução nem medição específica da topologia B. Não foi alterado nem contornado nesta missão.

**Próxima ação:** medir em runner selecionado a quota efetiva, QEMU fully allocated upper bounds, baseline real, picos de fases e testar restauro descartável; depois pedir avaliação Safety antes de qualquer Guest write. Nenhum novo workflow, PR, instalador, snapshot, Guest boot ou ação em disco físico foi executado nesta missão. Nível de evidência `DESIGN/STATIC`; `windows_boot_verified=false`, `gaslux_mint_install_verified=false`, `mint_boot_without_iso=false`, `windows_recovery_verified=false`.

## 2026-11-22 UTC — Compact owned 60-GiB QCOW2 allocation (PR #369)

[PR #369](https://github.com/LMhdez/gaslux/pull/369) implements a **real disposable QEMU target-disk allocation**, not an installer demonstration. [Action #45055079757](https://github.com/LMhdez/gaslux/actions/runs/45055079757) at candidate HEAD `f0aa0554b482087aecbc4593f5b3ac1ebb6b1d7c` **SUCCESS**: runner measured `94,835,286,016` free bytes, created and independently inspected a `64,424,509,440`-byte virtual QCOW2 (`60 GiB`), initial physical allocation `200,704` bytes, with no backing file, private owned temp directory and cleanup. Provisional physical planning envelope `80 GiB`, target ceiling `85 GiB`. This is a **different unadmitted experimental profile**, not the 56-GiB/84-GiB conditional Mint lean design described above. Neither profile enforces a physical quota or authenticates a Windows baseline. Artifact: [compact-ovmf-target-evidence](https://github.com/LMhdez/gaslux/actions/runs/45055079757/artifacts/14766164972). **Evidence level: REAL_QCOW2_ALLOCATION_ONLY** — no QEMU guest started; Windows/Mint installation, co-boot, updates, snapshot restore and Windows recovery are unproven. All guest writer/admission flags are **false**. Complementary to merged capacity-only PR #368; does not supersede its measurements.

**Preflight adicional sobre runner real (22-11-2026 18:24–18:25 UTC):** [Actions #43974311441 — attempt 2](https://github.com/LMhdez/gaslux/actions/runs/43974311441), job `137307884579`, executado novamente a partir do HEAD **histórico** `897648a01214f58ca185b491b6a06f7ced8f8b15` da branch Windows feasibility. Runner `ubuntu-24.04` (Ubuntu 24.04.5; image `20261116.133.1`); relatório `windows-x64-guest-host-readiness`, artefacto `14766706999`: `readyForWindows10X64Guest=false`, `ok=false`, bloqueio **`hardware KVM acceleration unavailable or denied on hosted runner`**. Os jobs de metadados Microsoft e de identidade do Windows runner passaram, mas **não houve download de ISO, guest, checkpoint, teste de overlay ou boot Windows**. O script histórico verifica apenas um limiar de 28 GiB livres e **não publica capacidade/quota em bytes do B**. KVM negativo não exclui TCG; possibilidade de completar Windows Setup por TCG no limite de tempo continua sem evidência. Esta leitura acrescenta-se à proposta B existente; **não altera** o orçamento A/B #350 nem representa `BLOCKED_CAPACITY` para B. O workflow concorrente `windows10-vm-host-capacity.yml` em `dev` usa `--required-bytes 867710795776`, logo mede A/B, não valida automaticamente o pico compacto.

## Manutenção contínua do índice GitHub Actions / VMs

**Rever e atualizar este índice** quando um workflow/branch de laboratório for criado, modificado, integrado ou encerrado, ou quando uma Action trouxer uma nova prova material. Confirmar o YAML e os scripts de `dev` **e do HEAD de PR relevante**, condições `if`, permissões, `workflow_dispatch`, resultados de cada job, SKIPPED, consents, artifacts e dados de boot. A contagem de 19 workflows abaixo é um **instantâneo de 22-11-2026**, não uma consulta dinâmica.

A atualização deve trazer data UTC, SHA exato, PR e URL da execução, tipo de prova (CONTRACT / SYNTHETIC_DISK / QEMU_PROTOCOL / LIVE_GUEST / INSTALLED_GUEST / WINDOWS_GUEST / SHARED_DISK_DUAL_BOOT / RECOVERY), bloqueios, limitações e regressões. O Integrador mantém coerência pós-merge; os agentes Backend, Safety e Observer atualizam as linhas da sua competência. `qemu-img` não implica guest boot e a palavra QEMU num workflow não substitui uma observação real.

Não voltar a executar QEMU apenas para mudar a data de documentação. A atualização é obrigatória nos eventos relevantes, **não um monitorizador autónomo**. Consultar [AGENTS.md](../AGENTS.md), [AI_POLICY.md](../AI_POLICY.md) e o [manual histórico](AGENT_HISTORICAL_PLAYBOOK.md).

### Core / PR #361 — proveniência do laboratório, sem VM (22-11-2026)

**Atualização de integração — CORE-361-DEV-INTEGRATION-01, 22-11-2026 UTC:** A [PR #361](https://github.com/LMhdez/gaslux/pull/361) foi integrada com método `merge` em `dev` no commit [`6129f9cc4b92617d35a4bb5ba47b69c201bbd43a`](https://github.com/LMhdez/gaslux/commit/6129f9cc4b92617d35a4bb5ba47b69c201bbd43a) (parentes: `dev@119b35a4fbc6e74e72171ac4794e37123cfe1b7f` e HEAD Safety `302f4f02e2968428bfd4c2e4bbf1d8e15582c0a7`). **F-361-01/F-361-02 CLOSED**, [Safety #7082951550](https://github.com/LMhdez/gaslux/pull/361#issuecomment-7082951550) = `SAFETY_APPROVED_NON_WRITER`; [delegação Supervisor #7082985320](https://github.com/LMhdez/gaslux/pull/361#issuecomment-7082985320). Os **12/12** blobs da PR #361 no merge igualam o HEAD aprovado e os **9/9** blobs da PR [#363](https://github.com/LMhdez/gaslux/pull/363) igualam o `dev` anterior, incluindo a sua atualização documental. A distinção das provas é fundamental: esta integração é non-writer e **não** demonstra instalação Mint nem recuperação Windows.

**CI pós-merge, no SHA `6129f9cc`, 6/6 SUCCESS (push em `dev`):** [GPT identity #45051151896](https://github.com/LMhdez/gaslux/actions/runs/45051151896), [media read-only #45051151914](https://github.com/LMhdez/gaslux/actions/runs/45051151914), [multidistro contracts #45051152082](https://github.com/LMhdez/gaslux/actions/runs/45051152082), [GPT FD Safety #45051151973](https://github.com/LMhdez/gaslux/actions/runs/45051151973), [CachyOS evidence #45051151959](https://github.com/LMhdez/gaslux/actions/runs/45051151959) e [Windows recovery evidence #45051151886](https://github.com/LMhdez/gaslux/actions/runs/45051151886). **Cinco checks exatos pré-merge** `source-identity-offline`, `windows-wpf-build`, `evidence-python`, `evidence-powershell`, `Windows recovery evidence rules` completaram SUCCESS no HEAD `302f4f02`: [Core #45049176083](https://github.com/LMhdez/gaslux/actions/runs/45049176083), [CachyOS #45049176040](https://github.com/LMhdez/gaslux/actions/runs/45049176040), [Windows #45049176072](https://github.com/LMhdez/gaslux/actions/runs/45049176072). O Core offline não tem trigger `push dev`, pelo que não existe rerun desse workflow no SHA do merge; a composição foi verificada por blobs, não por teste end-to-end de WPF/automação no código combinado. Nenhuma emissão de release, assinatura de catálogo, escritor de disco ou hardware usado.

**Nível máximo nesta missão:** `CONTRACT / STATIC`. Windows 10 UEFI/GPT, `clean2`, identidade de disco VM, quota e restauro não admitidos; `E2E_BLOCKED_ENVIRONMENT`. Não se pode inferir `INSTALLED_GUEST`, `SHARED_DISK_DUAL_BOOT` nem `RECOVERY`. O texto histórico subsequente ("não integrado", "pendente de Safety") retrata os HEADs antigos descritos na sua própria data; **não é o estado atual após este merge**. As alterações documentais posteriores ao commit de merge não modificam o SHA já aprovado pela Safety.



[PR #361](https://github.com/LMhdez/gaslux/pull/361), branch `core/mint-wpf-vm-recovery-20261122`, introduz exclusivamente o workflow de contrato [core-source-provenance-offline.yml](../.github/workflows/core-source-provenance-offline.yml) nessa branch (não integrado em `dev`). Dois jobs: runner Ubuntu para origem Git e testes Python; runner `windows-2022` para build WPF, .NET e Pester. Classificação **CONTRACT / STATIC** — runner Windows não é um Windows 10 convidado instalado. Não executa QEMU-system, Proxmox, instalação Mint, GPT/ESP/BCD/WinRE, desinstalação ou recuperação.

- **RED real de contrato:** [Actions #45041672878](https://github.com/LMhdez/gaslux/actions/runs/45041672878), commit `9244960c58f7f9262bbb0b2645c1db998c992fd4`: 7/7 casos adversariais falharam conforme esperado, ao aceitarem origens upstream/falsas, endpoint publicado errado, ou tentarem SSH sem identificar previamente o checkout local.
- **GREEN parcial de proveniência:** [Actions #45041964939](https://github.com/LMhdez/gaslux/actions/runs/45041964939), commit `988d09ef0336debb06b0a1e7a6ff3a6fd5667e09`: 7/7 testes, Ruff e compileall aprovados. Não valida repositório remoto independente nem bytes do worktree por atestação externa.
- **Validação herdada separada:** [Actions #45042241970](https://github.com/LMhdez/gaslux/actions/runs/45042241970), commit `c74a84518fe3398f2397a1c3d2f9c9aa981a4200`: 242/242 testes `test_core.py` e `test_published_release.py` aprovados; `deployment_audit` reportou **FAIL**, `undeclared-entry` em `Scripts/libertix-cachyos-windows-evidence.ps1`, presente no baseline de `dev` e não modificado pela PR.
- **Windows build:** [Actions #45042303433](https://github.com/LMhdez/gaslux/actions/runs/45042303433), commit `28d4bb5cc3190ac045d9a29b25d4d370226f592c`: MSBuild `Libertix.sln` e teste C# pelo VS VSTest concluídos; Pester `pwsh` teve **790 PASS / 7 FAIL** por APIs incompatíveis no runner. [Reexecução #45042543201](https://github.com/LMhdez/gaslux/actions/runs/45042543201), commit `c2ddb1aac24b017eb21a9c4806442177e5c86621`: Pester mudou para Windows PowerShell 5.1; verificar conclusão no HEAD antes de validar.


- **Correção source-only do auditor (22-11-2026, nova intervenção):** [RED #45042802666](https://github.com/LMhdez/gaslux/actions/runs/45042802666), HEAD `bb02a7eece00fadde9c6d1b0d3a93a0d7de2a9de`: `undeclared-entry` para `Scripts/libertix-cachyos-windows-evidence.ps1`, apesar de ser um auxiliar manual e read-only da VM CachyOS, não distribuído pelo instalador. Aquele run teve **WPF MSBuild, VS VSTest/C# e Pester PASS**, mas `deployment_audit` FAIL; a conclusão global foi FAIL.
- **Correcção isolada:** `auto_tests/tools/deployment_audit.py` classifica **apenas** esse auxiliar como `SOURCE_ONLY_LAB_TOOLS`. Continua a validar `Scripts/modules/Gaslux.CachyosWindowsEvidence.psm1`, o `Join-Path $PSScriptRoot` resolúvel, o import requerido e a não inclusão nos layouts da aplicação; scripts de produção não declarados continuam a gerar `undeclared-entry`. Cinco regressões adversariais foram adicionadas a `auto_tests/tests/test_deployment_audit.py`, sem incluir quaisquer ficheiros de laboratório no `Libertix.csproj`.
- **GREEN estático (observado em 22-11-2026 UTC):** [Actions #45044259938](https://github.com/LMhdez/gaslux/actions/runs/45044259938), commit de código `4f699e4a83c6d17d730576c71dbd9db1f40ca48f`: job `source-identity-offline` **SUCCESS**, auditor **RESULT OK: 0**, **18/18** testes do auditor, **7/7** proveniência Gaslux e **242/242** Python herdado, Ruff e compileall aprovados. Na observação inicial, `windows-wpf-build` desse run permanecia em Pester; verificar resultado final e repetir CI no HEAD documental antes de integrar. Nível **CONTRACT/STATIC** exclusivamente, sem arranque guest, disco QEMU ou recuperação Windows.

**Safety F-361-01/F-361-02 — remediação de contrato, 22-11-2026 UTC:** [revisão Safety inicial](https://github.com/LMhdez/gaslux/pull/361#issuecomment-7082353359), [decisão Supervisor](https://github.com/LMhdez/gaslux/pull/361#issuecomment-7082376520), HEAD avaliado `b85df554e4b1a410f326f31303e4c59f00b85e2e`.

- **RED adversarial real:** [Actions #45046490577](https://github.com/LMhdez/gaslux/actions/runs/45046490577), commit `33cc39d3f81d33578e5baff99f3b27751cb3ed6c` (testes e instrumentação do workflow, implementação vulnerável ainda inalterada). F-361-01: **4/4 FAIL** em `published/local` com e sem `prepared_release`; o mock de `_restore_clean_snapshots` foi alcançado indevidamente antes da recusa. F-361-02: **4/5 FAIL**, com o caso original de remoção completa 1 PASS; variantes comentadas, strings e here-strings não geraram `source-only-module-not-imported`. Execução exclusivamente offline, sem Proxmox ou SSH reais. Os steps RED temporários foram retirados após reprodução.
- **Correção limitada:** `ValidationService.verify_source_provenance` reutiliza a mesma política de `prepare_server`, agora chamada por `AutomationService.run` antes de snapshots, preparação de dispositivos/Windows e rede, inclusive com `prepared_release`; validação redundante em `prepare_server` preservada. `deployment_audit.py` reconhece import executável por máscara lexical de comentários, strings e here-strings; construções incompletas levantam `AuditStructureError`. Contratos `SOURCE_ONLY_LAB_TOOLS`, módulos e entradas operacionais preservados. Nenhum writer de instalação alterado.
- **GREEN estático do código:** [Actions #45046862717](https://github.com/LMhdez/gaslux/actions/runs/45046862717), commit `744371b0438f1e650186eceafcfbe1d80af760b7`: job `source-identity-offline` **SUCCESS**, proveniência/automação **13/13**, auditor **23/23**, auditor completo `RESULT OK: 0 error(s)`, Python herdado **242/242**, Ruff e compileall **PASS**. O job WPF permanecia em curso no registo inicial; confirmar o estado na CI do HEAD documental final.
- **Sem operações remotas:** os casos inválidos instrumentam `_restore_clean_snapshots`, Proxmox, SSH, preparação Windows e boot secundário com mocks cuja contagem final em GREEN é zero. Não houve guest boot, instalação, rollback real, ou recuperação Windows. Git origin e HEAD são declarações controladas pelo operador, sem atestação de história remota nem dos bytes não commitados/symlinked. Findings marcados **REMEDIATED_PENDING_INDEPENDENT_REVIEW**, não fechados por Safety nem autorização de merge.

**Safety diferencial F-361-02 — terminadores de here-string Windows PowerShell 5.1 (22-11-2026 UTC):** [Safety #7082697059](https://github.com/LMhdez/gaslux/pull/361#issuecomment-7082697059) e [Supervisor #7082713603](https://github.com/LMhdez/gaslux/pull/361#issuecomment-7082713603) reabriram apenas F-361-02 no HEAD `89d42150e4bb5b9d6077f0782ed96fce27dd29c1`. **F-361-01 permanece CLOSED** e os seus ficheiros/contratos não foram alterados nesta intervenção.

- **Defeito:** `powershell_executable_code()` aceitava whitespace antes/depois do terminador (`^[ \t]*'@[ \t]*` ou `^[ \t]*"@[ \t]*`). Windows PowerShell 5.1 exige marcador de fecho na coluna zero. Um trecho contendo `$text = @'`, a linha `  '@` e de seguida `Import-Module -Name $module -Force -ErrorAction Stop` era aceite falsamente como import executável apesar de a here-string estar mal terminada. Fonte de sintaxe: [PowerShell Team, Microsoft](https://devblogs.microsoft.com/powershell/diagnosing-here-strings-with-powershell_ise/); não foi executado PowerShell sobre o reproducer.
- **RED provado em CI:** [Actions #45048821161](https://github.com/LMhdez/gaslux/actions/runs/45048821161), commit de testes `f461c6c7fe560cafd989012618e20e29937b4421` (analisador ainda vulnerável). Comando `.core-venv/bin/python -m pytest -q auto_tests/tests/test_deployment_audit.py` reportou **4 FAIL / 31 PASS**: LF/CRLF × aspas simples/duplas, todos com `Failed: DID NOT RAISE AuditStructureError`. A referência `Join-Path` ao módulo foi preservada na substituição em memória. Zero execução de PowerShell, Proxmox ou guest.
- **Correção mínima:** [commit `3c91147a1e53e27f8a2b22fd9894fbdaa2b2d989`](https://github.com/LMhdez/gaslux/commit/3c91147a1e53e27f8a2b22fd9894fbdaa2b2d989) altera somente a expressão de terminador no analisador canónico para `rf"(?m)^{re.escape(quote + '@')}\r?$"`, recusando indentação e caracteres adicionais, preservando CRLF. Não cria parser, workflow, branch, PR, dependência ou writer novo.
- **GREEN Python no código corrigido:** [Actions #45049002404](https://github.com/LMhdez/gaslux/actions/runs/45049002404), job `source-identity-offline` **SUCCESS** em `3c91147a1e53e27f8a2b22fd9894fbdaa2b2d989`: **35/35** testes do auditor (inclui 23 históricos e 12 novos), **13/13** testes de proveniência/automação, **242/242** herdados, auditor completo `RESULT OK: 0 error(s)`, Ruff, format e compileall aprovados. O job Windows/WPF estava a executar no momento deste registo; verificar a conclusão em CI no HEAD final documental antes de pedir Safety.
- **Limites:** máscara lexical estática, não cobertura integral da gramática PowerShell nem interpretação do script PowerShell 5.1 real; verificação de contratos **STATIC/CONTRACT**. Sem `INSTALLED_GUEST`, `SHARED_DISK_DUAL_BOOT`, rollback ou `RECOVERY` demonstrados; nenhuma operação sobre discos físicos, ESP, BCD, WinRE ou NVRAM. F-361-02 **REMEDIATED_PENDING_INDEPENDENT_SAFETY**, PR #361 mantém bloqueio de merge até avaliação diferencial independente.

**Limite operacional:** `BLOCKED_ENVIRONMENT` — não foi disponibilizada VM Windows 10 UEFI/GPT exclusiva, snapshot `clean2`, disco descartável isolado e recuperação demonstrada. Não existe prova de `INSTALLED_GUEST`, `SHARED_DISK_DUAL_BOOT` ou `RECOVERY`; nenhuma mutação de disco físico. A PR permanece Draft e não promove backends.

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
- A [#325](https://github.com/LMhdez/gaslux/pull/325) é uma experiência QEMU **separada**, ainda Draft. Nenhum resultado dela foi integrado pelo fecho da #294. Preservar separadamente as provas e gates.


Para contratos base e critérios de estabilidade, ver [histórico/guia de agentes](AGENT_HISTORICAL_PLAYBOOK.md), [ARCHITECTURE](ARCHITECTURE.md), [issues CachyOS #3](https://github.com/LMhdez/gaslux/issues/3) e [Bazzite #254](https://github.com/LMhdez/gaslux/issues/254).

## 2026-11-22 — Windows 10 UEFI/GPT resource preflight (new bounded admission prerequisite)

This branch introduces [windows_vm_host_capacity.py](../auto_tests/tools/windows_vm_host_capacity.py) and [Windows 10 host capacity preflight](../.github/workflows/windows10-vm-host-capacity.yml). The tool reads actual `statvfs` free backing-space bytes on the disposable GitHub runner and compares them with a clearly labeled **historical Mint A/B initial requirement** of `867710795776` bytes. The previously measured runner had `91273920512` available bytes, giving a deficit of `776436875264` bytes, as recorded in PR #350. Those figures are *historical measurements*, not claims about the current runner; each CI run measures its own available bytes.

**Evidence scope:** `BLOCKED_STORAGE` or `CAPACITY_ONLY_OK`, both with `windows_lab_admitted=false`. The script does not create QCOW2, attach disks, boot Windows, touch NVRAM/BCD/ESP, assert media provenance, verify snapshot/restore or install Linux. A passing CI job proves only that the negative/positive capacity classification ran correctly; it cannot establish a Windows VM or satisfy the Mint install/dual-boot/recovery acceptance gate. Even `CAPACITY_ONLY_OK` requires a distinct owned virtual disk, authenticated Windows media, actual guest boot, snapshot and restore witnesses before any guest mutation.

This avoids expensive or unsafe VM startup on a runner already known to have insufficient real storage, without conflating sparse QCOW2 *virtual size* with physical host capacity. When real backing storage is sufficient, the next independent admission gates remain open. The tool is deliberately read-only, no model or GitHub write permissions, and cannot promote release eligibility. This is useful to the final project but **not an installer implementation**.

## 2026-11-22 — read-only destination cross-backend contract (PR #337)

- [PR #337](https://github.com/LMhdez/gaslux/pull/337) adds host-only
  `assess_authenticated_destination` with actual QEMU pidfd/procfd
  observations, held QCOW2/backing/checkpoint read-only FDs, checked SHA-256,
  canonical RAW backing GPT parser and *unchanged*, pinned #267 no-writer gate.
- [Actions #45032388422](https://github.com/LMhdez/gaslux/actions/runs/45032388422)
  and [#45032391998](https://github.com/LMhdez/gaslux/actions/runs/45032391998)
  **SUCCESS** on core HEAD `d2e382a60120d09a0b225e4188309f48f0315845`:
  private QEMU stopped before guest boot; 11 destination attack/positive
  cases, #327 BZD-DEST-01 suite and #267/HOST-FD/QEMU regressions;
  Ruff + compileall passed.
- [CachyOS recovery #45032392005](https://github.com/LMhdez/gaslux/actions/runs/45032392005)
  and [Windows recovery #45032392037](https://github.com/LMhdez/gaslux/actions/runs/45032392037)
  **SUCCESS** on the same HEAD. All are contract/fixture
  runs, **not** Windows/Linux boot, dual boot, in-place recovery or rollback.
- Properties: local FD and backing GPT **PROVEN locally**; caller plan, source
  and write-set ownership **CLAIMED**; independent backend/FD, effective
  QCOW2 guest GPT and checkpoint authenticity **UNPROVEN**;
  Guest channel, write and installation authority **DENIED**.
  No release or stability claim.

## 2026-11-22 — #337 integration branch reconciled with dev (non-destructive)

Original #337 HEAD `f1e082c37ab58887f942b1e9ab0a841cb4b2b02a` composed with dev `55a70a90bdde29d0d41d4592de205013ee61bc16` by a two-parent merge (common ancestor `8e68a475d6397ba8fef2e0f9f83758545e202a5f`). The only overlapping path was this evidence index: retain the entire dev text including #361/#368/#369 and append the original #337 historical section without editing it. The authenticated_destination.py source blob `328653beca42b5ac006974d014e1bc6da1182e63` remains unchanged; Safety D-337-01 technical closure applies exclusively to the audited offline read-only code. Fresh exact-composition CI and dev integration checks are mandatory. No writer, independent Guest or Windows recovery authorization.

## 2026-11-22 — AUTH-DEST-128G-READONLY-01, separate dependent branch

- [Actions #45034846402](https://github.com/LMhdez/gaslux/actions/runs/45034846402):
  **SUCCESS** on tested implementation SHA
  `6a94093271610dbd2ff908c2b8692e332e1585a1`. Real QEMU started
  **paused**, a test-owned RAW backing was created with **128 GiB apparent
  size but sparse allocation**, and a small QCOW2 overlay was observed
  read-only. No Windows image/guest/source authentication was provided.
- New bounds: QCOW2 apparent 64 MiB, RAW virtual 128 GiB, each image
  allocated maximum 32 MiB, total allocated 64 MiB, checkpoint 64 KiB,
  `qemu-img` JSON 64 KiB, inspection deadline 15 s default. Unknown
  quota, short read, I/O failure, mutation, FD swap, backing mismatch,
  checkpoint foreign transaction and user-space timeout all deny.
  `FULL_BACKING_HASH_NOT_COMPLETED` is the **correct outcome** of a
  structurally valid large-disk sample.
- Existing #337 64 MiB small disk positives continue full SHA-256;
  dependent branch addresses independent Safety D-337-01 short positive
  `pread` without altering parent #337. The index does **not**
  treat the 128 GiB sample/geometry as whole-file authentication.
  `guestChannelAuthenticated=false`,
  `productionStorageWritesAuthorized=false`,
  `rollbackProven=false`, `sameDiskDualBootVerified=false`,
  `stable=false`.
  See [resource and trust contract](AUTH_DEST_128G_READONLY.md).


## 2026-11-22 — SAFETY2-346-01: inherited-pipe subprocess RED and scoped candidate fix

- Historical **RED**: [PR #355](https://github.com/LMhdez/gaslux/pull/355),
  Safety HEAD `b690cf3b7da0ec34b950e354a4b8af8bd94a70c0`,
  [Actions #45037813419](https://github.com/LMhdez/gaslux/actions/runs/45037813419),
  SUCCESS **only as an expected-negative runner**. Source tested:
  #346 `9306d0fff8cc89794b83fe002ae133c110e641ae`.
- Producer process cleanup correction in existing
  [PR #346](https://github.com/LMhdez/gaslux/pull/346),
  code `4ab0f13b718fabf4d8cb5598626ae3df67eafce1`,
  regression code `431599b0b5e6f04f9b7617c028bfb1091771cef7`,
  strict lint adjustment `00f93376210c3bce8ab01e3ceb237a70cb0a78b8`.
  POSIX session isolation, group kill before leader reap, time-limited group
  disappearance and cleanup-denial are scoped to `_bounded_info`.
- Exact-source independent GREEN and Safety-2 judgement **pending**.
  The original Safety test shim discards `start_new_session`; only its
  forwarding adapter and checkout reference should be corrected by Safety-2,
  not its adversarial assertion. No new runtime writer/guest authority.
- Evidence type: **QEMU_HOST / offline subprocess**, not GUEST_BOOT,
  INSTALLED, DUAL_BOOT, RECOVERED or CERTIFIED. No Windows/ESP/BCD/WinRE
  change. Preserve `FULL_BACKING_HASH_NOT_COMPLETED` and
  `DENY_NO_WRITER`.


### 2026-11-22 — #346 producer CI after process-group correction

- #346 tested HEAD `6c2af28acd7da24ce127de0909c66e15147ff873`,
  [push #45054177113](https://github.com/LMhdez/gaslux/actions/runs/45054177113)
  **SUCCESS**, [PR #45054181689](https://github.com/LMhdez/gaslux/actions/runs/45054181689)
  **SUCCESS**. Strict Ruff/format/compile, synthetic sparse-128GiB real
  **paused** QEMU, real subprocess descendant cleanup and foreign-session
  isolation, inherited #337/#327/#267, and protected checkout verification.
- No independent #355 oracle GREEN on corrected head yet. Exact Safety-2
  request at [#7083477427](https://github.com/LMhdez/gaslux/pull/355#issuecomment-7083477427).
  Evidence stays **QEMU_HOST / offline, DENY_NO_WRITER**; source/guest
  authentication and full 128GiB RAW hash remain unproven.

## 2026-11-22 — #346 reconciled after #337 dev integration

Corrected #346 source at `49389810a46d43bee407304a237b912b2faebc07` was composed after #337 landed in dev at `c97cef409c39f6d488d9ec0722b3cfa845685826`. The paragraphs above are retained as dated snapshots; the later [Safety-2 RED→GREEN decision](https://github.com/LMhdez/gaslux/pull/355#issuecomment-7083769456) closed `SAFETY2-346-01` only in the offline HOST read-only boundary. The newly composed HEAD requires fresh CI. No change to `FULL_BACKING_HASH_NOT_COMPLETED`, `DENY_NO_WRITER`, guest trust or Windows rollback/writer authority.

## 2026-11-22 — 128GiB #342+#346 canonical deny-only reconciliation

- [PR #356](https://github.com/LMhdez/gaslux/pull/356),
  code HEAD `72106b2dfe4d38612ea37cdc8b0618a33298fa9e`,
  [CI push #45037589606](https://github.com/LMhdez/gaslux/actions/runs/45037589606)
  and [CI PR #45037640437](https://github.com/LMhdez/gaslux/actions/runs/45037640437)
  **SUCCESS on exact code SHA**.
- The historical #342 metadata-probe test suite ran from its own
  immutable source checkout, alongside #346's actual paused-QEMU,
  sparse 128GiB pinned-FD/GPT/checkpoint contracts and newly
  imported-only-by-behavior 32-byte QCOW2 header, checkpoint-space estimate,
  and final allocated-block verification. No duplicate runtime API.
- Independent upstream #337 D-337-01 digest regressions, #327 BZD,
  #267 no-writer and HOST/FD tests passed. Entire 128 GiB RAW was
  **not** hashed, original Windows checkpoint was not authenticated,
  and QEMU internal backend or guest provenance remain unproven.
  `DENY_NO_WRITER` stays invariant. Documentation-only changes
  after this tested code SHA require separate exact-head checks.

## 2026-11-22 — #356 non-destructive reconciliation after #346 Safety-2 closure

The historical PR #356 head `83489eee123c124266b0c514b8f20e6e19ca9bc2` and corrected PR #346 `49389810a46d43bee407304a237b912b2faebc07` share ancestor `9306d0fff8cc89794b83fe002ae133c110e641ae`. This composition preserves both histories using a two-parent merge; the final `_bounded_info` function matches approved #346 byte-for-byte, while 32-byte QCOW2 header/version/geometry, `statvfs` checkpoint estimate and final `st_blocks` recheck from #356 are preserved. The independent [Safety-2 oracle #355](https://github.com/LMhdez/gaslux/pull/355#issuecomment-7083769456) was GREEN on **#346's corrected SHA only**, not yet independently reviewed on the combined candidate; its immutable original test blob `c29c68a13967377c4a3ee89c13087b2ce6bad6b5` is reused in the existing #356 CI workflow. Before any decision, confirm CI on the new exact merged HEAD.

**Evidence classification:** QEMU stopped / host-only read-only synthetic files and contracts, NEVER installed Guest, Windows recovery, full 128GiB RAW hash, or writer. Continue to refuse `FULL_BACKING_HASH_NOT_COMPLETED`, `DENY_NO_WRITER`, `productionStorageWritesAuthorized=false`, `checkpointReserveProven=false`, `checkpointRestorationProven=false`. No release or dev merge.

## 2026-11-22 — PR #356 corrected parent composition / independent Safety oracle

**Committed histories:** first parent #356 `83489eee123c124266b0c514b8f20e6e19ca9bc2`, second parent corrected #346 `49389810a46d43bee407304a237b912b2faebc07`; merged at `22d8da1df232e0216a882242d349562bbecdcd7d`. Workflow ancestry check fixed at **code HEAD `a6e2f01ee061f05917eb1930dadbc1dfb099905d`** using full checkout depth (the earlier initial merged HEAD run [#45057399777](https://github.com/LMhdez/gaslux/actions/runs/45057399777) failed during preflight because shallow history could not prove both parents, not a QEMU regression). The final code HEAD had **3/3 SUCCESS**: [push QEMU #45057466420](https://github.com/LMhdez/gaslux/actions/runs/45057466420), [PR QEMU #45057470701](https://github.com/LMhdez/gaslux/actions/runs/45057470701), [docs #45057470700](https://github.com/LMhdez/gaslux/actions/runs/45057470700). Both QEMU runs include actual stopped-QEMU HOST FD/GPT, #337, #346/#356, original 12-case #342 suite, inherited #327/#267 and 15 original independent #355 oracle cases using externally pinned checkout and verified composed import blob `a1a6364b12cf9a6b988eb124e2aa66e374c32cfe`. Startup/cleanup failure injection rejects safely.

**Evidence classification:** QEMU_PROTOCOL + SYNTHETIC_DISK + CONTRACT only; NO LIVE_GUEST, INSTALLED_GUEST, WINDOWS_GUEST, SHARED_DISK_DUAL_BOOT or RECOVERY. A sparse 128GiB virtual extent is not an authenticated whole-RAW hash. Maintain `FULL_BACKING_HASH_NOT_COMPLETED`, `DENY_NO_WRITER`, `checkpointReserveProven=false`, `checkpointRestorationProven=false`, `productionStorageWritesAuthorized=false`. Independent differential Safety-2 assessment of combined HEAD is **pending**. No merge.

## 2026-11-22 — #356 propagated across merged #337/#346 dev chain

After [PR #337](https://github.com/LMhdez/gaslux/pull/337) and [PR #346](https://github.com/LMhdez/gaslux/pull/346) reached `dev`, the original #356 source approved by [Safety-2](https://github.com/LMhdez/gaslux/pull/356#issuecomment-7084162704) remains at verified module blob `a1a6364b12cf9a6b988eb124e2aa66e374c32cfe`. This entry preserves all current dev historical sections including #361/#368/#369 and the #346 subprocess Safety closure. The new #356 HEAD requires its own exact-head QEMU/GPT/QCOW2 and immutable 15-case #355 oracle, plus post-merge checks; approval of the old SHA alone is not sufficient proof of environment compatibility. Evidence remains HOST read-only; no authenticated RAW 128GiB digest, installed Guest, Windows recovery, physical disk or writer authority. `DENY_NO_WRITER`, `checkpointReserveProven=false`, `checkpointRestorationProven=false`, and `productionStorageWritesAuthorized=false` remain enforced.


## MINT-393 — Feature Factory Qwen e integração diagnóstica em dev (24-11-2026 UTC)

- Feature Factory real [#45354202973](https://github.com/LMhdez/gaslux/actions/runs/45354202973) **SUCCESS** no `main@c8184573226481103ae4992ce17d369dfb92ba6e`: Qwen 3.5 9B real, proposta AST/funcional, testes de contrato/backend, job independente Safety e publicação da [PR Draft #393](https://github.com/LMhdez/gaslux/pull/393). Não é evidência de guest Linux/Windows.
- A PR #393 corrigiu só formatação no HEAD `935527ac696a086e8c7d1eaac3fcfec484a3ab2c`, preservando a AST. **CI do HEAD:** [multidistro #45358863330](https://github.com/LMhdez/gaslux/actions/runs/45358863330), [CachyOS recovery #45358863160](https://github.com/LMhdez/gaslux/actions/runs/45358863160), [Windows recovery #45358863174](https://github.com/LMhdez/gaslux/actions/runs/45358863174): 3/3 SUCCESS. [Safety independente técnica](https://github.com/LMhdez/gaslux/pull/393#issuecomment-7126656760): `SAFETY_APPROVED_NON_WRITER`, 11/11 casos isolados e equivalência AST. [Avaliação técnica Mint](https://github.com/LMhdez/gaslux/pull/393#issuecomment-7126717329): `BACKEND_APPROVED_NONWRITER`, sem aprovação humana formal.
- [Merge #393](https://github.com/LMhdez/gaslux/commit/e61e42457bbabb2cc9d62269f3a892692e166307) em `dev`, commit `e61e42457bbabb2cc9d62269f3a892692e166307`; **somente** um auxiliar read-only com oito gates faltantes e duas flags `False`. O `push dev` acionou os runs [#45360305701](https://github.com/LMhdez/gaslux/actions/runs/45360305701), [#45360305212](https://github.com/LMhdez/gaslux/actions/runs/45360305212), [#45360305164](https://github.com/LMhdez/gaslux/actions/runs/45360305164), [#45360305091](https://github.com/LMhdez/gaslux/actions/runs/45360305091), [#45360305083](https://github.com/LMhdez/gaslux/actions/runs/45360305083), [#45360305046](https://github.com/LMhdez/gaslux/actions/runs/45360305046), [#45360304961](https://github.com/LMhdez/gaslux/actions/runs/45360304961). **Verificar conclusão individual antes de declarar CI pós-merge totalmente verde.**
- **Nível da prova:** STATIC/CONTRACT. Nenhum Windows instalado em VM, instalação Mint, dual boot, upgrade, uninstall ou rollback foi demonstrado por esta PR; sem autoridade para modificar discos físicos ou stable. A aceitação Windows/Linux em VM continua obrigatória para funcionalidades de instalação, mas não para este auxiliar estritamente não operacional.
