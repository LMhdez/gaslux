# Q4OS 6.10 r2 (Live/Calamares de laboratório) — investigação e execução Gaslux

**Data:** 2026-11-19 UTC. **Identidade/backend:** q4os / Debian 13 / native Calamares. **Snapshot:** main 90b044ba435b2b4b4db6c5813ca4698b37e4a555, dev 34d50646783498000eb13dbaf8a63220e63ff719. Estes HEADs não são autoridade futura. Consultar [contratos partilhados](SHARED_CONTRACTS.md), [índice](README.md) e revalidar PR/Actions antes de trabalhar.

**Rótulos:** DOCUMENTADO = fonte oficial; IMPLEMENTADO = código identificado; COMPROVADO = teste/artefacto verificável **no âmbito indicado**; PENDENTE = investigação ou prova por fazer; BLOQUEADO = não escrever ou promover. Não extrapolar de ISO Live ou GPT sintética para instalação real.

## 1. Resumo executivo e estado de maturidade

**EXPERIMENTAL, não estável.** ISO Q4OS 6.10 r2 e configuração Calamares foram examinadas; existe root extraída do unpackfs com primeiro boot Linux em GPT descartável, mas **não** execução completa nativa Calamares nem dual boot Windows + Q4OS, upgrades ou rollback completo.

## 2. Fontes oficiais e versões consultadas

- [Q4OS downloads oficiais](https://www.q4os.org/downloads1.html), [instalação de Live](https://www.q4os.org/dqa018.html), [instalação Q4OS](https://www.q4os.org/dqa007.html), [Windows folder installation](https://www.q4os.org/dqa014.html), consultados 2026-11-19.
- [Calamares upstream](https://github.com/calamares/calamares), [settings.conf](https://github.com/calamares/calamares/blob/calamares/settings.conf). O código Calamares upstream atual não substitui plugins/hooks da ISO Q4OS 6.10 r2.
- [PR #44](https://github.com/LMhdez/gaslux/pull/44), [#49](https://github.com/LMhdez/gaslux/pull/49), [#59](https://github.com/LMhdez/gaslux/pull/59), [#209](https://github.com/LMhdez/gaslux/pull/209), [#237](https://github.com/LMhdez/gaslux/pull/237).

## 3. Arquitetura de arranque

**DOCUMENTADO:** ISO Live Q4OS inicia GUI com ícone Install Q4OS e Calamares; [PR #35](https://github.com/LMhdez/gaslux/pull/35) arrancou em OVMF com ISO virtio read-only e [#59](https://github.com/LMhdez/gaslux/pull/59) controlou launcher GUI por screenshot/OCR. A cadeia Windows→Q4OS Live sem USB depende de BCD/GRUB BIOS ou BootNext/GRUB EFI e localização efetiva da ISO depois de carregar kernel/initramfs e SquashFS; **PENDENTE** caminhos/flags exatos na ISO. Não confundir arranque a partir da optical VM com handoff Gaslux Windows.

## 4. Estrutura e autenticação da ISO

**COMPROVADO no laboratório:** ISO oficial Q4OS 6.10 r2, SHA-256 **1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d**, /etc/q4os_version = **6.10-deb13u1**, base Debian 13 ([PR #44](https://github.com/LMhdez/gaslux/pull/44)). **PENDENTE:** tamanho, URL ISO exato e verificação independente de hash upstream/signature; extrair do workflow/manifesto da release antes de qualquer catálogo. Há edições Trinity/Plasma e install-CD/Live, que não partilham automaticamente Calamares, initramfs ou processo de instalação. O instalador Windows em pasta usa outro modelo, não partições Linux nativas.

## 5. Sequência completa Windows → Linux

**COMPROVADO em #44:** Calamares /etc/calamares/settings.conf (módulos partition, mount, unpackfs, hooks Q4OS, bootloader, initramfs, cleanup), /run/live/medium/live/filesystem.squashfs como origem do unpackfs.conf, configuração EFI bootloader.conf com `installEFIFallback: true`. Os jobs Q4OS q4oshook2/q4oshook3/q4oshook5 necessitam inspeção de código e SHA. **PENDENTE:** manifesto exato de El Torito, kernel, initrd, EFI executables, imagem root e versão módulo Calamares e CLI da ISO, antes de usar automação.

**Contrato partilhado:** vincular nonce/transação/autorização, ISO, disco, partição, firmware, programa executado e plano a um handoff autenticado. Preparar recuperação com baseline verificável **antes de escrever**. Checkpoint durável por fase e compensação idempotente por recurso pertencente à transação. Em falha, não descartar o overlay antes de observar Windows recuperar e arrancar. Prova serial/OCR/log não basta sem inspeção independente de geometria/boot.

## 6. Instalador nativo e automatização

**COMPROVADO quanto à identidade, não execução completa:** Calamares nativo na ISO verificada; os módulos de partition/mount/unpackfs/users/GRUB e hooks alteram o sistema alvo. PR #44 apenas executou unpackfs e GRUB temporário para arrancar root num disco Linux-only: **não** é Calamares completo. A UI das PR #209/#237 tem Welcome/Locale/Desktop/Software mas não prova transição Partitions: #237 relata spinner até frame 56, sem captura depois da ação Next. Para unattended, usar módulos Calamares por perfil autêntico e ordem conferida; todos os botões/IDs/cliques e sinais de progresso devem ser recolhidos na versão exata. Não inventar YAML, parâmetros de arranque, coordenadas ou aceitar summary com write-set não verificado.

## 7. Particionamento e proteção Windows

**Contrato transversal — IMPLEMENTADO na base, não necessariamente integrado neste backend:** Windows 10/11 pré-valida firmware e tabela, serial/identificador persistente, bytes por setor, capacidade, offsets, NTFS shrink, estado BitLocker/Device Encryption, BCD, WinRE, OEM/Recovery, ESP e BootOrder/BootNext ou MBR/PBR/active flag. No ambiente Live repetir a identificação e comparar com plano tipado. Nunca selecionar o primeiro /dev/sdX nem confiar apenas na letra C:. Recusar qualquer geometria divergente, partição estrangeira, GPT sem CRC consistente ou EBR não auditada. Não converter tabela/firmware, formatar Windows/ESP nem alterar chaves Secure Boot.

**Risco crítico:** `installEFIFallback: true` no bootloader.conf pode instalar EFI/BOOT/BOOTX64.EFI, sobrescrevendo carregadores Windows ou ESP partilhada. **BLOQUEADO** seguir perfil nativo inalterado sobre Windows. Exigir programa/manifesto adaptado e não mutante para verificar que Calamares só opera partições próprias, configurações GPT/UEFI, ESP e fstab por UUID, opções de bootloader/fallback, e não toca EFI/Microsoft/Windows Boot Manager, Recovery/OEM/BitLocker. PR #182 cria proposed signed GPT target em COW **sintética**, não dá autoridade para Windows real. BIOS/MBR exige procedimento separado para EBR/slots/GRUB BIOS.

## 8. Configuração do sistema instalado

Durante instalador nativo verificar user/hostname/password, sudo/grupos, locale, teclado, timezone, mount points e fstab, apt/dpkg, Q4OS branding e desktop Trinity ou Plasma, hooks Q4OS com respetivos argumentos/efeitos. Após boot sem ISO medir /etc/q4os_version, kernel/modules, dpkg, serviços e conta, não basta mensagem Calamares completed nem root extraída. Scripts post-install devem ser source-bound e whitelist operacional.

## 9. Bootloader e manutenção

**DOCUMENTADO na ISO #44:** GRUB Calamares UEFI com `installEFIFallback: true`, risco Microsoft. #45 relata GRUB package-owned e segundo boot em disco **Linux-only**, sem Windows, não aplica à ESP Windows. Garantir loader privado transacional e estratégia de EFI fallback proibida na ESP Windows; validar NVRAM e entradas Windows. No BIOS/MBR exigir GRUB BIOS e preservação MBR/PBR/BCD, só quando layout suportado. Updates apt/grub/initramfs exigem hooks nativos verificados.

## 10. Atualizações e desinstalação

Apt/dpkg e Q4OS-specific hooks devem manter kernel/initramfs/GRUB e Windows entry após update e reboot Linux + Windows. Reinstalação nativa Calamares não deve reclamar partições estrangeiras. Desinstalar apenas a root/ESP/GRUB entry da própria transação, restaurar WinRE/BCD/BootOrder/MBR/ESP; Windows folder-installer removal não é teste de desinstalação nativa.

## 11. Recuperação e rollback

**Obrigatório:** guardar baseline de partições e hashes/testemunhos, EFI/BCD/WinRE/NVRAM ou MBR/PBR, encriptação e caminho de boot Windows; testar acesso à recuperação; em corte de energia, download falhado, falta de espaço, erro nativo ou bootloader parcial, parar escrita e restaurar apenas recursos transacionais após reidentificar disco. Validar no Windows realmente arrancado geometria, BitLocker/WinRE/BCD e BootOrder/ESP ou MBR. Snapshot/COW protege o laboratório, não prova a recuperação de produto; se não for possível provar, marcar recuperação incompleta e não declarar sucesso. Calamares pode aplicar vários módulos sem transação Windows integrada: exigir checkpoints por operação, geometria antes/depois e resto nativo somente se todos os módulos têm compensação. Testar energia cortada no partition/mount/unpackfs/users/bootloader e no update. PR #206 testa powercut em COW sintética sem Windows; não classificar como recuperação Windows.

## 12. Código Gaslux reutilizável

Reutilizar preflight, plano/ledger/rollback comuns, auditoria de ISO Calamares #44 e hooks #49, launcher GUI #59, target signed Ed25519 #182, snapshots COW #188/#198/#206 e read-only GUI #209/#237. PR #22 preflight read-only integrada em dev; outras PRs experimentais podem estar fechadas sem merge. Não copiar Q4OS Windows folder installer ou Debian live root materializada em vez do Calamares real.

## 13. PRs, branches e commits relevantes

- [PR #44](https://github.com/LMhdez/gaslux/pull/44), SHA fc0d755bddf2c5db48fb44792d86cb14fb060ab9; [Actions #43964771409](https://github.com/LMhdez/gaslux/actions/runs/43964771409) ISO/Live, [#43966106405](https://github.com/LMhdez/gaslux/actions/runs/43966106405) config policy.
- [Actions #43966638284](https://github.com/LMhdez/gaslux/actions/runs/43966638284)/[artefacto #14276431994](https://github.com/LMhdez/gaslux/actions/runs/43966638284/artifacts/14276431994): root unpackfs boot, não Calamares full.
- [#49](https://github.com/LMhdez/gaslux/pull/49) Q4OS hooks, [#59](https://github.com/LMhdez/gaslux/pull/59) launcher GUI, [#182](https://github.com/LMhdez/gaslux/pull/182) Ed25519 signed target synthetic.
- [PR #209](https://github.com/LMhdez/gaslux/pull/209), SHA a958511ac737ed01130e8bbb5e24edf2c340040d: GUI na COW sintética, **sem instalação**.
- [PR #237](https://github.com/LMhdez/gaslux/pull/237), SHA b73ffd6a78a78f3c44f8254bafa1ec790df8f5d1, e [Actions #44518473290](https://github.com/LMhdez/gaslux/actions/runs/44518473290): ecrã Software ainda a carregar, não prova Partitions.
- [PR #256](https://github.com/LMhdez/gaslux/pull/256), draft aberta: manifestos nofollow/dirfd de evidência, não instalação.

## 14. Problemas conhecidos e causas identificadas

**BLOQUEADO:** executar Calamares installEFIFallback na ESP Windows, converter GPT sem autorização, confundir unpackfs root boot ou 'Native Calamares UI' com execução de todos os jobs, clicar Next em vista não identificada, aceitar bitmap/hook de ISO sem hash, assumir Windows folder install como dual boot nativo. GUI Software spinner sem foto Partitions não demonstra avanço. Substituir parâmetros/calamasres module por suposição gera risco de apagar Windows.

## 15. Soluções tecnicamente verificadas

**COMPROVADO apenas como está descrito:** Q4OS 6.10 r2 Calamares e hooks ligados à ISO (#44/#49); Live ISO QEMU OVMF, root import via unpackfs e temporário GRUB (não Calamares completo) com serial no Actions #43966638284; GUI até ecrã Software numa COW sintética #209/#237. **NÃO COMPROVADO:** native unattended Calamares real com write-set Windows-safe, firstboot Windows-shared ou rollback.

## 16. Matriz de compatibilidade

| Cenário | Estado Gaslux 2026-11-19 |
|---|---|
| Win10 UEFI/GPT mesmo disco | COW sintética GUI; native Calamares Windows dual boot PENDENTE |
| Win11 UEFI/GPT | PENDENTE |
| Win10 BIOS/MBR | Upstream possível; Gaslux BLOQUEADO sem EBR/MBR/boot proofs |
| Segundo disco | PENDENTE identidade/boot Windows |
| Secure Boot | PENDENTE loader/shim aceite por firmware; sem mudança keys |
| UEFI/MBR, BIOS/GPT, EBR incerta | BLOQUEADO |

## 17. Testes existentes e evidências

**COMPROVADO apenas como está descrito:** Q4OS 6.10 r2 Calamares e hooks ligados à ISO (#44/#49); Live ISO QEMU OVMF, root import via unpackfs e temporário GRUB (não Calamares completo) com serial no Actions #43966638284; GUI até ecrã Software numa COW sintética #209/#237. **NÃO COMPROVADO:** native unattended Calamares real com write-set Windows-safe, firstboot Windows-shared ou rollback.

Runs e commits disponíveis na secção 13; a palavra SUCCESS de contratos não prova N4/N5.

## 18. Testes ainda necessários

**N0:** contratos C#/Pester/Python/Bash, linters, hashes/identidade/ownership/negativas. **N1:** ISO oficial imutável, assinaturas e árvore interna/boot/installer. **N2:** boot do Live autenticado, mas não instalação. **N3:** instalador **nativo** executado, primeiro e segundo boot Linux instalado sem ISO, conta/localização/loader. **N4:** Windows 10 BIOS/MBR, Win10 UEFI/GPT e Win11 UEFI/GPT quando aplicáveis, disco único/segundo, ambos SO num **mesmo Windows QCOW2 real**. **N5:** updates, reinstalação/desinstalação, powercut em cada etapa, rollback e WinRE/BCD/ESP/MBR comprovados. **N6:** hardware real só com autorização, backup e restauro demonstrado. Não somar ensaios de discos diferentes para alegar N4.

1. Reabrir PR #44/#49/#59/#209/#237/#256, inventariar módulos/GUI/paths/SHAs exatos da ISO e os efeitos de cada hook. 2. Construir plano nativo Calamares sem GRUB EFI fallback sobre Windows, validar write-set completo em modo preview read-only e criar mapa de views e clicks observados. 3. Executar em VM COW sintética autorizada **instalação Calamares real** e provar segundo boot sem ISO. 4. Adicionar Windows10/11 realmente instalado ao mesmo overlay com recuperação, efetuar ambos arranques e updates. 5. Injeções powercut/nvram/falha loader, rollback e desinstalação, segunda disco/BIOS quando elegível. 6. Rever catálogo só após N5.

## 19. Plano de implementação ordenado

1. Reabrir PR #44/#49/#59/#209/#237/#256, inventariar módulos/GUI/paths/SHAs exatos da ISO e os efeitos de cada hook. 2. Construir plano nativo Calamares sem GRUB EFI fallback sobre Windows, validar write-set completo em modo preview read-only e criar mapa de views e clicks observados. 3. Executar em VM COW sintética autorizada **instalação Calamares real** e provar segundo boot sem ISO. 4. Adicionar Windows10/11 realmente instalado ao mesmo overlay com recuperação, efetuar ambos arranques e updates. 5. Injeções powercut/nvram/falha loader, rollback e desinstalação, segunda disco/BIOS quando elegível. 6. Rever catálogo só após N5.

## 20. Critérios objetivos de estabilidade

Só permitir em release as combinações concretas com prova N5 de instalação nativa, primeiro boot Linux e Windows no mesmo QCOW2 realmente instalado, atualizações e rollback/desinstalação com dados/WinRE/BCD/EFI/BitLocker preservados. A ligação da evidência a commit, runner, firmware, ISO e geometria é obrigatória; hardware requer backup/restauro testados e autorização.

## ONE-SHOT EXECUTION PLAYBOOK

### Pré-requisitos exatos, branch e referências

- **GitHub LMhdez**; branch sugerida: feature/q4os-calamares-transaction-native-<fase> de dev e ancestrais auditados. Revalidar base, HEAD, PRs/commits indicados na secção 13 e Actions no mesmo SHA. Não atuar com credenciais DINISIHO. Não fazer merge automático.
- Artefactos ISO autenticamente versionados por tamanho/SHA/signature/key; firmware/tabela testados; disk/partition IDs e offsets exatos; screenshot/CLI/version nativa; autorização de laboratório COW e recuperação Windows preparada. Se qualquer um falhar, não executar writes.
- **Ficheiros a modificar apenas quando requisito de implementação:** adaptador Calamares, tabela de módulos/hooks, guarda de EFI fallback, plan/ledger e testes; preservar Mint/Zorin e release-config. **Ficheiros a não modificar:** release-config.json/main estável, RSA signing keys, EFI/Microsoft, Windows OEM/Recovery, writers de outras distribuições e qualquer dado real. Comparar regressões de Mint e Zorin.
- **Interfaces a preservar:** InstallationPlanFactory, InstallationExecutionLedger, InstallationStateMachine, schemas/installation-plan.schema.json e installation-state.schema.json, validadores C#/PowerShell/Python, ownership, checkpoints e BootGuardian; não criar sequências incompatíveis.
- **Referências a reutilizar:** PRs/commits na secção 13, mas uma PR fechada sem merge não é código disponível automaticamente em dev. Identificar dependências e comparar patch antes de copiar.

### Sequência de implementação e critérios de passagem

| Gate | Trabalho | Evidência exigida |
|---|---|---|
| G0 — Estado atualizado | main/dev, PRs, issues, Actions, fontes oficiais | SHA/branch/artefactos comparados; nenhuma contradição ignorada |
| G1 — Media | ISO, GPG/Cosign/RSA conforme origem, SHA, EFI, initramfs, root image, instalador | Manifesto source-bound e todas as identidades coerentes |
| G2 — Safety preflight | firmware/tabela, disco físico, offsets, Windows, ESP/BCD/WinRE, encriptação, rollback | Negativos fail closed sem escrever |
| G3 — Live handoff | Windows→boot sem USB, Cmdline/nonce/plan/ISO/disk autenticados | Linux convidado encontra media e Windows tem fallback |
| G4 — Native install | Só VM autorizada com COW, executar motor oficial no **único alvo owned** | Write-set controlado, pacotes/deployment e conta/locale reais |
| G5 — Installed Linux boot | Desligar Live, iniciar de novo sem ISO | Kernel/root/loader/ID/account/updates verificados por host+guest |
| G6 — Windows dual boot | Mesma COW com Windows real, boot Windows e retorno Linux | Hash/geometry/BCD/WinRE/ESP ou MBR e BootOrder preservados |
| G7 — Update/removal | Atualizar kernel/loader, reiniciar ambos, desinstalar/reinstalar | Regressões e rollback autenticados, recursos estrangeiros intactos |
| G8 — Faults/release | Energia/rede/storage/bad hash/bootloader/IDs e revisão humana | Recuperação Windows real comprovada, só então aprovação por configuração |

### Comandos e workflows de teste

- **Checks locais não destrutivos** em checkout provisionado: `git diff --check`; `bash -n assets/live/libertix-install-main.sh`; `python3 -m pytest -q auto_tests/tests` (sem fixtures opt-in destrutivas). Consultar README.md/CONTRIBUTING.md e .github/workflows da **branch em teste** para comandos exatos de Ruff, Pester, ShellCheck, C# e CI.
- Workflows de referência nas PRs secção 13 são evidência histórica, não ordens de execução. Só correr QEMU com writes em VMs descartáveis autorizadas e snapshots verificáveis. Não executar writers de Windows/disco físico nesta missão documental.
- Registar commit e job/action IDs, conclusão no SHA efetivo, screenshots por estado, serial/auditoria de guest, hashes de before/after e logs dos sistemas instalados. Um OCR/screenshot visual sem controlo do estado não autoriza clicar em Begin Installation.

### Falhas previsíveis e STOP obrigatório

- Assinatura/ISO/versão ou hash divergente: parar, rever release e origem, nunca desativar verificador.
- Disco, firmware, ESP/WinRE/BCD, estado encriptação ou ownership incertos: parar sem shrink, format ou EFI write.
- ISO não encontrada após boot: reentrar Windows por boot fallback e investigar cmdline/initramfs autenticado; nunca adivinhar flags.
- Instalador falha após checkpoint: registrar estado, recuperar apenas recursos owned e comparar Windows real antes de tentar de novo.
- **STOP específico:** ISO/version sem origem, hook não autenticado, GUI view/click não identificado, installEFIFallback afeta Windows, target não owned, Windows/WinRE boot ou recuperação não comprovados.
- Não alterar automaticamente chaves Secure Boot nem converter tabela; não usar teste sintético para declarar estabilidade.

### Evidências necessárias para concluir

SHA/commit da implementação, SHA/size/signature da imagem e trust chain, exactos bytes/setor/GUID/PARTUUID/offsets, firmware e NVRAM/BCD/WinRE, snapshots originais, logs host+guest, hashes witness Windows antes/depois, native installation + firstboot Linux sem media, boot Windows efetivo, dois SO após updates, falha injetada e rollback/desinstalação completo, testes por layout e PR revista por humano. A estabilidade depende de provas N5, não do volume desta documentação.
