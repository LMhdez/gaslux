# Bazzite ISO legacy 42 / backend Fedora Atomic — investigação e execução Gaslux

**Data:** 2026-11-19 UTC. **Identidade/backend:** bazzite / Fedora Atomic; UEFI/GPT exclusivamente. **Snapshot:** main 90b044ba435b2b4b4db6c5813ca4698b37e4a555, dev 34d50646783498000eb13dbaf8a63220e63ff719. Estes HEADs não são autoridade futura. Consultar [contratos partilhados](SHARED_CONTRACTS.md), [índice](README.md) e revalidar PR/Actions antes de trabalhar.

**Rótulos:** DOCUMENTADO = fonte oficial; IMPLEMENTADO = código identificado; COMPROVADO = teste/artefacto verificável **no âmbito indicado**; PENDENTE = investigação ou prova por fazer; BLOQUEADO = não escrever ou promover. Não extrapolar de ISO Live ou GPT sintética para instalação real.

## 1. Resumo executivo e estado de maturidade

**EXPERIMENTAL e BLOQUEADO para canal estável.** BIOS/MBR/CSM **explicitamente proibidos no Gaslux**. ISO legacy 42 arranca em OVMF sem disco e apresenta GUI Anaconda-style, mas a sua proveniência não está autenticada independentemente nem versão do deployment ligada ao ecrã. Não existe instalação Atomic/Windows dual boot comprovada.

## 2. Fontes oficiais e versões consultadas

- [Bazzite — guia de instalação](https://docs.bazzite.gg/General/Installation_Guide/install-guide/), [guia legacy](https://docs.bazzite.gg/General/Installation_Guide/legacy-install/), [Fedora Atomic FAQ](https://docs.bazzite.gg/General/FAQ/), [repositório fonte](https://github.com/ublue-os/bazzite), consultados 2026-11-19.
- [Fedora Anaconda](https://github.com/rhinstaller/anaconda), [Blivet GUI](https://github.com/storaged-project/blivet-gui), [rpm-ostree](https://coreos.github.io/rpm-ostree/), [bootc](https://bootc-dev.github.io/bootc/); a aplicação exata depende da versão/ISO.
- [PR Gaslux #214](https://github.com/LMhdez/gaslux/pull/214), [#222](https://github.com/LMhdez/gaslux/pull/222), [#250](https://github.com/LMhdez/gaslux/pull/250), [#255](https://github.com/LMhdez/gaslux/pull/255).

## 3. Arquitetura de arranque

**DOCUMENTADO upstream e política Gaslux:** Bazzite requer UEFI; no Gaslux aceitar **UEFI/GPT somente**. BIOS/MBR, legacy CSM, UEFI/MBR e BIOS/GPT são recusas pré-escrita, sem tentativa de conversão. Secure Boot nos guias pode necessitar inscrição MOK — intervenção manual não elegível para fluxo automático; não tocar PK/KEK/db/MOK. **COMPROVADO #214:** ISO optical read-only arrancou em QEMU/OVMF com 8 GiB de RAM, sem disco nem rede, até picker idioma. **PENDENTE:** cadeia de boot da ISO sem USB a partir Windows, EFI loader e initramfs, re-descoberta de payload e recuperação boot Windows.

## 4. Estrutura e autenticação da ISO

**COMPROVADO bytes, NÃO proveniência independente:** [Actions #44358709061](https://github.com/LMhdez/gaslux/actions/runs/44358709061) descarregou `bazzite-stable-amd64.iso` de CDN de domínio oficial com tamanho **7 907 770 368 bytes** e SHA-256 **9c8d06cd8e57f2274678edeb14b4b13a79b8117c70571a65199919a66305b5c7**; a hash originou na mesma CDN mutável, GitHub provenance=false e não foi encontrada assinatura Cosign detached correspondente. **BLOQUEADO** usá-la como confiança upstream ou fixar no catálogo. O ecrã OCR do instalador anuncia **Bazzite 42**, enquanto o upstream já tinha versões mais recentes. É preciso imagem release suportada, origem imutável, assinatura independente, identidade do installer e digest deployment.

## 5. Sequência completa Windows → Linux

Manifesto necessário da ISO imutável: El Torito/EFI, kernel/initramfs, Anaconda/kickstart e image payload rpm-ostree/bootc, assinatura das imagens subjacentes, origem Fedora/ublue e versão de deployment. **PENDENTE:** identidade de Anaconda ELF/Python/Blivet na ISO legacy 42 e versão instalada; menu visual não prova isso. Os ficheiros e algoritmos rootfs Debian, dpkg, pacstrap Arch não servem para Bazzite Atomic.

**Contrato partilhado:** vincular nonce/transação/autorização, ISO, disco, partição, firmware, programa executado e plano a um handoff autenticado. Preparar recuperação com baseline verificável **antes de escrever**. Checkpoint durável por fase e compensação idempotente por recurso pertencente à transação. Em falha, não descartar o overlay antes de observar Windows recuperar e arrancar. Prova serial/OCR/log não basta sem inspeção independente de geometria/boot.

## 6. Instalador nativo e automatização

**DOCUMENTADO:** Bazzite Fedora Atomic instala por workflow Anaconda/Atomic e configura deployments/image state; versões/variantes podem diferir em bootc/ostree e nas opções de partição. **COMPROVADO em #255:** em ecrã Installation Destination, clicar `Advanced Custom (Blivet-GUI)` apenas seleciona o rádio; NÃO abre editor Blivet. Verificar separadamente clique de lançamento, OCR/UI tree, estado da janela e alterações no disco antes de automatizar. **PENDENTE:** versão concreta e API kickstart de Anaconda, unattended sem intervenção, exacto write-set, UI identifiers, ordem e cada clique. Não automatizar o botão Begin Installation antes de provar media/plan/ownership/recovery. Não usar opções Erase Disk/Reclaim como atalho.

## 7. Particionamento e proteção Windows

**Contrato transversal — IMPLEMENTADO na base, não necessariamente integrado neste backend:** Windows 10/11 pré-valida firmware e tabela, serial/identificador persistente, bytes por setor, capacidade, offsets, NTFS shrink, estado BitLocker/Device Encryption, BCD, WinRE, OEM/Recovery, ESP e BootOrder/BootNext ou MBR/PBR/active flag. No ambiente Live repetir a identificação e comparar com plano tipado. Nunca selecionar o primeiro /dev/sdX nem confiar apenas na letra C:. Recusar qualquer geometria divergente, partição estrangeira, GPT sem CRC consistente ou EBR não auditada. Não converter tabela/firmware, formatar Windows/ESP nem alterar chaves Secure Boot.

**BLOQUEADO:** alterar ESP Windows, mover/formatar Recovery/OEM, inicializar automaticamente disco por enumeração, aceitar reclamation da partition Win sem plano de shrink/backup. Ensaios #222/#250 usam apenas GPT **sintética** COW, sem Windows realmente instalado. Criar root/boot/ESP próprios só se nativo permitir preservar todos os GUIDs/offsets Windows e o Atomic loader. Se Anaconda implicar writes não predeterminados, interromper em preview. Minimum RAM/space devem ser extraídos da versão oficial, não deduzidos de um ensaio com 8 GiB.

## 8. Configuração do sistema instalado

No primeiro boot comprovar Fedora/Bazzite ID, versão e deployment hash/ostree ref ou bootc image, account/sudo, layout teclado/timezone/locale, kernel e partições mount; validar /var persistente, bootloader e serviços. rpm-ostree rollback é **rollback de deployment Linux**, distinto da recuperação Windows GPT/ESP/BCD/WinRE. Não usar `apt update` ou `pacstrap`. A configuração GUI não substitui provas no alvo instalado.

## 9. Bootloader e manutenção

A documentação upstream mostra ficheiros EFI Fedora/GRUB em algumas variantes; **PENDENTE** enumerar o loader/shim exactos e o respetivo update mechanism na ISO autenticada, incluindo fallback EFI e ESP própria. Manter EFI/Microsoft intacta, entrada Windows acessível e BootOrder/BootNext restaurável. O facto de um shim/MOK permitir Secure Boot upstream não autoriza alteração de chaves no Gaslux.

## 10. Atualizações e desinstalação

Validar o mecanismo suportado pela imagem (rpm-ostree, ujust/bootc conforme release), atualização completa de deployment, dois boots Linux e retorno Windows, rollback Atomic para deployment anterior e prova de que não alterou entradas Microsoft. A desinstalação Gaslux deve remover exclusivamente partições/ESP/loader/entradas da transação e verificar Windows; um Atomic rollback não substitui esta operação.

## 11. Recuperação e rollback

**Obrigatório:** guardar baseline de partições e hashes/testemunhos, EFI/BCD/WinRE/NVRAM ou MBR/PBR, encriptação e caminho de boot Windows; testar acesso à recuperação; em corte de energia, download falhado, falta de espaço, erro nativo ou bootloader parcial, parar escrita e restaurar apenas recursos transacionais após reidentificar disco. Validar no Windows realmente arrancado geometria, BitLocker/WinRE/BCD e BootOrder/ESP ou MBR. Snapshot/COW protege o laboratório, não prova a recuperação de produto; se não for possível provar, marcar recuperação incompleta e não declarar sucesso. **Testes Atomic especiais:** imagem upstream indisponível entre commits, metadata Cosign errada, falha Anaconda após particionamento, deployment parcialmente atualizado, MOK enrollment indevido, insuficiência ESP e BootNext inválido. Um rollback Atomic do deployment mantém potenciais mudanças de GPT/firmware, portanto é insuficiente para declarar recuperação Windows.

## 12. Código Gaslux reutilizável

PR #21 integrated dev acrescenta origem/política read-only; #214 pesquisa ISO legacy/assinatura/OCR, #222 GPT/Blivet read-only, #235 combina contratos, #250 observação GUI, #255 desambiguação do rádio, #257 lint. Reutilizar shared preflight, plan/state, ownership e signed catalog v2 (PR #12 merged dev), mas nunca o instalador Debian SquashFS ou GRUB update hooks dpkg.

## 13. PRs, branches e commits relevantes

- [PR #214](https://github.com/LMhdez/gaslux/pull/214) aberta draft, [Actions #44358709061](https://github.com/LMhdez/gaslux/actions/runs/44358709061) mídia SHA sem provenance, [#44364282815](https://github.com/LMhdez/gaslux/actions/runs/44364282815) OVMF diskless, [#44368046013](https://github.com/LMhdez/gaslux/actions/runs/44368046013) OCR e [artefacto #14456718037](https://github.com/LMhdez/gaslux/actions/runs/44368046013/artifacts/14456718037).
- [PR #222](https://github.com/LMhdez/gaslux/pull/222) e [#235](https://github.com/LMhdez/gaslux/pull/235) fechadas sem merge, laboratórios GPT sintéticos.
- [PR #250](https://github.com/LMhdez/gaslux/pull/250) aberta draft, [#255](https://github.com/LMhdez/gaslux/pull/255) fechada sem merge, confirma rádio ≠ editor; [#257](https://github.com/LMhdez/gaslux/pull/257) lint.
- [Actions #44582498563](https://github.com/LMhdez/gaslux/actions/runs/44582498563) SUCCESS contratos, [#44582473674](https://github.com/LMhdez/gaslux/actions/runs/44582473674) FAILURE GUI observer no snapshot.

## 14. Problemas conhecidos e causas identificadas

**BLOQUEADO:** BIOS/MBR, fontes sem proveniência criptográfica independente, versão do payload diferente do banner, fazer login/setup MOK por conta própria, presumir que Advanced Custom abriu Blivet, ligar Windows real ao instalador antes de auditado write-set. O download de media e o screenshot com Bazzite 42 não comprovam instalador, deployment atual, primeira inicialização ou recuperação.

## 15. Soluções tecnicamente verificadas

**COMPROVADO:** bytes da ISO legacy coincidem com hash de laboratório (#44358709061) e Live OVMF sem disco (#44364282815), OCR welcome Bazzite 42 (#44368046013), seleção rádio Advanced Custom sem editor (#255). **NÃO COMPROVADO:** ligação de assinatura release/deployment, write-set, instalação Atomic e coexistência Windows. A estratégia segura é obter release autentica atual, provar controlo do Anaconda em COW sintética sem Windows, e só depois testar Windows real em VM descartável.

## 16. Matriz de compatibilidade

| Cenário | Estado Gaslux 2026-11-19 |
|---|---|
| Win10/11 UEFI/GPT | Candidato após autenticidade/installer, N3/N4/N5 PENDENTES |
| UEFI/GPT, segundo disco | PENDENTE EFI e identidade physical |
| BIOS/MBR ou CSM | **BLOQUEADO — rejeitar antes de escrever** |
| UEFI/MBR ou BIOS/GPT | **BLOQUEADO** |
| Secure Boot com MOK enrollment | **BLOQUEADO** até solução sem procedimento manual e suportada |
| GPT sintética COW | N0/N2 parcial, não Windows coexistência |

## 17. Testes existentes e evidências

**COMPROVADO:** bytes da ISO legacy coincidem com hash de laboratório (#44358709061) e Live OVMF sem disco (#44364282815), OCR welcome Bazzite 42 (#44368046013), seleção rádio Advanced Custom sem editor (#255). **NÃO COMPROVADO:** ligação de assinatura release/deployment, write-set, instalação Atomic e coexistência Windows. A estratégia segura é obter release autentica atual, provar controlo do Anaconda em COW sintética sem Windows, e só depois testar Windows real em VM descartável.

Runs e commits disponíveis na secção 13; a palavra SUCCESS de contratos não prova N4/N5.

## 18. Testes ainda necessários

**N0:** contratos C#/Pester/Python/Bash, linters, hashes/identidade/ownership/negativas. **N1:** ISO oficial imutável, assinaturas e árvore interna/boot/installer. **N2:** boot do Live autenticado, mas não instalação. **N3:** instalador **nativo** executado, primeiro e segundo boot Linux instalado sem ISO, conta/localização/loader. **N4:** Windows 10 BIOS/MBR, Win10 UEFI/GPT e Win11 UEFI/GPT quando aplicáveis, disco único/segundo, ambos SO num **mesmo Windows QCOW2 real**. **N5:** updates, reinstalação/desinstalação, powercut em cada etapa, rollback e WinRE/BCD/ESP/MBR comprovados. **N6:** hardware real só com autorização, backup e restauro demonstrado. Não somar ensaios de discos diferentes para alegar N4.

1. Resolver ISO legacy Bazzite 42 vs upstream atual e exigir proveniência independente assinada, versionamento instalado. 2. Extrair inventário Anaconda/Blivet/Kickstart/EFI/Atomic deployment. 3. Reproduzir screenshots e navegação validada: escolher rádio, identificar botão que realmente abre editor, comprovar estado e validar targeting read-only. 4. Gerar plano transacional UEFI/GPT sem Windows write-set, ensaiar COW sintética em VM autorizada, instalar e arrancar imagem Atomic, update+rollback deployment. 5. Só então Windows10/11 QCOW2 real, dois boots e recuperação Windows. BIOS/MBR permanece BLOQUEADO.

## 19. Plano de implementação ordenado

1. Resolver ISO legacy Bazzite 42 vs upstream atual e exigir proveniência independente assinada, versionamento instalado. 2. Extrair inventário Anaconda/Blivet/Kickstart/EFI/Atomic deployment. 3. Reproduzir screenshots e navegação validada: escolher rádio, identificar botão que realmente abre editor, comprovar estado e validar targeting read-only. 4. Gerar plano transacional UEFI/GPT sem Windows write-set, ensaiar COW sintética em VM autorizada, instalar e arrancar imagem Atomic, update+rollback deployment. 5. Só então Windows10/11 QCOW2 real, dois boots e recuperação Windows. BIOS/MBR permanece BLOQUEADO.

## 20. Critérios objetivos de estabilidade

Só permitir em release as combinações concretas com prova N5 de instalação nativa, primeiro boot Linux e Windows no mesmo QCOW2 realmente instalado, atualizações e rollback/desinstalação com dados/WinRE/BCD/EFI/BitLocker preservados. A ligação da evidência a commit, runner, firmware, ISO e geometria é obrigatória; hardware requer backup/restauro testados e autorização.

## ONE-SHOT EXECUTION PLAYBOOK

### Pré-requisitos exatos, branch e referências

- **GitHub LMhdez**; branch sugerida: feature/bazzite-atomic-trust-and-ui-<fase> de dev HEAD auditado. Revalidar base, HEAD, PRs/commits indicados na secção 13 e Actions no mesmo SHA. Não atuar com credenciais DINISIHO. Não fazer merge automático.
- Artefactos ISO autenticamente versionados por tamanho/SHA/signature/key; firmware/tabela testados; disk/partition IDs e offsets exatos; screenshot/CLI/version nativa; autorização de laboratório COW e recuperação Windows preparada. Se qualquer um falhar, não executar writes.
- **Ficheiros a modificar apenas quando requisito de implementação:** origin/provenance validation, capacidade UEFI/GPT, backend Fedora Atomic separado, testes OCR+disk, plan, rollback; não mexer no catálogo estável nem chaves firmware. **Ficheiros a não modificar:** release-config.json/main estável, RSA signing keys, EFI/Microsoft, Windows OEM/Recovery, writers de outras distribuições e qualquer dado real. Comparar regressões de Mint e Zorin.
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
- **STOP específico:** ISO sem assinatura independente, versão/deployment incertos, invocação de formatação GPT Windows, Secure Boot/MOK, modo BIOS/MBR, UI sem widget identificado, recovery/Windows boot não demonstrados.
- Não alterar automaticamente chaves Secure Boot nem converter tabela; não usar teste sintético para declarar estabilidade.

### Evidências necessárias para concluir

SHA/commit da implementação, SHA/size/signature da imagem e trust chain, exactos bytes/setor/GUID/PARTUUID/offsets, firmware e NVRAM/BCD/WinRE, snapshots originais, logs host+guest, hashes witness Windows antes/depois, native installation + firstboot Linux sem media, boot Windows efetivo, dois SO após updates, falha injetada e rollback/desinstalação completo, testes por layout e PR revista por humano. A estabilidade depende de provas N5, não do volume desta documentação.
