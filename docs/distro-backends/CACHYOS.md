# CachyOS 260809 ISO de laboratório — guia técnico operacional Gaslux

**Snapshot:** 2026-11-19 UTC; **identidade:** cachyos/archiso-cachyos; pacstrap/pacman. Referências repositório: main 90b044ba435b2b4b4db6c5813ca4698b37e4a555, dev 34d50646783498000eb13dbaf8a63220e63ff719. A cada trabalho revalidar versões e branch. [Contratos partilhados](SHARED_CONTRACTS.md) e [índice](README.md) são obrigatórios.

**Classes:** DOCUMENTADO = upstream oficial; IMPLEMENTADO = código identificável; COMPROVADO = Actions/artefacto/commit e âmbito real; PENDENTE = sem prova; BLOQUEADO = não escrever. Uma Live, root extraída ou COW sintética não é dual boot.

## 1. Resumo executivo e maturidade

EXPERIMENTAL, **não** em main stable. ISSUE #3 aberta é gate explícita. Linux-only pacstrap+firstboot foi comprovado; Windows shared-root, updates, rollback e BIOS/MBR ainda não certificados.

## 2. Fontes oficiais e versões consultadas

[CachyOS downloads+signature](https://wiki.cachyos.org/cachyos_basic/download/), [instalação](https://wiki.cachyos.org/installation/installation_on_root/), [boot managers](https://wiki.cachyos.org/installation/boot_managers/), [Calamares settings.conf](https://github.com/CachyOS/cachyos-calamares/blob/cachyos/settings.conf), [bootloader.conf](https://github.com/CachyOS/cachyos-calamares/blob/cachyos/src/modules/bootloader/bootloader.conf), [New CLI installer config](https://github.com/CachyOS/New-Cli-Installer/blob/master/docs/config.md), consulta 2026-11-19. A versão New CLI na ISO 260809 não foi comprovada.

## 3. Arquitetura de arranque

PR #36 estabeleceu handoff Ed25519 efémero GRUB/OVMF com Archiso real em disco Linux-only; PR #165 fornece proposta autenticada para quinta GPT em Windows QCOW2; PR #215 investiga ISO carrier OVMF. Handoff tem de ligar cmdline, nonce, guest, ISO, PARTUUID/serial e programa a transação, com replay negative tests. Para BIOS/MBR exigem GRUB BIOS, BCD/MBR/PBR e validação EBR/4 slots: **BLOQUEADO** até ensaio separado. Secure Boot enabled é rejeição antes de disk write enquanto não houver chain de assinatura comprovada.

## 4. Estrutura e autenticação da ISO

PR #36 usa ISO oficial CachyOS desktop 260809 e autenticação SHA-256/GPG em laboratório; **digest e tamanho exactos PENDENTES de manifesto upstream/código ligado à run**, não os inventar. Upstream publica ISO e assinatura .sig; verificar fingerprint GPG independentemente, nome/arquitetura, kernel, initramfs, EFI e Archiso root image. Sem versão catalogada em release-config main. Nunca interpretar airootfs Live como sistema instalado.

## 5. Sequência completa Windows → Linux

DOCUMENTADO Calamares CachyOS: settings.conf inclui GUI Welcome→locale→keyboard→partition→packagechooser/netinstall→users→summary; execução partition, mount, pacstrap, machineid, locale, mkinitcpio, fstab, bootloader e umount. Possui opções GRUB, systemd-boot, Limine, rEFInd; estratégia escolhida deve ser fixada por release/capability. PENDENTE paths exatos de Archiso 260809 e kernel cmdline; não usar Casper.

A transação só pode modificar a extensão criada/reivindicada pelo seu plano tipado. Persistir estado, dono, identificador da operação, ação compensadora e pré/pós-condições numa sessão de recuperação **antes** da mutação. Proibir limpeza de artefactos não próprios. Handoff com hash e validação de nonce/plan/guest/disk sempre que backend novo. Não confiar em /dev/sda, letras Windows, nomes de volume ou linha COM1 isolada.

## 6. Instalador nativo e automatização

Backend independente usa Archiso real e pacstrap/pacman, keyring/CachyOS repositories assinadas, mkinitcpio, kernel linux-cachyos ou LTS e firstboot; não executar pacstrap Debian mini-ISO nem copiar Live rootfs. COMPROVADO [Actions #43954231860](https://github.com/LMhdez/gaslux/actions/runs/43954231860), commit dea48bfe47d9fc656f4c069c45f46d1d092c0245: pacstrap -K mínimo e primeiro boot numa GPT Linux-only sem Windows. Códigos #36 que fazem sgdisk --clear ou formatam ESP **não** podem tocar Windows.

## 7. Particionamento e proteção Windows

Antes de escrever: confirmar firmware/tabela; disco por identificador persistente, tamanho, setor real, assinatura/GUID, geometria e offsets exatos; Windows, BCD, WinRE, ESP/MBR/PBR, Recovery/OEM, BitLocker/Device Encryption, NTFS shrink e witness hashes. Repetir no Live e antes de cada fase; rejeitar IDs ambíguos, alterações após reboot, ESP sem espaço e qualquer partição estrangeira. MBR: quatro entradas primárias, extended/logical/EBR e active flag; GPT: CRC, UUID, ESP e NVRAM. Nunca converter firmware/tabela nem alterar chaves.

## 8. Configuração do sistema instalado

Configurar conta, senha, locale, teclado, timezone, sudo/grupos, fstab por UUID/PARTUUID, kernel LTS, initramfs, pacman DB, serviços, rede e desktop se escolhida. Provar ID=cachyos, kernel/modules, boot mode, login e pacote pacman -Q após primeiro boot real. Falha keyring/mirror deve manter transação recuperável e nunca desabilitar assinatura.

## 9. Bootloader e manutenção

Documentado upstream: GRUB/systemd-boot/Limine/rEFInd selecionáveis. PR #36 prova GRUB EFI fallback no disco **Linux-only**, não na ESP Windows. Em Windows-shared é proibido sobrepor EFI/BOOT/BOOTX64.EFI Microsoft; fixar diretório/entrada própria e preservar BootOrder. Pacman hooks e mkinitcpio requerem backend Arch, não dpkg-divert/apt Mint.

## 10. Atualizações e desinstalação

Atualizações via pacman e hooks de kernel/initramfs/GRUB; validar boot Linux e Windows pós-update e falha de update, rede e NVRAM. Desinstalação remove apenas ESP/root/boot entries próprios e revalida Windows boot, BCD/WinRE, não apaga artefactos de outras transações.

## 11. Recuperação e rollback

Em hash inválido, corte de energia, rede indisponível, falta de espaço, disco/UUID trocado ou falha parcial de bootloader: recusar novo write, recuperar apenas recursos próprios depois de revalidar geometria; restaurar boot/ordem EFI/BCD ou MBR/PBR/active flag; verificar Windows boot real, WinRE, BitLocker, EFI e testemunhos. Logs e marcadores são auxiliares, não prova. Snapshot COW protege ensaio VM, não substitui rollback do produto.

## 12. Código Gaslux reutilizável

Contrato Windows partilhado PR #165 (Ed25519), pacstrap root-only #171, mount identity #184, carrier #215 e GPT Windows real #161; reutilizar preflight/plan/state/rollback do Gaslux. Verificar existência no HEAD: PRs fechadas sem merge não estão automaticamente em dev. **Não** reutilizar destrutiva #36 no disco Windows.

## 13. PRs, branches e commits relevantes

[Issue #3](https://github.com/LMhdez/gaslux/issues/3) aberta (acceptance); [PR #36](https://github.com/LMhdez/gaslux/pull/36), [Actions #43954231860](https://github.com/LMhdez/gaslux/actions/runs/43954231860), [artefacto #14271728542](https://github.com/LMhdez/gaslux/actions/runs/43954231860/artifacts/14271728542): firstboot Linux-only; [PR #161](https://github.com/LMhdez/gaslux/pull/161) Windows10 arrancou após quinta ext4 GPT sem Cachy instalado; [#165](https://github.com/LMhdez/gaslux/pull/165), [#171](https://github.com/LMhdez/gaslux/pull/171), [#184](https://github.com/LMhdez/gaslux/pull/184), [#215](https://github.com/LMhdez/gaslux/pull/215) labs. Branch fix/cachyos-configured-root-grant-binding-issue3 @ c5b3246dc8df9873015291dbb64a3c0ddecc8613, [Actions #44586267350](https://github.com/LMhdez/gaslux/actions/runs/44586267350) SUCCESS sintético e [#44586277571](https://github.com/LMhdez/gaslux/actions/runs/44586277571) in_progress no snapshot.

## 14. Problemas conhecidos e causas identificadas

Perigo de confundir prova de Windows boot pós-partição, prova de pacstrap Linux-only e handoff com um dual boot complete; **não são a mesma execução**. Mini-ISO Debian não tem pacstrap nativo. ESP Windows não pode receber fallback. Pacman keyring/mirrors causaram problemas em runs antigas e foram corrigidos sem bypass de assinaturas. Secure Boot/MBR sem provas proibidos.

## 15. Soluções tecnicamente verificadas

COMPROVADO N3 parcial Linux-only por Actions #43954231860 e N4 parcial Windows10 boot com ext4 sem Linux instalado por PR #161; **N4 Windows+CachyOS instalado não comprovado**. Job Windows shared-root #44586277571 não tinha conclusão no momento consultado. PENDENTE N5 e updates. #3 permanece gate release.

## 16. Matriz de compatibilidade

| Configuração | Estado comprovado ou bloqueio |
|---|---|
| Win10 UEFI/GPT | Handoff/stage experimental; installed dualboot e recovery PENDENTES |
| Win11 UEFI/GPT | PENDENTE |
| Win10 BIOS/MBR | BLOQUEADO sem backend/EBR/VM firstboot |
| Segundo disco | PENDENTE binding de serial e ESP |
| Secure Boot enabled | BLOQUEADO no caminho atual |
| UEFI/MBR e BIOS/GPT | BLOQUEADO |

## 17. Testes existentes e evidências

COMPROVADO N3 parcial Linux-only por Actions #43954231860 e N4 parcial Windows10 boot com ext4 sem Linux instalado por PR #161; **N4 Windows+CachyOS instalado não comprovado**. Job Windows shared-root #44586277571 não tinha conclusão no momento consultado. PENDENTE N5 e updates. #3 permanece gate release.

## 18. Testes ainda necessários

N0 contratos/unit/Pester/C#/Python/ShellCheck e sintaxe; N1 mídia ISO assinada/tamanho/hash/identidade; N2 arranque Live; N3 instalador real + Linux instalado e segundo boot sem ISO; N4 dois SO no mesmo QCOW2 Windows realmente instalado; N5 atualizações, falhas, desinstalação e rollback verificável; N6 hardware sob autorização com backup restaurável. Testes sintéticos e Live não provam N3-N5.

Para CachyOS: 1. Auditar #165→#171/#184/#215 e HEAD fix/...; 2. provar signature/ISO→Archiso/serial handoff em COW Windows read-only; 3. pacstrap apenas owned root + bootloader sem Windows modifications; 4. dois boot Linux/Windows com Linux instalado; 5. pacman/kernel/GRUB updates, rollback sob falhas e Win10/11; 6. BIOS/MBR apenas com plano separado. Só fechar issue #3 com provas completas.

## 19. Plano de implementação ordenado

1. Auditar #165→#171/#184/#215 e HEAD fix/...; 2. provar signature/ISO→Archiso/serial handoff em COW Windows read-only; 3. pacstrap apenas owned root + bootloader sem Windows modifications; 4. dois boot Linux/Windows com Linux instalado; 5. pacman/kernel/GRUB updates, rollback sob falhas e Win10/11; 6. BIOS/MBR apenas com plano separado. Só fechar issue #3 com provas completas.

## 20. Critérios objetivos de estabilidade

Apenas N5 com Linux/Windows boots, updates, rollback/remoção e provas de identidade no mesmo Windows QCOW2 e firmware aprovado; hardware sob autorização e backup restaurado. Não extrapolar para Secure Boot, segundo disco ou EBR sem cobertura.

## ONE-SHOT EXECUTION PLAYBOOK

**Branch recomendada:** feature/cachyos-windows-shared-pacstrap-issue3 a partir de ancestrais e dev HEAD auditados (confirmar HEAD, ancestralidade e autorização LMhdez). **Ficheiros a tocar:** backend Archiso isolado, testes, schemas/C#/PS/Python se capacidades evoluírem; não alterar apt/dpkg Mint/Zorin, release-config ou EFI Windows. **Condição adicional STOP:** pacstrap fora de Archiso, ISO hash/assinatura falhada, membro GPT não owned, mudança WinRE/BCD/EFI, Secure Boot, EBR desconhecida, CI sem primeiro Windows boot. Não alterar código funcional ou catálogo estável fora do PR de implementação aprovado.

### Ordem de execução verificável

1. Reabrir main, dev, PRs, issues, Actions e artefactos no HEAD exato; comparar ancestrais e código já integrado.
2. Autenticar versão/edição ISO e inventariar El Torito/EFI, kernel/initrd, payload, instalador e respetivos hashes. Corrigir contradições upstream antes de escolher parâmetros.
3. Executar exclusivamente **testes não destrutivos** de schema, identidade, assinatura, boot policy, plan/state/ownership, regressões Mint/Zorin e recusa de layouts.
4. Validar read-only disco Windows QCOW2 instalado, baseline de boot/WinRE/BitLocker e a recuperação. Falha aqui implica STOP, sem instalação.
5. Provar no convidado firmware/cmdline/ISO/identidade e handoff sem USB. Só depois de autorizar explicitamente VM descartável e snapshot, permitir write set definido.
6. Executar **instalador real** sobre partições pertencentes à transação e verificar root, utilizador, locale, bootloader, pacotes e primeiro boot sem ISO.
7. Provar independentemente arranque Windows e Linux no mesmo overlay, integridade ESP/BCD/WinRE, updates de kernel/bootloader e segunda ronda de boots.
8. Injetar falhas de energia, rede, hash, IDs, armazenamento, atualização e loader; desinstalar/reinstalar; comparar geometria e voltar a Windows. Só propor fecho/release depois de N5 e revisão humana.

### Pré-requisitos, ficheiros e comandos

- **Conta GitHub LMhdez** e branch de trabalho dedicada a partir de dev **atual**; identificar SHA/PRs a reutilizar na secção 13. Não fazer merge automático.
- Ler AGENTS.md, AI_POLICY.md, CONTRIBUTING.md, docs/ARCHITECTURE.md, docs/UEFI_BOOTNEXT_BOOTORDER.md, docs/distro-backends/SHARED_CONTRACTS.md.
- **Contratos a preservar:** schemas/installation-plan.schema.json, schemas/installation-state.schema.json, InstallationPlanFactory, InstallationExecutionLedger e estado C#/PowerShell/Python, BootGuardian e rollback.
- **Comandos não destrutivos**: git diff --check; bash -n assets/live/libertix-install-main.sh; python3 -m pytest -q auto_tests/tests (no ambiente de testes provisionado, sem ativar fixtures de escrita). Usar CONTRIBUTING.md/README.md e workflows reais na branch para Ruff, ShellCheck, Pester e build C#; não inventar identificadores de workflows. Todos os jobs VM de escrita requerem autorização explícita, snapshot e exactidão dos discos.
- **NÃO alterar:** release-config.json estável, chaves, EFI/Microsoft, Windows Recovery/OEM, scripts de outros backends ou loader de Windows.
- **STOP:** assinatura/hash/versão divergentes, firmware não elegível, discos/partições/ownership ambíguos, recuperação não preparada, write-set que toca Windows, falta de rede segura, falha de teste de Windows boot.
- **Evidências para fechar:** commit SHA, identidade e assinatura de mídia, PARTUUID/bytes/sector/offsets, snapshots de estado, artefactos hash-verified, guest+host logs, Linux e Windows boots reais, updates e rollback verificado com WinRE/BCD/ESP/MBR/BitLocker. Nenhuma extrapolação de VM sintética para hardware real.

**Fontes/links verificados nesta investigação:** secções 2 e 13; data 2026-11-19. O próximo agente deve recolher no HEAD os nomes e inputs exatos dos workflows e IDs/posição de controlos do instalador, mantendo **PENDENTE** qualquer clique, caminho, argumento kernel ou hash não comprovado. O utilizador final não deve executar passos manuais.
