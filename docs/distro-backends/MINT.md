# Linux Mint 22.3 Cinnamon — guia técnico operacional Gaslux

**Snapshot:** 2026-11-19 UTC; **identidade:** mint/linuxmint; backend debian-squashfs. Referências repositório: main 90b044ba435b2b4b4db6c5813ca4698b37e4a555, dev 34d50646783498000eb13dbaf8a63220e63ff719. A cada trabalho revalidar versões e branch. [Contratos partilhados](SHARED_CONTRACTS.md) e [índice](README.md) são obrigatórios.

**Classes:** DOCUMENTADO = upstream oficial; IMPLEMENTADO = código identificável; COMPROVADO = Actions/artefacto/commit e âmbito real; PENDENTE = sem prova; BLOQUEADO = não escrever. Uma Live, root extraída ou COW sintética não é dual boot.

## 1. Resumo executivo e maturidade

IMPLEMENTADO no catálogo main e no instalador Libertix herdado; **não** é certificação de todas as variantes firmware/BitLocker; experiências COW não certificam native full dual boot.

## 2. Fontes oficiais e versões consultadas

[Mint ISO verify](https://linuxmint-installation-guide.readthedocs.io/en/latest/verify.html), [Mint install](https://linuxmint-installation-guide.readthedocs.io/en/latest/install.html), [linuxmint/ubiquity](https://github.com/linuxmint/ubiquity), [release-config](../../release-config.json), consulta 2026-11-19. A assinatura dos manifests do catálogo Gaslux é RSA (docs/ARCHITECTURE.md).

## 3. Arquitetura de arranque

O caminho Gaslux já existente inicia mini-ISO BIOS e UEFI em iso/ e iso-uefi/, revalida plano e cadeia Windows, extrai target e instala loader de distribuição. NÃO é um comando de boot direto da ISO Mint via BCD. BIOS/MBR: auditar GRUB4DOS, código MBR/PBR, partição ativa, BCD e GRUB target. UEFI/GPT: ESP, BootNext, BootOrder, shim/grub assinado e Windows Boot Manager. Secure Boot só quando a cadeia Microsoft assinante da própria ISO bate com autoridade da máquina. Alternativa de kernel+initrd/loopback Casper: PENDENTE ensaio com ISO exata e filesystem acessível.

## 4. Estrutura e autenticação da ISO

IMPLEMENTADO no release-config.json main: ISO linuxmint-22.3-cinnamon-64bit.iso em https://pub.linuxmint.io/stable/22.3/linuxmint-22.3-cinnamon-64bit.iso, **3 091 660 800 bytes**, SHA-256 **a081ab202cfda17f6924128dbd2de8b63518ac0531bcfe3f1a1b88097c459bd4**; x86_64, ID=linuxmint. DOCUMENTADO upstream: sha256sum.txt e sha256sum.txt.gpg oficiais; validar assinatura/chave antes de confiar no arquivo. Não autorizar edições MATE/Xfce/LMDE por identidade semelhante. PENDENTE: inventário byte-a-byte ISO 22.3 e assinaturas das subimagens.

## 5. Sequência completa Windows → Linux

IMPLEMENTADO: assets/live/libertix-distribution-common.sh exige exactly one filesystem.squashfs, ID=linuxmint e capacidades etc/os-release, var/lib/dpkg/status, update-grub, update-initramfs, lsinitramfs. Live Mint baseada em Casper. PENDENTE: paths exatos de vmlinuz, initrd, EFI executables, El Torito, parâmetros de kernel, posição ISO e prova de SquashFS descoberto pós-pivot. Estes devem ser extraídos da ISO verificada, não inventados.

A transação só pode modificar a extensão criada/reivindicada pelo seu plano tipado. Persistir estado, dono, identificador da operação, ação compensadora e pré/pós-condições numa sessão de recuperação **antes** da mutação. Proibir limpeza de artefactos não próprios. Handoff com hash e validação de nonce/plan/guest/disk sempre que backend novo. Não confiar em /dev/sda, letras Windows, nomes de volume ou linha COM1 isolada.

## 6. Instalador nativo e automatização

IMPLEMENTADO Gaslux: assets/live/libertix-install-main.sh + configure-target-main.sh e helpers Debian/Ubuntu materializam e configuram SquashFS no staging da transação. O instalador Ubiquity upstream existe, mas **não** foi demonstrado como API do backend Gaslux; não substituir caminho funcional sem motivo. Provar que raiz materializada tem kernel instalado (não live Casper), dpkg consistente, fstab por UUID e boot GRUB package-owned.

## 7. Particionamento e proteção Windows

Antes de escrever: confirmar firmware/tabela; disco por identificador persistente, tamanho, setor real, assinatura/GUID, geometria e offsets exatos; Windows, BCD, WinRE, ESP/MBR/PBR, Recovery/OEM, BitLocker/Device Encryption, NTFS shrink e witness hashes. Repetir no Live e antes de cada fase; rejeitar IDs ambíguos, alterações após reboot, ESP sem espaço e qualquer partição estrangeira. MBR: quatro entradas primárias, extended/logical/EBR e active flag; GPT: CRC, UUID, ESP e NVRAM. Nunca converter firmware/tabela nem alterar chaves.

## 8. Configuração do sistema instalado

Conta, hash de senha protegido, sudo/grupos, idioma, teclado, timezone e partilhas estão previstos no plano e scripts Live. Verificar login real com locale e timezone efetivos no primeiro e no segundo boot. Password hash retirada do Windows após verificação; não publicar segredo nos logs.

## 9. Bootloader e manutenção

ARCHITECTURE.md descreve shim/grub package-owned, dpkg-divert e wrapper update-grub com validação de Windows entry/EFI; EFI sync via serviço/hook, substituição com arquivo e hash. Linux Mint é APT/dpkg, não pacman ou rpm-ostree. Testar reinstalação de grub/shim, kernel e regeneração initramfs, com entradas Microsoft e Linux válidas.

## 10. Atualizações e desinstalação

Atualizar kernel, initramfs, GRUB e shim em VM e provar dois boots pós-atualização, WinRE e BCD. Desinstalar apenas root/ESP/BCD/GRUB/Recovery tasks identificados por transação, restaurar geometria Windows e BootOrder; uma nova instalação não deve apagar ownership antigo.

## 11. Recuperação e rollback

Em hash inválido, corte de energia, rede indisponível, falta de espaço, disco/UUID trocado ou falha parcial de bootloader: recusar novo write, recuperar apenas recursos próprios depois de revalidar geometria; restaurar boot/ordem EFI/BCD ou MBR/PBR/active flag; verificar Windows boot real, WinRE, BitLocker, EFI e testemunhos. Logs e marcadores são auxiliares, não prova. Snapshot COW protege ensaio VM, não substitui rollback do produto.

## 12. Código Gaslux reutilizável

Reutilizar Installation/InstallationPlan*.cs, InstallationExecutionLedger.cs, Scripts/modules/Libertix.InstallationPlan.psm1, Scripts/libertix-storage-preflight.ps1, assets/live/libertix-distribution-common.sh, assets/live/configure-target-main.sh e libertix-rollback-common.sh. PR #62 integrada em dev separa fases de configuração Ubuntu/GRUB preservando ordem; PR #167 (fechada sem merge) pode conter guard de verificação da ISO **antes** da primeira escrita.

## 13. PRs, branches e commits relevantes

[PR #7](https://github.com/LMhdez/gaslux/pull/7) e [#62](https://github.com/LMhdez/gaslux/pull/62) integradas em dev; [#167](https://github.com/LMhdez/gaslux/pull/167) pré-escrita; [#174](https://github.com/LMhdez/gaslux/pull/174) live boot; [#181](https://github.com/LMhdez/gaslux/pull/181) firstboot root em GPT Linux-only; [#185](https://github.com/LMhdez/gaslux/pull/185) extração em quinta GPT COW Windows10; [#212](https://github.com/LMhdez/gaslux/pull/212) declarou explicitamente que live SquashFS COW **não** prova instalação nativa. Comparar SHAs/ancestralidade, pois PRs experimentais estão fechadas sem merge.

## 14. Problemas conhecidos e causas identificadas

Causa de risco: a validação de rootfs/ISO pode ocorrer tarde se o patch #167 não está no backend atual; verificar estágio pré-escrita no código, não deduzir do título. Kernel Live na COW não é kernel instalado. Testes VM Linux-only/Win10-COW diferentes não devem ser combinados como se fossem a mesma transação. Falhas de EBR ou Device Encryption devem rejeitar pré-escrita.

## 15. Soluções tecnicamente verificadas

COMPROVADO apenas no âmbito declarado pelos PRs: em #181 ensaio de raiz Mint numa GPT descartável; em #185 ensaio de materialização em partição ext4 de COW Windows10; #212 kernel/initramfs e shutdown de Live. PENDENTE prova de native installer end-to-end, Windows e Mint boots após atualização, rollback Windows completo. Não assumir CI green de outras branches.

## 16. Matriz de compatibilidade

| Configuração | Estado comprovado ou bloqueio |
|---|---|
| Win10 BIOS/MBR | Backend original implementado; N4/N5 específicos PENDENTES |
| Win10 UEFI/GPT | Backend original implementado; N4/N5 específicos PENDENTES |
| Win11 UEFI/GPT | PENDENTE campanha BitLocker/WinRE/TPM + N4/N5 |
| Segundo disco | Revalidar seleção, dois arranques e rollback por disk ID |
| Secure Boot | Condicional a shim/signer e firmware reais, não universal |
| MBR EBR ambígua, UEFI/MBR, BIOS/GPT | BLOQUEADO sem prova |

## 17. Testes existentes e evidências

COMPROVADO apenas no âmbito declarado pelos PRs: em #181 ensaio de raiz Mint numa GPT descartável; em #185 ensaio de materialização em partição ext4 de COW Windows10; #212 kernel/initramfs e shutdown de Live. PENDENTE prova de native installer end-to-end, Windows e Mint boots após atualização, rollback Windows completo. Não assumir CI green de outras branches.

## 18. Testes ainda necessários

N0 contratos/unit/Pester/C#/Python/ShellCheck e sintaxe; N1 mídia ISO assinada/tamanho/hash/identidade; N2 arranque Live; N3 instalador real + Linux instalado e segundo boot sem ISO; N4 dois SO no mesmo QCOW2 Windows realmente instalado; N5 atualizações, falhas, desinstalação e rollback verificável; N6 hardware sob autorização com backup restaurável. Testes sintéticos e Live não provam N3-N5.

Para Linux Mint: 1. Auditar HEADs/main/dev e fluxo antes de mkfs, comparar #62/#167/#181/#185. 2. Fixar manifesto interno da ISO e verificar GPG. 3. Exercitar preflight/rollback, Mint e Zorin regressões. 4. Numa VM Windows real autorizada provar instalação sem USB, dois SO boots, kernel+GRUB updates, falhas e desinstalação. 5. Documentar provas por variante antes de afirmar estabilidade.

## 19. Plano de implementação ordenado

1. Auditar HEADs/main/dev e fluxo antes de mkfs, comparar #62/#167/#181/#185. 2. Fixar manifesto interno da ISO e verificar GPG. 3. Exercitar preflight/rollback, Mint e Zorin regressões. 4. Numa VM Windows real autorizada provar instalação sem USB, dois SO boots, kernel+GRUB updates, falhas e desinstalação. 5. Documentar provas por variante antes de afirmar estabilidade.

## 20. Critérios objetivos de estabilidade

Apenas N5 com Linux/Windows boots, updates, rollback/remoção e provas de identidade no mesmo Windows QCOW2 e firmware aprovado; hardware sob autorização e backup restaurado. Não extrapolar para Secure Boot, segundo disco ou EBR sem cobertura.

## ONE-SHOT EXECUTION PLAYBOOK

**Branch recomendada:** feature/mint-safe-prewrite-and-dualboot-<etapa> a partir de dev HEAD revalidado (confirmar HEAD, ancestralidade e autorização LMhdez). **Ficheiros a tocar:** Installation/, Scripts/, assets/live/ e testes; preservar release-config.json, chaves e código de outros backends. **Condição adicional STOP:** ISO errada, ext4 não própria, Windows BCD/WinRE/BitLocker divergentes, EBR não auditada, recusa de Win Boot Manager ou recuperação não armada. Não alterar código funcional ou catálogo estável fora do PR de implementação aprovado.

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
