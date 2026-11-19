# Zorin OS 18.1 Core — guia técnico operacional Gaslux

**Snapshot:** 2026-11-19 UTC; **identidade:** zorin/zorin; backend debian-squashfs. Referências repositório: main 90b044ba435b2b4b4db6c5813ca4698b37e4a555, dev 34d50646783498000eb13dbaf8a63220e63ff719. A cada trabalho revalidar versões e branch. [Contratos partilhados](SHARED_CONTRACTS.md) e [índice](README.md) são obrigatórios.

**Classes:** DOCUMENTADO = upstream oficial; IMPLEMENTADO = código identificável; COMPROVADO = Actions/artefacto/commit e âmbito real; PENDENTE = sem prova; BLOQUEADO = não escrever. Uma Live, root extraída ou COW sintética não é dual boot.

## 1. Resumo executivo e maturidade

IMPLEMENTADO no catálogo main e caminho Debian/Ubuntu herdado. Experimentos firstboot e segundo initramfs boot em GPT sintética não provam Windows dual boot completo.

## 2. Fontes oficiais e versões consultadas

[Zorin install](https://help.zorin.com/docs/getting-started/install-zorin-os/), [Zorin integrity](https://help.zorin.com/docs/getting-started/check-the-integrity-of-your-copy-of-zorin-os/), [Zorin details](https://zorin.com/os/details/), [download 18.1](https://zorin.com/os/download/18/core/) consultados 2026-11-19; contrato main release-config.json.

## 3. Arquitetura de arranque

Gaslux usa mini-ISOs BIOS/UEFI e live runner comum; parâmetros de arranque Casper devem ser obtidos dos ficheiros oficiais 18.1, não inferidos. BIOS exige identidade MBR/PBR/BCD e slot/EBR; UEFI valida ESP, Windows Boot Manager e BootNext/BootOrder. Zorin upstream declara que Secure Boot funciona em muitos equipamentos modernos, mas a elegibilidade no Gaslux depende da autoridade e binários da ISO e da firmware real. Testar recuperação se Live falhar.

## 4. Estrutura e autenticação da ISO

IMPLEMENTADO main: ISO Zorin-OS-18.1-Core-64-bit.iso em https://mirrors.univ-reims.fr/IMAGES/zorinos/18/Zorin-OS-18.1-Core-64-bit.iso, **3 909 091 328 bytes**, SHA-256 **44649b97bd307fc4c8529205d098ebbf98575a1e1ba2ee7d7005b697af1721d5**. DOCUMENTADO: página oficial Zorin lista o mesmo SHA para 18.1 Core. ID=zorin, x86_64. Não extrapolar para Pro/Lite ou futuras versões. PENDENTE inventário completo de certificados/assinaturas de boot e ISO offsets.

## 5. Sequência completa Windows → Linux

IMPLEMENTADO: descoberta de exatamente um filesystem.squashfs e inspeção de etc/os-release ID=zorin, ID_LIKE Debian/Ubuntu, dpkg, update-grub e update-initramfs. Live baseada em casper. PENDENTE manifesto concreto El Torito, kernel/initrd, squashfs interno, EFI e versão/executável do instalador gráfico **na ISO 18.1**, sem supor que reproduz Ubiquity de releases passadas.

A transação só pode modificar a extensão criada/reivindicada pelo seu plano tipado. Persistir estado, dono, identificador da operação, ação compensadora e pré/pós-condições numa sessão de recuperação **antes** da mutação. Proibir limpeza de artefactos não próprios. Handoff com hash e validação de nonce/plan/guest/disk sempre que backend novo. Não confiar em /dev/sda, letras Windows, nomes de volume ou linha COM1 isolada.

## 6. Instalador nativo e automatização

IMPLEMENTADO: backend debian-squashfs de Gaslux, não o installer GUI upstream invocado por API. É obrigação verificar que sistema final conserva identidade e pacotes Zorin, fstab por UUID, kernel instalado, initramfs, GRUB assinado e não um mero root Live. Autoinstall do installer upstream, flags, YAML/JSON e versão exatos PENDENTES até inspecção da ISO; não inventar cliques.

## 7. Particionamento e proteção Windows

Antes de escrever: confirmar firmware/tabela; disco por identificador persistente, tamanho, setor real, assinatura/GUID, geometria e offsets exatos; Windows, BCD, WinRE, ESP/MBR/PBR, Recovery/OEM, BitLocker/Device Encryption, NTFS shrink e witness hashes. Repetir no Live e antes de cada fase; rejeitar IDs ambíguos, alterações após reboot, ESP sem espaço e qualquer partição estrangeira. MBR: quatro entradas primárias, extended/logical/EBR e active flag; GPT: CRC, UUID, ESP e NVRAM. Nunca converter firmware/tabela nem alterar chaves.

## 8. Configuração do sistema instalado

Conta e segredo protegido, sudo, idioma, teclado, fuso horário, permissões, Windows shares e preferências são configurados pelo common Live; provar no sistema arrancado. Contrato Windows protege senha hash e não a deve expor em logs; validar utilizador e timezone também após updates.

## 9. Bootloader e manutenção

Debian/Ubuntu GRUB e shim com cadeia assinatura da distribuição; wrappers dpkg-divert/update-grub e EFI sync herdados da arquitetura Gaslux. Em BIOS validar GRUB target e BCD sem alterar MBR estrangeiro; em UEFI preservar EFI/Microsoft. Nunca reutilizar esta cadeia para Pop/systemd-boot ou Cachy/Arch.

## 10. Atualizações e desinstalação

Apt, dpkg, update-initramfs, update-grub, atualização GRUB/shim; cada update requer reboot e prova de menu/Windows entry, WinRE/BCD e Linux. Desinstalação e reinstalação removem apenas recursos de transação, com rollback de disco/firmware verificado.

## 11. Recuperação e rollback

Em hash inválido, corte de energia, rede indisponível, falta de espaço, disco/UUID trocado ou falha parcial de bootloader: recusar novo write, recuperar apenas recursos próprios depois de revalidar geometria; restaurar boot/ordem EFI/BCD ou MBR/PBR/active flag; verificar Windows boot real, WinRE, BitLocker, EFI e testemunhos. Logs e marcadores são auxiliares, não prova. Snapshot COW protege ensaio VM, não substitui rollback do produto.

## 12. Código Gaslux reutilizável

Installation/InstallationPlan*.cs, InstallationExecutionLedger.cs, Scripts/modules/, assets/live/libertix-distribution-common.sh, configure-target-main.sh, libertix-rollback-common.sh, schemas/ — sem reescrita do caminho Mint. PR #62 em dev separa target/boot fases. PR #167 fechada sem merge acrescenta pré-verificação ISO/rootfs; confirmar código efetivo.

## 13. PRs, branches e commits relevantes

[PR #62](https://github.com/LMhdez/gaslux/pull/62) integrada dev; [#167](https://github.com/LMhdez/gaslux/pull/167) pré-escrita; [#176](https://github.com/LMhdez/gaslux/pull/176) root installed first boot; [#219](https://github.com/LMhdez/gaslux/pull/219) segundo boot após update-initramfs, [Actions #44582546627](https://github.com/LMhdez/gaslux/actions/runs/44582546627) SUCCESS; [#224](https://github.com/LMhdez/gaslux/pull/224) draft aberta, raiz 18.1 numa quinta GPT **Windows-shaped sintética**, [Actions #44582528728](https://github.com/LMhdez/gaslux/actions/runs/44582528728) SUCCESS, HEAD 3a10dac2d85dd19849a0736d8f57558827277794. [#175](https://github.com/LMhdez/gaslux/pull/175) proposta integração draft.

## 14. Problemas conhecidos e causas identificadas

O ensaio #224 usa GPT sintética de forma Windows, **não** uma instalação Windows real; não afirmar dual boot. A variante do instalador native upstream da ISO Zorin 18.1 não foi registada neste snapshot. Pré-escrita #167 pode faltar na branch; verificar. Limitação de Secure Boot por firmware e cifragem real é condição, não hipótese aprovada.

## 15. Soluções tecnicamente verificadas

COMPROVADO: Actions #44582546627 passou ensaio Zorin OVMF do segundo boot após regenerar initramfs; Actions #44582528728 passou importação/boot Zorin numa GPT sintética. Nenhuma destas provas inclui Windows realmente instalado nem rollback Windows. Artefactos e SHAs devem ser validados por um novo agente antes de reutilizar.

## 16. Matriz de compatibilidade

| Configuração | Estado comprovado ou bloqueio |
|---|---|
| Win10 BIOS/MBR | Original implementado; N4/N5 PENDENTES |
| Win10 UEFI/GPT | Original implementado; N4/N5 PENDENTES |
| Win11 UEFI/GPT | PENDENTE provas N4/N5 e TPM/WinRE |
| Segundo disco | PENDENTE transação e double boot |
| Secure Boot | Condicional ao signers Zorin/firmware reais |
| EBR não auditada, BIOS/GPT, UEFI/MBR | BLOQUEADO |

## 17. Testes existentes e evidências

COMPROVADO: Actions #44582546627 passou ensaio Zorin OVMF do segundo boot após regenerar initramfs; Actions #44582528728 passou importação/boot Zorin numa GPT sintética. Nenhuma destas provas inclui Windows realmente instalado nem rollback Windows. Artefactos e SHAs devem ser validados por um novo agente antes de reutilizar.

## 18. Testes ainda necessários

N0 contratos/unit/Pester/C#/Python/ShellCheck e sintaxe; N1 mídia ISO assinada/tamanho/hash/identidade; N2 arranque Live; N3 instalador real + Linux instalado e segundo boot sem ISO; N4 dois SO no mesmo QCOW2 Windows realmente instalado; N5 atualizações, falhas, desinstalação e rollback verificável; N6 hardware sob autorização com backup restaurável. Testes sintéticos e Live não provam N3-N5.

Para Zorin OS: 1. Auditar #176/#219/#224 e compara dev/main; 2. inventariar ISO 18.1 e binário instalador exato; 3. teste pré-escrita com ISO errada; 4. Windows10/11 QCOW2 real para instalação + ambos boot; 5. atualização kernel/GRUB/shim e falhas/rollback com WinRE intacta.

## 19. Plano de implementação ordenado

1. Auditar #176/#219/#224 e compara dev/main; 2. inventariar ISO 18.1 e binário instalador exato; 3. teste pré-escrita com ISO errada; 4. Windows10/11 QCOW2 real para instalação + ambos boot; 5. atualização kernel/GRUB/shim e falhas/rollback com WinRE intacta.

## 20. Critérios objetivos de estabilidade

Apenas N5 com Linux/Windows boots, updates, rollback/remoção e provas de identidade no mesmo Windows QCOW2 e firmware aprovado; hardware sob autorização e backup restaurado. Não extrapolar para Secure Boot, segundo disco ou EBR sem cobertura.

## ONE-SHOT EXECUTION PLAYBOOK

**Branch recomendada:** feature/zorin-native-root-proof-<etapa> de dev HEAD atual (confirmar HEAD, ancestralidade e autorização LMhdez). **Ficheiros a tocar:** assets/live/, Installation/, Scripts/, testes; preservar Mint, catálogo e EFI/Microsoft. **Condição adicional STOP:** ISO/identity/capability mismatch, Windows GPT/ESP/BCD alterados, EBR ambígua, BitLocker não elegível, boot Windows não verificado. Não alterar código funcional ou catálogo estável fora do PR de implementação aprovado.

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
