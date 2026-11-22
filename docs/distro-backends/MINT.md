# Linux Mint — ONE-SHOT backend dossier

> **Atualização de navegação (22-11-2026):** este dossier mantém a análise histórica de 19-11. Revalidar HEADs, PRs/merges, media e artefactos antes de usar as propostas. Ver [histórico e instruções por agente](../AGENT_HISTORICAL_PLAYBOOK.md), [índice GitHub Actions/VM](../CI_VM_EVIDENCE_INDEX.md) e [contratos partilhados](SHARED_CONTRACTS.md). Propostas antigas de criação de branch/PR não substituem a regra atual de reutilização e consolidação; testes QEMU descartáveis têm autorização delimitada em [AGENTS](../../AGENTS.md).

**Revisão:** 2026-11-19. **Maturidade:** IMPLEMENTADO: entrada no catálogo main e runtime de família Ubuntu; instalação integral em todos os cenários e rollback continuam dependentes de prova real. Ver [contratos gerais](SHARED_CONTRACTS.md). **Não usar este documento como autorização de escrita.**

## 1. Resumo executivo e estado
Live QEMU e raiz Linux em imagem isolada não provam instalação automática Gaslux nem rollback Windows. O objectivo é uma instalação nativa automatizada ao lado do Windows, com prova independente dos dois boots e recuperação. Compatibilidade upstream não equivale a suporte validado no Gaslux.

## 2. Fontes oficiais, versões e proveniência
- [Origem oficial/media](https://pub.linuxmint.io/stable/22.3/linuxmint-22.3-cinnamon-64bit.iso) — versão/release: **22.3 Cinnamon**. [DOCUMENTADO como endereço de referência; revalidar disponibilidade, conteúdo e assinatura na data da execução.]
- [Documentação upstream](https://linuxmint-installation-guide.readthedocs.io/en/latest/verify.html) — instruções gerais, não aprovação de boot sem USB. [DOCUMENTADO; verificar versão, data e parâmetros antes de automatizar.]
- [Configuração Gaslux main](https://github.com/LMhdez/gaslux/blob/main/release-config.json) — fonte dos metadados exactos da ISO. [IMPLEMENTADO]
- [Arquitectura Gaslux](https://github.com/LMhdez/gaslux/blob/dev/docs/ARCHITECTURE.md), [contratos de segurança Mint/Zorin](../ARCHITECTURE.md) e [PR multidistro #7](https://github.com/LMhdez/gaslux/pull/7). [IMPLEMENTADO/critério documental]
- PRs/threads experimentais relacionadas: [#167](https://github.com/LMhdez/gaslux/pull/167), [#174](https://github.com/LMhdez/gaslux/pull/174), [#181](https://github.com/LMhdez/gaslux/pull/181), [#197](https://github.com/LMhdez/gaslux/pull/197), [#204](https://github.com/LMhdez/gaslux/pull/204), [#233](https://github.com/LMhdez/gaslux/pull/233). **Consultar HEAD, estado de merge, logs e branches antes de reutilizar.**
- Evidência histórica de CI para contexto: [Actions](https://github.com/LMhdez/gaslux/actions/runs/44147851503); a existência ou êxito do workflow não certifica todas as etapas. [PENDENTE: rever job e artefactos exactos.]

## 3. Arquitectura de arranque
**Estratégia:** GRUB BIOS ou GRUB EFI com shim assinado onde o firmware/ISO o suportem. **Modo:** BIOS/MBR e UEFI/GPT: caminhos de infraestrutura em main; conformidade fim-a-fim ainda exige provas por cenário.
[DOCUMENTADO/pendente por mídia] Em BIOS o arranque envolve MBR/PBR, BCD e eventual cadeia GRUB; em UEFI começa em entradas NVRAM/ESP, sem sobrepor `EFI/Microsoft`. Os caminhos são mutuamente distintos. Recusar associações firmware/tabela não ensaiadas. Não alterar chaves Secure Boot ou privilégios de arranque automaticamente.

## 4. Estrutura, identidade e autenticação da ISO
- Artefacto: `linuxmint-22.3-cinnamon-64bit.iso`.
- SHA-256 fixado: `a081ab202cfda17f6924128dbd2de8b63518ac0531bcfe3f1a1b88097c459bd4`; tamanho exacto: `3091660800` bytes. [IMPLEMENTADO — release-config.json/main; revalidar assinatura real do catálogo e hash da imagem descarregada].
- Investigar *na versão exacta* mapa ISO9660, El Torito BIOS, EFI image/BOOTX64.EFI, localização de kernel e initramfs, squashfs/stage2, ficheiros de configuração e `os-release`, manifestos e cadeia de assinatura. Registar comandos de leitura e hashes dos ficheiros internos depois de autenticar a ISO. [PENDENTE até análise de artefacto]
- Distinguir ISO Live, instaladora, netinstall e imagem especializada; não presumir layout constante nem nome dos componentes entre releases.

## 5. Sequência Windows → Linux sem USB
1. [IMPLEMENTADO — padrão Gaslux] Validar Windows, disco, firmware, encriptação, WinRE/BCD, assinatura do catálogo e posse da transacção.
2. [PENDENTE de ensaio específico] Autenticar ISO, mapear todos os ficheiros de arranque internos e provar que kernel/initramfs acedem à ISO ou ao staging no primeiro reboot. Comparar loopback GRUB, extração controlada de kernel/initramfs e cadeia EFI própria: seleccionar apenas método comprovado pela versão exacta. **Parâmetros de kernel/IDs: PENDENTE**; nunca fabricá-los.
3. [IMPLEMENTADO — arquitectura] Preparar rollback durável ANTES do primeiro shrink/EFI/BCD; publicar plano autenticado e checkpoint; preservar loader Windows.
4. [PENDENTE] Arrancar Linux Live real (SeaBIOS ou OVMF conforme gate), verificar identidade da mídia, serial/GUID/offsets, montagens read-only e handoff, antes de qualquer escritor.
5. [PENDENTE] Executar instalador nativo com target possuído, depois primeiro boot sem ISO e reentrar Windows com prova independente.
6. [BLOQUEADO] Se falta driver de FS no initramfs, ISO invisível, BootNext sem recuperação, Secure Boot incompatível, identidade divergente ou Windows encriptado sem autorização segura: abortar sem escrita.

## 6. Instalador nativo e automação
**Instalador:** instalador Ubuntu/Mint integrado na edição ISO; identificar binário e versão exacta na imagem fixada antes de declarar unattended.
**Mecanismo previsto:** Debian/Ubuntu: estudar a extracção/configuração existente e inspecionar instalador nativo da ISO; não equiparar squashfs copiada a execução do instalador.
[INVESTIGAR] Ler fontes upstream/versão binária efectiva, argumentos ou API suportados, modo unattended, ficheiros YAML/JSON/scripts declarados, mapeamento de contas/UID, locale, teclado, fuso horário, password hashing e grupos, pacote manager, formatos root/ESP e tratamento de erros. Não usar cliques por coordenadas sem estado observável: identificar janelas/elementos e pré/pós-condições; qualquer click manual não é estratégia de produção unattended. Não escrever um pseudo-instalador que só copia raiz Live.

## 7. Particionamento e protecção de Windows
[CONTRATO] Capturar disk serial, firmware, tabela e sector real; comparar GUIDs/assinatura, início/tamanho exacto em bytes e todas as partições; possuir explicitamente cada intervalo afectado. Nunca mudar ESP/EFI Windows, OEM, Recovery, WinRE, BCD, BitLocker/Device Encryption ou discos não seleccionados. MBR: validar quatro slots, primária activa, partição estendida/lógicas/EBR e endereçamento; recusar qualquer cadeia EBR sem método testado. GPT: validar primária/secundária, GUIDs, ESP, NVRAM e limite do resize. Segundo disco exige o mesmo nível de identificação e prova de boot. [BLOQUEADO quando não comprovado]

## 8. Configuração instalada e primeiro boot
Confirmar OS ID linuxmint, kernel e initramfs instalados, root UUID, utilizador, GRUB e entrada Windows. [PENDENTE — exigir evidência de comandos executados no convidado, versões e verificações independentes] Aplicar locale, teclado, timezone, password e permissões de forma transaccional; verificar também instalação real de pacotes, serviços, fstab por UUID e root montada. Sem ISO montada no boot de aceitação.

## 9. Bootloader, kernel e manutenção
GRUB BIOS ou GRUB EFI com shim assinado onde o firmware/ISO o suportem. Manter Windows Boot Manager intacto, cópias EFI/boot code apenas onde a transacção detenha posse, e entradas Windows válidas. Revalidar entradas e hashes antes/depois da instalação e de cada update de kernel/loader. Hooks APT/dpkg de Mint/Zorin não são transferíveis sem adaptação a pacman, distinst ou Atomic. [PENDENTE — prova por distro]

## 10. Actualizações e desinstalação
Testar upgrade de pacotes, regeneração de initramfs, kernel novo, loader novo, reboot Linux, reboot Windows e operação de remoção. Backup imutável de EFI/BCD/MBR/NVRAM e ownership por transacção; a desinstalação não pode apagar um artefacto partilhado/unowned. Reinicializar a verificação Windows/WinRE após remoção. [PENDENTE — não inferir de update numa raiz Linux isolada]

## 11. Recuperação e rollback
Antes da mutação: baseline geométrico/WinRE/BCD/ESP ou MBR, encriptação, estado boot, hashes, snapshot de VM e recovery runtime. Em cada fase: checkpoint durável; em falha, compensação inversa apenas sobre recursos possuídos, revalidar disco e sector, recuperar arranque e medir o Windows após reinício verdadeiro. Queda de energia e falha parcial EFI/rede são testes obrigatórios. Sem arranque Windows e comparações de integridade não existe rollback COMPROVADO. [BLOQUEADO para hardware real]

## 12. Código Gaslux reutilizável
[IMPLEMENTADO — caminhos confirmados pela documentação do projecto; conferir conteúdo/ref de cada um] `Installation/` (plano/ledger), `Scripts/modules/` (PowerShell, storage/rollback), `Scripts/uefi/`, `assets/live/` (verificação/handoff/first boot), `schemas/`, `iso-tools/`, `Libertix.Tests/`, `PowerShell.Tests/`, `auto_tests/`. Preservar o fluxo Mint/Zorin e separar módulos específicos da família Linux.

## 13. PRs, branches e commits a reutilizar
#167, #174, #181, #197, #204, #233. Resolver IDs, HEADs, base empilhada e diffs efectivos no momento da implementação; não aplicar commits de PR antigos cegamente. A PR #7 foi integrada em `dev`; `main` não contém necessariamente o mesmo `AGENTS.md`. Reaproveitar somente partes cujo comportamento foi confirmado e não duplicar guardas.

## 14. Problemas conhecidos e causas
Live QEMU e raiz Linux em imagem isolada não provam instalação automática Gaslux nem rollback Windows. Problemas gerais: parâmetros de initramfs desconhecidos, Windows ISO/UEFI prompt, discos que mudam de ordem, entrada NVRAM que não persiste, partição estendida difícil de compensar, confiança Secure Boot incompleta, instaladores que reformatam ESP/Windows por defeito. A causa exacta de uma falha é PENDENTE até log + reprodução + commit.

## 15. Soluções tecnicamente verificadas vs. hipóteses
[IMPLEMENTADO] Existem protecções de plano, state ledger, catálogo assinado e caminhos firmware Gaslux (ver ARCHITECTURE). [PENDENTE] A adaptação ao instalador Linux Mint e estratégia USB-free do artefacto exacto não estão comprovadas nesta investigação. Não confundir existência de scripts com execução de instalação nativa.

## 16. Matriz de compatibilidade
| Ambiente | Compatibilidade no Gaslux | Gate |
|---|---|---|
| Windows 10 BIOS/MBR | IMPLEMENTADO infraestrutura; COMPROVAÇÃO fim-a-fim pendente | slots/EBR/sector real/MBR/PBR/BCD |
| Windows 10 UEFI/GPT | IMPLEMENTADO infraestrutura; provas independentes pendentes | ESP/NVRAM/BCD/WinRE/Windows boot |
| Windows 11 UEFI/GPT | IMPLEMENTADO infraestrutura; provas independentes pendentes | TPM/BitLocker/ESP/WinRE/Secure Boot |
| Segundo disco | PENDENTE | serial real e BootOrder independente |
| Secure Boot | PENDENTE conforme versão e chaves de firmware | prova de loader instalado, sem enrollment manual |
| BIOS/GPT ou UEFI/MBR | BLOQUEADO sem teste explícito | nunca converter automaticamente |

## 17. Testes existentes e evidências
- [Actions histórica](https://github.com/LMhdez/gaslux/actions/runs/44147851503): **COMPROVADO somente para as verificações que o job e os artefactos realmente contêm**, e sujeito a revalidação do HEAD actual.
- [ISSUE #3](https://github.com/LMhdez/gaslux/issues/3) indica gates não resolvidos; PRs citadas acima oferecem trabalho experimental, não prova universal.
- [PENDENTE] Associar manifesto de artefactos, digest, SHA exacto do workflow e nível de evidência (fixtures vs Live vs instalado vs dual boot vs rollback).

## 18. Testes adicionais obrigatórios
Lint/documentação e contratos C#/Pester/Python/Bash; autenticação ISO offline; VM descartável com ISO real; primeiro boot sem ISO; Windows 10 BIOS/MBR onde elegível, Windows 10 e 11 UEFI/GPT; disco único/segundo disco, partições complexas, Secure Boot admissível; update/reboot de kernel e loader; reinstall/uninstall; falhas de hash, disco permutado, ISO truncada, rede ausente, SIGKILL/power-cut e recovery BCD/WinRE. Escritas somente em VM autorizada, sem discos host. [PENDENTE]

## 19. Plano incremental de implementação
(1) Confirmar HEAD e upstream/media fixada; (2) automatizar inspecção read-only + hashes; (3) testes negativos dos gates; (4) validar handoff em Live; (5) autorizar escritor apenas sobre VM com snapshot e identidade comprovada; (6) executar instalador real; (7) provar primeiro boot sem ISO; (8) dual boot Windows; (9) update e reboot; (10) rollback completo; (11) revisão humana. Cada etapa deve deixar evidência ligada a commit, run, artefactos e manifestos; nunca continuar numa falha.

## 20. Critério objectivo de estabilidade
Não basta existir ISO/hash válido, CI verde, Live boot ou raiz extraída. Requer ISO oficial autenticada, instalação nativa de Linux Mint numa VM descartável Windows realmente instalado, boot Linux e Windows independentes, kernel/bootloader actualizados, Windows WinRE/BCD/ESP preservados, uninstall e rollback completos, incluindo injecção de falhas e testes negativos dos layouts suportados. Hardware só depois de backup/restauro sob autorização explícita.

---

## Anexo técnico — descoberta de instalador, assinatura e boot real (19-11-2026)

### Identidade e origem exacta
[DOCUMENTADO] A distribuição fixada em `main/release-config.json` é **Linux Mint 22.3 Cinnamon**, ISO de 3 091 660 800 bytes, SHA-256 `a081ab202cfda17f6924128dbd2de8b63518ac0531bcfe3f1a1b88097c459bd4`. O [guia oficial de autenticação](https://linuxmint-installation-guide.readthedocs.io/en/latest/verify.html) requer `sha256sum.txt` e a assinatura `sha256sum.txt.gpg`, emitida pela chave cujo fingerprint é `27DEB15644C6B3CF3BD7D291300F846BA25BAE09`. A assinatura do catálogo Gaslux é **independente** da assinatura dos hashes Linux Mint: exigir ambas quando o trust model reclamar proveniência upstream. [PENDENTE] Guardar o resultado da verificação GPG exacta para a ISO 22.3 juntamente com versão/fingerprint e data da consulta.

### Instalador upstream vs. backend Gaslux
[DOCUMENTADO em código upstream] O projecto [linuxmint/ubiquity](https://github.com/linuxmint/ubiquity) é um instalador mantido pela Linux Mint. [PENDENTE] Determinar o **pacote, versão e binário realmente incluídos** na ISO Cinnamon 22.3; não deduzir isso apenas pela existência do repositório. [IMPLEMENTADO em `dev`] O Gaslux **não chama necessariamente o Ubiquity**: [`assets/live/libertix-distribution-common.sh`](https://github.com/LMhdez/gaslux/blob/dev/assets/live/libertix-distribution-common.sh) resolve exactamente um `filesystem.squashfs`, exige `/etc/os-release`, `var/lib/dpkg/status`, `usr/sbin/update-grub`, `usr/sbin/update-initramfs` e `usr/bin/lsinitramfs`. [`assets/live/libertix-install-main.sh`](https://github.com/LMhdez/gaslux/blob/dev/assets/live/libertix-install-main.sh) orquestra o target, não sendo sinónimo de execução do instalador upstream. Não reescrever este backend sem prova de falha, mas distinguir instalação configurada pelo Gaslux de instalação feita pelo Ubiquity.

### Arranque, parâmetros e testes reproduzíveis
[IMPLEMENTADO] A mini-ISO Libertix usa os parâmetros **da própria mini-ISO**, não necessariamente da ISO Mint: [`Scripts/config/Libertix.BootArguments.json`](https://github.com/LMhdez/gaslux/blob/dev/Scripts/config/Libertix.BootArguments.json) contém `boot=live toram components ... console=ttyS0,115200n8`; `Installation/LiveBootArguments.cs` escolhe `/live/vmlinuz` e `/live/initrd.img` para GRUB4DOS BIOS e usa `find --set-root /installation-plan.json`. Não copiar `boot=live` para arranque directo da ISO Mint sem ensaio: Mint tem `casper` e argumentos próprios por versão. [PENDENTE] Extrair configuração GRUB/isolinux da ISO exacta e provar discovery da mídia no initramfs.

[COMPROVADO com limites] [Run #44147851503](https://github.com/LMhdez/gaslux/actions/runs/44147851503) cobre Mint 22.3 Live e login série em OVMF. [Run #44572398014](https://github.com/LMhdez/gaslux/actions/runs/44572398014) confirmou preparação Windows 10 genuíno, GPT/quinta ext4 em overlay, mas o job real **FAILED**: `MintOverlayError: Mint guest did not emit a systemd/kernel orderly-shutdown witness`. [PR #233](https://github.com/LMhdez/gaslux/pull/233), HEAD `0f3613a67e542ab630ba933e0f96c12325367199`, propõe novas testemunhas; o erro de encerramento não se pode ignorar nem converter em sucesso. O relatório da própria PR indica `nativeGrubDualBootVerified=false`, `updatesVerified=false` e `rollbackVerified=false`.

**Próxima execução one-shot:** (1) confirmar se `PR #233` já foi consolidada, (2) verificar testemunho no log série íntegro, (3) provar Windows após staging Mint em **COW**, (4) executar especificamente o fluxo `libertix-install-main.sh` na VM segura, (5) comparar com instalação Ubiquity do upstream sem confundir os dois métodos, (6) só então estudar updates e rollback. Parar se a identidade da quinta GPT ou o shutdown witness falhar.


---

## ONE-SHOT EXECUTION PLAYBOOK
**Pré-requisitos exactos:** acesso GitHub conta LMHDEZ, HEAD `dev` confirmado, `AI_POLICY.md`, `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/distro-backends/SHARED_CONTRACTS.md`, mídia oficial e digest/assinatura validados; runner VM descartável com QEMU/SeaBIOS/OVMF conforme firmware e snapshot recuperável. Sem estes elementos, STOP.

**Branch recomendada:** `feature/mint-native-backend-verified` a partir do HEAD revisto de `dev`, evitando branches empilhadas obsoletas. **PRs candidatas:** #167, #174, #181, #197, #204, #233. Verificar SHA/head/diff antes do cherry-pick.

**Ficheiros a inspeccionar e possivelmente alterar apenas numa futura PR funcional:** `Installation/`, `Scripts/modules/`, `Scripts/uefi/`, `assets/live/`, `schemas/`, adaptadores de distro e testes. **Não alterar sem gates:** `release-config.json` estável, `EFI/Microsoft`, boot Windows, partições alheias, assinaturas/catálogo e contratos Mint/Zorin.

**Interfaces obrigatórias:** preflight tipado → catálogo assinado/ISO validada → plano e ledger duráveis → handoff autenticado → provisioning de target possuído → instalador nativo → bootloader da distribuição → first-boot evidence → verificação Windows → manutenção/uninstall/rollback.

**Execução faseada e testes:** primeiro `ruff check`, `pytest`, `dotnet test`, Pester e ShellCheck conforme workflows existentes e HEAD; verificar nomes e argumentos reais dos workflows antes de executar. Seguidamente lançar apenas workflow explicitamente autorizado com VM descartável, snapshot e hash. Sucesso de cada fase exige relatório de identidade, logs independentes e hashes; nunca métricas auto-reportadas. A lista de workflows experimentais nas PRs #167, #174, #181, #197, #204, #233 é *candidata*, não comando autorizado.

**Falhas previsíveis/correcções:** assinatura errada → descartar a imagem; root ISO não visível → corrigir initramfs/handoff antes de escrever; UUID errado → bloquear; ausência de slot MBR → bloquear, não mexer em EBR; instalador tenta reformatar ESP/Windows → bloquear; bootloader incompleto → restaurar só ficheiros possuídos e confirmar Windows; update altera entrada Windows → reverter com checkpoint e negar sucesso.

**Interrupção obrigatória:** qualquer geometria, hash, conta, firma/assinatura, Secure Boot, propriedade, WinRE/BCD ou estado de recuperação não comprovado; Windows sem boot validado; tentativa de usar disco físico; parâmetros, caminhos de ISO ou opções unattended desconhecidos.

**Provas de conclusão:** SHA commit, PR, workflow/run, artefactos e respectivos SHA-256, cadeia de assinatura upstream, serial/GUID/offsets, pré/pós Windows BCD/WinRE/EFI/MBR, arranques Linux e Windows pós-instalação e pós-update, remoção, rollback e relatório independente. **Nunca declarar estável sem a matriz completa.**

## Auditoria de fronteiras de manutenção, atualização e remoção — 22-11-2026 (read-only)

**Base observada:** `dev` em `8e68a475d6397ba8fef2e0f9f83758545e202a5f`, `main` em `b07e88fd42488591bf7a18c9a45094751e79434e`. Os scripts de sincronização EFI, fallback, rollback UEFI e UI de remoção examinados têm blobs iguais nos dois ramos; `configure-target-main.sh` e `libertix-install-main.sh` divergem. A PR de inventário read-only foi criada a partir de `dev`, sem sobrepor #336, #350 ou o Integrador 1.

**Fontes reais e write-set identificado:**

| Cenário | Chamadas encontradas | Potenciais destinos | Limite da prova |
| --- | --- | --- | --- |
| Instalação BIOS/MBR | `libertix-install-main.sh`: `grub-install --target=i386-pc --recheck "$WINDOWS_DISK"` | boot code MBR do disco validado; Windows ativo/BCD tratado pelo fluxo de recovery | Existe o código; não equivale a boot Windows pós-instalação nem demonstra ausência de PBR/MBR writes por hooks externos |
| Instalação UEFI/GPT | `libertix-uefi-adapter.sh` e signed EFI GRUB | `EFI/Libertix`, `Boot####`, `BootOrder`, `BootNext`; limpeza temporária | Estado das variáveis e origens dos loaders exigem prova por execução, firmware e ESP |
| Update de kernel e GRUB | `configure-target-main.sh`: `update-initramfs -u -k all`, `dpkg-divert`, `DPkg::Post-Invoke`; `libertix-update-grub.sh`: `grub-mkconfig`, validador, rename atómico | Linux `/boot`, `/etc`, `/boot/grub/grub.cfg` | Existem testes de falha/atomicidade; não há prova completa dos scripts `postinst` dos pacotes efetivos, nem reboot Mint→Windows pós-update |
| Sincronização UEFI | `libertix-sync-efi.sh` e watcher systemd `libertix-efi-sync.path` | `EFI/Libertix/{shimx64.efi,grubx64.efi,mmx64.efi,secure-boot-chain.json}` e histórico local | O marcador `.libertix-owner` sozinho não autentica toda a geometria, cada ficheiro e a cadeia temporal dos writers |
| Fallback UEFI excepcional | `libertix-preferred-boot-path.py` faz `publish_synchronization` e `replace_atomic` | **`EFI/Microsoft/Boot/{bootmgfw.efi,bootmgfw.libertix-windows.efi,grubx64.efi,mmx64.efi,grub.cfg}`**; `EFI/Libertix/BootGuardianReference` | Não classificar esta manutenção como isolada de Windows. O helper possui journal/read-back, mas o seu resultado não é prova de recuperação Windows |
| Desinstalação | `Pages/UninstallLinux.xaml.cs` chama recovery `-VerifiedUninstall`; `Libertix.Uefi.Transaction.ps1`, `Libertix.Uefi.Firmware.ps1` e adaptadores Linux restauram/retiram artefactos | Partição Linux, eventual reexpansão NTFS, ESP, BCD, `Boot####`, `BootOrder/BootNext`, MBR/PBR em BIOS e fallback Windows excepcional | Existem verificações de transação e rollback, mas `libertix-uefi-adapter.sh` ainda contém `rm -rf` sobre `EFI/Libertix*` após verificação do marcador. Não executar nem presumir ownership de cada filho sem revisão independente |

**Lacuna concreta:** não existia um inventário read-only conjunto, dependente da versão exata de código, que assinalasse a fronteira entre operações pertencentes ao Linux, a ESP partilhada, o fallback Microsoft e a desinstalação. A nova implementação `auto_tests/tools/mint_boot_update_remove_writeset.py` fixa os blobs Git *da fonte local* auditada, expõe operações potenciais por firmware/cenário, e inspeciona paths EFI numa fixture sem seguir symlinks ou hardlinks. A fonte Git não constitui assinatura do editor; a inspeção da árvore não comprova montagem de ESP real, GUID, BootOrder, ownership transacional completo, Windows boot, ausência de outros writers ou TOCTOU contra concorrentes same-UID. **Nunca concede autoridade de escrita**: `productionWriteAuthorized=false`, `bootUpdateVerified=false`, `windowsInPlaceRollbackProven=false`, `stable=false`.

**Evidência inicial publicada:** [PR #360](https://github.com/LMhdez/gaslux/pull/360) (draft contra `dev`) e [Actions #45038173819](https://github.com/LMhdez/gaslux/actions/runs/45038173819) (SUCCESS no HEAD `75d5d2b61c04e320ea2add95615304b2ddee1075`). É uma validação offline de 13 casos novos e regressões Mint/Zorin; não prova upgrades ou desinstalações reais.

**Critério para avançar:** auditar write-set real de hooks `dpkg`/kernel/GRUB da imagem Mint 22.3 autenticada, incluindo escritas fora de `EFI/Libertix` e riscos em `EFI/BOOT`; depois verificar, em VMs descartáveis com imagens/snapshots e orçamento próprios, boot de Mint e Windows antes/depois das atualizações e a remoção Windows com validação MBR/ESP/BCD/WinRE e recuperação efetiva. Não inferir estabilidade de contratos offline nem de testes Zorin com scripts partilhados.
