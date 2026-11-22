# CachyOS — ONE-SHOT backend dossier

> **Atualização de navegação (22-11-2026):** este dossier mantém a análise histórica de 19-11. Revalidar HEADs, PRs/merges, media e artefactos antes de usar as propostas. Ver [histórico e instruções por agente](../AGENT_HISTORICAL_PLAYBOOK.md), [índice GitHub Actions/VM](../CI_VM_EVIDENCE_INDEX.md) e [contratos partilhados](SHARED_CONTRACTS.md). Propostas antigas de criação de branch/PR não substituem a regra atual de reutilização e consolidação; testes QEMU descartáveis têm autorização delimitada em [AGENTS](../../AGENTS.md).

**Revisão:** 2026-11-19. **Maturidade:** EXPERIMENTAL / PENDENTE: não autorizado para catálogo estável. Ver [contratos gerais](SHARED_CONTRACTS.md). **Não usar este documento como autorização de escrita.**

## 1. Resumo executivo e estado
Rootfs Live Archiso não é target instalado; CI de GPT/ext4/Windows não demonstra pacstrap ou Linux instalado. O objectivo é uma instalação nativa automatizada ao lado do Windows, com prova independente dos dois boots e recuperação. Compatibilidade upstream não equivale a suporte validado no Gaslux.

## 2. Fontes oficiais, versões e proveniência
- [Origem oficial/media](https://cachyos.org/download/) — versão/release: **nenhuma versão no catálogo estável**. [DOCUMENTADO como endereço de referência; revalidar disponibilidade, conteúdo e assinatura na data da execução.]
- [Documentação upstream](https://wiki.cachyos.org/installation/installation_on_root/) — instruções gerais, não aprovação de boot sem USB. [DOCUMENTADO; verificar versão, data e parâmetros antes de automatizar.]
- [Configuração Gaslux main](https://github.com/LMhdez/gaslux/blob/main/release-config.json) — não contém esta distribuição. [IMPLEMENTADO]
- [Arquitectura Gaslux](https://github.com/LMhdez/gaslux/blob/dev/docs/ARCHITECTURE.md), [issue de aceitação CachyOS #3](https://github.com/LMhdez/gaslux/issues/3) e [Windows 11 #71](https://github.com/LMhdez/gaslux/issues/71) e [PR multidistro #7](https://github.com/LMhdez/gaslux/pull/7). [IMPLEMENTADO/critério documental]
- PRs/threads experimentais relacionadas: [#1](https://github.com/LMhdez/gaslux/pull/1), [#2](https://github.com/LMhdez/gaslux/pull/2), [#3 (issue)](https://github.com/LMhdez/gaslux/issues/3), [#34](https://github.com/LMhdez/gaslux/pull/34), [#159](https://github.com/LMhdez/gaslux/pull/159), [#160](https://github.com/LMhdez/gaslux/pull/160), [#162](https://github.com/LMhdez/gaslux/pull/162). **Consultar HEAD, estado de merge, logs e branches antes de reutilizar.**
- Evidência histórica de CI para contexto: [Actions](https://github.com/LMhdez/gaslux/actions/runs/44125124789); a existência ou êxito do workflow não certifica todas as etapas. [PENDENTE: rever job e artefactos exactos.]

## 3. Arquitectura de arranque
**Estratégia:** GRUB Arch próprio/EFI e BIOS conforme implementação efectivamente verificada; não reutilizar dpkg/shim Debian. **Modo:** BIOS/MBR e UEFI/GPT a investigar/testar; nenhuma combinação declarada estável no Gaslux.
[DOCUMENTADO/pendente por mídia] Em BIOS o arranque envolve MBR/PBR, BCD e eventual cadeia GRUB; em UEFI começa em entradas NVRAM/ESP, sem sobrepor `EFI/Microsoft`. Os caminhos são mutuamente distintos. Recusar associações firmware/tabela não ensaiadas. Não alterar chaves Secure Boot ou privilégios de arranque automaticamente.

## 4. Estrutura, identidade e autenticação da ISO
- Artefacto: `não fixada em release-config.json`.
- SHA-256 fixado: `PENDENTE`; tamanho exacto: `PENDENTE` bytes. [PENDENTE — não inventar valor nem usar versão móvel].
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
**Instalador:** Archiso real, pacstrap/pacman como estratégia proposta na issue #3; eventual Calamares da ISO oficial exige auditoria separada.
**Mecanismo previsto:** Autenticar handoff da mini-ISO Debian para Archiso original; verificar kernel/initramfs, pacstrap/pacman, mirror e pacotes antes de criar target; recusar Secure Boot não suportado.
[INVESTIGAR] Ler fontes upstream/versão binária efectiva, argumentos ou API suportados, modo unattended, ficheiros YAML/JSON/scripts declarados, mapeamento de contas/UID, locale, teclado, fuso horário, password hashing e grupos, pacote manager, formatos root/ESP e tratamento de erros. Não usar cliques por coordenadas sem estado observável: identificar janelas/elementos e pré/pós-condições; qualquer click manual não é estratégia de produção unattended. Não escrever um pseudo-instalador que só copia raiz Live.

## 7. Particionamento e protecção de Windows
[CONTRATO] Capturar disk serial, firmware, tabela e sector real; comparar GUIDs/assinatura, início/tamanho exacto em bytes e todas as partições; possuir explicitamente cada intervalo afectado. Nunca mudar ESP/EFI Windows, OEM, Recovery, WinRE, BCD, BitLocker/Device Encryption ou discos não seleccionados. MBR: validar quatro slots, primária activa, partição estendida/lógicas/EBR e endereçamento; recusar qualquer cadeia EBR sem método testado. GPT: validar primária/secundária, GUIDs, ESP, NVRAM e limite do resize. Segundo disco exige o mesmo nível de identificação e prova de boot. [BLOQUEADO quando não comprovado]

## 8. Configuração instalada e primeiro boot
Verificar vmlinuz-linux-cachyos, initramfs, pacman DB, mounts, kernel, network, entrada Windows e boot após update. [PENDENTE — exigir evidência de comandos executados no convidado, versões e verificações independentes] Aplicar locale, teclado, timezone, password e permissões de forma transaccional; verificar também instalação real de pacotes, serviços, fstab por UUID e root montada. Sem ISO montada no boot de aceitação.

## 9. Bootloader, kernel e manutenção
GRUB Arch próprio/EFI e BIOS conforme implementação efectivamente verificada; não reutilizar dpkg/shim Debian. Manter Windows Boot Manager intacto, cópias EFI/boot code apenas onde a transacção detenha posse, e entradas Windows válidas. Revalidar entradas e hashes antes/depois da instalação e de cada update de kernel/loader. Hooks APT/dpkg de Mint/Zorin não são transferíveis sem adaptação a pacman, distinst ou Atomic. [PENDENTE — prova por distro]

## 10. Actualizações e desinstalação
Testar upgrade de pacotes, regeneração de initramfs, kernel novo, loader novo, reboot Linux, reboot Windows e operação de remoção. Backup imutável de EFI/BCD/MBR/NVRAM e ownership por transacção; a desinstalação não pode apagar um artefacto partilhado/unowned. Reinicializar a verificação Windows/WinRE após remoção. [PENDENTE — não inferir de update numa raiz Linux isolada]

## 11. Recuperação e rollback
Antes da mutação: baseline geométrico/WinRE/BCD/ESP ou MBR, encriptação, estado boot, hashes, snapshot de VM e recovery runtime. Em cada fase: checkpoint durável; em falha, compensação inversa apenas sobre recursos possuídos, revalidar disco e sector, recuperar arranque e medir o Windows após reinício verdadeiro. Queda de energia e falha parcial EFI/rede são testes obrigatórios. Sem arranque Windows e comparações de integridade não existe rollback COMPROVADO. [BLOQUEADO para hardware real]

## 12. Código Gaslux reutilizável
[IMPLEMENTADO — caminhos confirmados pela documentação do projecto; conferir conteúdo/ref de cada um] `Installation/` (plano/ledger), `Scripts/modules/` (PowerShell, storage/rollback), `Scripts/uefi/`, `assets/live/` (verificação/handoff/first boot), `schemas/`, `iso-tools/`, `Libertix.Tests/`, `PowerShell.Tests/`, `auto_tests/`. Preservar o fluxo Mint/Zorin e separar módulos específicos da família Linux.

## 13. PRs, branches e commits a reutilizar
#1, #2, #3 (issue), #34, #159, #160, #162. Resolver IDs, HEADs, base empilhada e diffs efectivos no momento da implementação; não aplicar commits de PR antigos cegamente. A PR #7 foi integrada em `dev`; `main` não contém necessariamente o mesmo `AGENTS.md`. Reaproveitar somente partes cujo comportamento foi confirmado e não duplicar guardas.

## 14. Problemas conhecidos e causas
Rootfs Live Archiso não é target instalado; CI de GPT/ext4/Windows não demonstra pacstrap ou Linux instalado. Problemas gerais: parâmetros de initramfs desconhecidos, Windows ISO/UEFI prompt, discos que mudam de ordem, entrada NVRAM que não persiste, partição estendida difícil de compensar, confiança Secure Boot incompleta, instaladores que reformatam ESP/Windows por defeito. A causa exacta de uma falha é PENDENTE até log + reprodução + commit.

## 15. Soluções tecnicamente verificadas vs. hipóteses
[IMPLEMENTADO] Existem protecções de plano, state ledger, catálogo assinado e caminhos firmware Gaslux (ver ARCHITECTURE). [PENDENTE] A adaptação ao instalador CachyOS e estratégia USB-free do artefacto exacto não estão comprovadas nesta investigação. Não confundir existência de scripts com execução de instalação nativa.

## 16. Matriz de compatibilidade
| Ambiente | Compatibilidade no Gaslux | Gate |
|---|---|---|
| Windows 10 BIOS/MBR | PENDENTE | slots/EBR/sector real/MBR/PBR/BCD |
| Windows 10 UEFI/GPT | PENDENTE | ESP/NVRAM/BCD/WinRE/Windows boot |
| Windows 11 UEFI/GPT | PENDENTE | TPM/BitLocker/ESP/WinRE/Secure Boot |
| Segundo disco | PENDENTE | serial real e BootOrder independente |
| Secure Boot | BLOQUEADO até cadeia validada | prova de loader instalado, sem enrollment manual |
| BIOS/GPT ou UEFI/MBR | BLOQUEADO sem teste explícito | nunca converter automaticamente |

## 17. Testes existentes e evidências
- [Actions histórica](https://github.com/LMhdez/gaslux/actions/runs/44125124789): **COMPROVADO somente para as verificações que o job e os artefactos realmente contêm**, e sujeito a revalidação do HEAD actual.
- [ISSUE #3](https://github.com/LMhdez/gaslux/issues/3) indica gates não resolvidos; PRs citadas acima oferecem trabalho experimental, não prova universal.
- [PENDENTE] Associar manifesto de artefactos, digest, SHA exacto do workflow e nível de evidência (fixtures vs Live vs instalado vs dual boot vs rollback).

## 18. Testes adicionais obrigatórios
Lint/documentação e contratos C#/Pester/Python/Bash; autenticação ISO offline; VM descartável com ISO real; primeiro boot sem ISO; Windows 10 BIOS/MBR onde elegível, Windows 10 e 11 UEFI/GPT; disco único/segundo disco, partições complexas, Secure Boot admissível; update/reboot de kernel e loader; reinstall/uninstall; falhas de hash, disco permutado, ISO truncada, rede ausente, SIGKILL/power-cut e recovery BCD/WinRE. Escritas somente em VM autorizada, sem discos host. [PENDENTE]

## 19. Plano incremental de implementação
(1) Confirmar HEAD e upstream/media fixada; (2) automatizar inspecção read-only + hashes; (3) testes negativos dos gates; (4) validar handoff em Live; (5) autorizar escritor apenas sobre VM com snapshot e identidade comprovada; (6) executar instalador real; (7) provar primeiro boot sem ISO; (8) dual boot Windows; (9) update e reboot; (10) rollback completo; (11) revisão humana. Cada etapa deve deixar evidência ligada a commit, run, artefactos e manifestos; nunca continuar numa falha.

## 20. Critério objectivo de estabilidade
Não basta existir ISO/hash válido, CI verde, Live boot ou raiz extraída. Requer ISO oficial autenticada, instalação nativa de CachyOS numa VM descartável Windows realmente instalado, boot Linux e Windows independentes, kernel/bootloader actualizados, Windows WinRE/BCD/ESP preservados, uninstall e rollback completos, incluindo injecção de falhas e testes negativos dos layouts suportados. Hardware só depois de backup/restauro sob autorização explícita.

---

## Anexo técnico — Archiso 260809, Calamares e pacstrap partilhado (19-11-2026)

### Instalador concreto e alternativa
[DOCUMENTADO upstream] [`CachyOS/cachyos-calamares/settings.conf`](https://github.com/CachyOS/cachyos-calamares/blob/cachyos/settings.conf) define os ecrãs `welcome → locale → keyboard → partition → packagechooser → netinstall → users → summary` e a execução `partition → mount → initialize_pacman → pacstrap → ... → fstab → initcpio → users → bootloader → services-systemd → umount`. A variante `settings_online.conf` inclui escolha explícita de bootloader e desktop. Isto confirma que a distribuição usa **Calamares com módulo pacstrap**, não uma cópia genérica da raiz Live. [PENDENTE] fixar commit e versão exactos do Calamares/Archiso **dentro da ISO 260809**; os ficheiros upstream podem mudar.

[IMPLEMENTADO apenas em branches] A [PR #248](https://github.com/LMhdez/gaslux/pull/248), HEAD `c5b3246dc8df9873015291dbb64a3c0ddecc8613`, acrescenta o hash `installedConfiguratorSha256` ao grant Ed25519 para `cachyos_configure_installed.py`, que já era copiado para o guest. O erro anterior `guest program manifest is incomplete or has unexpected entries` foi uma recusa correcta antes de pacstrap, causada pela allow-list do programa incompleta. Reutilizar `auto_tests/tools/cachyos_windows_shared_root_pacstrap_host.py`, `cachyos_windows_shared_cow_grant.py`, `gaslux-cachyos-shared-root-install.sh`, `cachyos_configure_installed.py`, verificados na branch da PR. A chave de laboratório **não** estabelece uma autoridade de assinatura Windows de produção.

### Mídia e ensaios realmente concluídos
[COMPROVADO em CI, não catálogo] CachyOS Archiso ISO **260809**, SHA-256 `959f6577f45e25ee9fd8c220fd221b08e4ea79412c7315c0f922dd6d86d5e33c`, verificado nos [logs #44563479551](https://github.com/LMhdez/gaslux/actions/runs/44563479551), PR #42 HEAD `9726bc74416ea235a5957a1f7d95f35807f679c3`. Em QCOW2 **só-Linux**, a execução arrancou Archiso oficial, completou pacstrap, GRUB EFI e boot autónomo do kernel LTS; aplicou update pacman em child COW, reiniciou Linux e provou recuperação da baseline por descarte de overlay. [Artefacto #14554036041](https://github.com/LMhdez/gaslux/actions/runs/44563479551/artifacts/14554036041). Não há Windows neste teste.

[COMPROVADO com âmbito separado] [Run #44571015093](https://github.com/LMhdez/gaslux/actions/runs/44571015093), job `real-windows10-archiso-pacstrap-and-discard`, **SUCCESS**, [artefacto #14556716731](https://github.com/LMhdez/gaslux/actions/runs/44571015093/artifacts/14556716731): Windows 10 genuíno em QCOW2, quinta ext4 possuída, `pacstrap` real e arranque mínimo read-only do kernel/systemd instalado, verificação de backing/ESP/BCD/WinRE e descarte do COW com Windows baseline novamente arrancado. Os logs declaram explicitamente: **não comprovados** bootloader nativo no disco Windows, primeiro boot completo, menu de dual boot, actualizações partilhadas e rollback in-place. Recuperar por descarte de COW não equivale a desfazer alterações in-place num sistema real.

### One-shot: sequência segura específica
1. Obter ISO imutável exacta e validar assinatura/proveniência upstream além do SHA local; descobrir Archiso `archisobasedir`, kernel/initramfs e mecanismo de montagem **directamente na ISO**. Não inventar `archisolabel` ou flags.
2. Reutilizar `gaslux_candidate_handoff.py` para diagnóstico e o grant Ed25519 experimental da PR #248 após auditar autoridade/nonce/expiração e binding ao plano. Bloquear Secure Boot se não existir bootchain validado.
3. Revalidar convidado: número 5/GUID/offsets ext4, Windows partições #1–#4, serial exacto do disco, COW exclusivo, estado Windows/EFI/BCD/WinRE, checkpoint de rollback. Se qualquer campo divergir, abortar.
4. Executar pacstrap com pacman/mirrors **só na quinta ext4**; aplicar configurador autenticado e testar identidade de kernel/root/conta/mounts. Sem `/dev/sda` presumido.
5. Acrescentar bootloader GRUB Arch-owned sem escrita sobre Windows EFI/BCD; boot autónomo Linux e Windows a partir do mesmo COW; update pacman + reboot de ambos; rollback in-place e compensação contra falhas. **Só após etapa 5** rever gates da [issue #3](https://github.com/LMhdez/gaslux/issues/3).


---

## ONE-SHOT EXECUTION PLAYBOOK
**Pré-requisitos exactos:** acesso GitHub conta LMHDEZ, HEAD `dev` confirmado, `AI_POLICY.md`, `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/distro-backends/SHARED_CONTRACTS.md`, mídia oficial e digest/assinatura validados; runner VM descartável com QEMU/SeaBIOS/OVMF conforme firmware e snapshot recuperável. Sem estes elementos, STOP.

**Branch recomendada:** `feature/cachyos-native-backend-verified` a partir do HEAD revisto de `dev`, evitando branches empilhadas obsoletas. **PRs candidatas:** #1, #2, #3 (issue), #34, #159, #160, #162. Verificar SHA/head/diff antes do cherry-pick.

**Ficheiros a inspeccionar e possivelmente alterar apenas numa futura PR funcional:** `Installation/`, `Scripts/modules/`, `Scripts/uefi/`, `assets/live/`, `schemas/`, adaptadores de distro e testes. **Não alterar sem gates:** `release-config.json` estável, `EFI/Microsoft`, boot Windows, partições alheias, assinaturas/catálogo e contratos Mint/Zorin.

**Interfaces obrigatórias:** preflight tipado → catálogo assinado/ISO validada → plano e ledger duráveis → handoff autenticado → provisioning de target possuído → instalador nativo → bootloader da distribuição → first-boot evidence → verificação Windows → manutenção/uninstall/rollback.

**Execução faseada e testes:** primeiro `ruff check`, `pytest`, `dotnet test`, Pester e ShellCheck conforme workflows existentes e HEAD; verificar nomes e argumentos reais dos workflows antes de executar. Seguidamente lançar apenas workflow explicitamente autorizado com VM descartável, snapshot e hash. Sucesso de cada fase exige relatório de identidade, logs independentes e hashes; nunca métricas auto-reportadas. A lista de workflows experimentais nas PRs #1, #2, #3 (issue), #34, #159, #160, #162 é *candidata*, não comando autorizado.

**Falhas previsíveis/correcções:** assinatura errada → descartar a imagem; root ISO não visível → corrigir initramfs/handoff antes de escrever; UUID errado → bloquear; ausência de slot MBR → bloquear, não mexer em EBR; instalador tenta reformatar ESP/Windows → bloquear; bootloader incompleto → restaurar só ficheiros possuídos e confirmar Windows; update altera entrada Windows → reverter com checkpoint e negar sucesso.

**Interrupção obrigatória:** qualquer geometria, hash, conta, firma/assinatura, Secure Boot, propriedade, WinRE/BCD ou estado de recuperação não comprovado; Windows sem boot validado; tentativa de usar disco físico; parâmetros, caminhos de ISO ou opções unattended desconhecidos.

**Provas de conclusão:** SHA commit, PR, workflow/run, artefactos e respectivos SHA-256, cadeia de assinatura upstream, serial/GUID/offsets, pré/pós Windows BCD/WinRE/EFI/MBR, arranques Linux e Windows pós-instalação e pós-update, remoção, rollback e relatório independente. **Nunca declarar estável sem a matriz completa.**
