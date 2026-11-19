# Pop!_OS — ONE-SHOT backend dossier

**Revisão:** 2026-11-19. **Maturidade:** EXPERIMENTAL / PENDENTE: não autorizado para catálogo estável. Ver [contratos gerais](SHARED_CONTRACTS.md). **Não usar este documento como autorização de escrita.**

## 1. Resumo executivo e estado
Arranque Live em overlay QCOW2 readonly não é execução de distinst nem dual boot. O objectivo é uma instalação nativa automatizada ao lado do Windows, com prova independente dos dois boots e recuperação. Compatibilidade upstream não equivale a suporte validado no Gaslux.

## 2. Fontes oficiais, versões e proveniência
- [Origem oficial/media](https://iso.pop-os.org/24.04/amd64/intel/20/pop-os_24.04_amd64_intel_20.iso) — versão/release: **24.04 Intel build 20 experimental em PR #228 (não catálogo)**. [DOCUMENTADO como endereço de referência; revalidar disponibilidade, conteúdo e assinatura na data da execução.]
- [Documentação upstream](https://support.system76.com/articles/install-pop/) — instruções gerais, não aprovação de boot sem USB. [DOCUMENTADO; verificar versão, data e parâmetros antes de automatizar.]
- [Configuração Gaslux main](https://github.com/LMhdez/gaslux/blob/main/release-config.json) — não contém esta distribuição. [IMPLEMENTADO]
- [Arquitectura Gaslux](https://github.com/LMhdez/gaslux/blob/dev/docs/ARCHITECTURE.md), [Issue de estabilidade #3](https://github.com/LMhdez/gaslux/issues/3) e [PR multidistro #7](https://github.com/LMhdez/gaslux/pull/7). [IMPLEMENTADO/critério documental]
- PRs/threads experimentais relacionadas: [#221](https://github.com/LMhdez/gaslux/pull/221), [#223](https://github.com/LMhdez/gaslux/pull/223), [#228](https://github.com/LMhdez/gaslux/pull/228), [#232](https://github.com/LMhdez/gaslux/pull/232). **Consultar HEAD, estado de merge, logs e branches antes de reutilizar.**
- Evidência histórica de CI para contexto: [Actions](https://github.com/LMhdez/gaslux/actions/runs/44490023468); a existência ou êxito do workflow não certifica todas as etapas. [PENDENTE: rever job e artefactos exactos.]

## 3. Arquitectura de arranque
**Estratégia:** systemd-boot em UEFI; GRUB em Legacy BIOS quando suportado pela versão exacta; Secure Boot desactivado segundo orientação System76, confirmar por release. **Modo:** UEFI/GPT em ensaios; BIOS/MBR apenas após teste real e confirmação upstream; Secure Boot activo BLOQUEADO sem solução unattended verificada.
[DOCUMENTADO/pendente por mídia] Em BIOS o arranque envolve MBR/PBR, BCD e eventual cadeia GRUB; em UEFI começa em entradas NVRAM/ESP, sem sobrepor `EFI/Microsoft`. Os caminhos são mutuamente distintos. Recusar associações firmware/tabela não ensaiadas. Não alterar chaves Secure Boot ou privilégios de arranque automaticamente.

## 4. Estrutura, identidade e autenticação da ISO
- Artefacto: `pop-os_24.04_amd64_intel_20.iso (experimental)`.
- SHA-256 fixado: `a0ef3842ab710db4f4407cf3499560b59dddbbcd59bee17beab7b0e99dc22b4c`; tamanho exacto: `2955067392` bytes. [IMPLEMENTADO em metadados de PR experimental, NÃO catálogo main; assinatura GPG upstream tem de ser verificada no pipeline].
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
**Instalador:** System76 distinst e integração nativa Pop; API CLI/config específica requer fonte e artefacto da ISO examinados.
**Mecanismo previsto:** Ler distinst real da ISO e versões System76; limitar destino a partições autorizadas; confirmar estratégia EFI/bootloader e manter Boot Manager Windows.
[INVESTIGAR] Ler fontes upstream/versão binária efectiva, argumentos ou API suportados, modo unattended, ficheiros YAML/JSON/scripts declarados, mapeamento de contas/UID, locale, teclado, fuso horário, password hashing e grupos, pacote manager, formatos root/ESP e tratamento de erros. Não usar cliques por coordenadas sem estado observável: identificar janelas/elementos e pré/pós-condições; qualquer click manual não é estratégia de produção unattended. Não escrever um pseudo-instalador que só copia raiz Live.

## 7. Particionamento e protecção de Windows
[CONTRATO] Capturar disk serial, firmware, tabela e sector real; comparar GUIDs/assinatura, início/tamanho exacto em bytes e todas as partições; possuir explicitamente cada intervalo afectado. Nunca mudar ESP/EFI Windows, OEM, Recovery, WinRE, BCD, BitLocker/Device Encryption ou discos não seleccionados. MBR: validar quatro slots, primária activa, partição estendida/lógicas/EBR e endereçamento; recusar qualquer cadeia EBR sem método testado. GPT: validar primária/secundária, GUIDs, ESP, NVRAM e limite do resize. Segundo disco exige o mesmo nível de identificação e prova de boot. [BLOQUEADO quando não comprovado]

## 8. Configuração instalada e primeiro boot
Validar instalador finalizado, kernel/initramfs, loader entries systemd-boot, Windows EFI e reboot sem ISO. [PENDENTE — exigir evidência de comandos executados no convidado, versões e verificações independentes] Aplicar locale, teclado, timezone, password e permissões de forma transaccional; verificar também instalação real de pacotes, serviços, fstab por UUID e root montada. Sem ISO montada no boot de aceitação.

## 9. Bootloader, kernel e manutenção
systemd-boot em UEFI; GRUB em Legacy BIOS quando suportado pela versão exacta; Secure Boot desactivado segundo orientação System76, confirmar por release. Manter Windows Boot Manager intacto, cópias EFI/boot code apenas onde a transacção detenha posse, e entradas Windows válidas. Revalidar entradas e hashes antes/depois da instalação e de cada update de kernel/loader. Hooks APT/dpkg de Mint/Zorin não são transferíveis sem adaptação a pacman, distinst ou Atomic. [PENDENTE — prova por distro]

## 10. Actualizações e desinstalação
Testar upgrade de pacotes, regeneração de initramfs, kernel novo, loader novo, reboot Linux, reboot Windows e operação de remoção. Backup imutável de EFI/BCD/MBR/NVRAM e ownership por transacção; a desinstalação não pode apagar um artefacto partilhado/unowned. Reinicializar a verificação Windows/WinRE após remoção. [PENDENTE — não inferir de update numa raiz Linux isolada]

## 11. Recuperação e rollback
Antes da mutação: baseline geométrico/WinRE/BCD/ESP ou MBR, encriptação, estado boot, hashes, snapshot de VM e recovery runtime. Em cada fase: checkpoint durável; em falha, compensação inversa apenas sobre recursos possuídos, revalidar disco e sector, recuperar arranque e medir o Windows após reinício verdadeiro. Queda de energia e falha parcial EFI/rede são testes obrigatórios. Sem arranque Windows e comparações de integridade não existe rollback COMPROVADO. [BLOQUEADO para hardware real]

## 12. Código Gaslux reutilizável
[IMPLEMENTADO — caminhos confirmados pela documentação do projecto; conferir conteúdo/ref de cada um] `Installation/` (plano/ledger), `Scripts/modules/` (PowerShell, storage/rollback), `Scripts/uefi/`, `assets/live/` (verificação/handoff/first boot), `schemas/`, `iso-tools/`, `Libertix.Tests/`, `PowerShell.Tests/`, `auto_tests/`. Preservar o fluxo Mint/Zorin e separar módulos específicos da família Linux.

## 13. PRs, branches e commits a reutilizar
#221, #223, #228, #232. Resolver IDs, HEADs, base empilhada e diffs efectivos no momento da implementação; não aplicar commits de PR antigos cegamente. A PR #7 foi integrada em `dev`; `main` não contém necessariamente o mesmo `AGENTS.md`. Reaproveitar somente partes cujo comportamento foi confirmado e não duplicar guardas.

## 14. Problemas conhecidos e causas
Arranque Live em overlay QCOW2 readonly não é execução de distinst nem dual boot. Problemas gerais: parâmetros de initramfs desconhecidos, Windows ISO/UEFI prompt, discos que mudam de ordem, entrada NVRAM que não persiste, partição estendida difícil de compensar, confiança Secure Boot incompleta, instaladores que reformatam ESP/Windows por defeito. A causa exacta de uma falha é PENDENTE até log + reprodução + commit.

## 15. Soluções tecnicamente verificadas vs. hipóteses
[IMPLEMENTADO] Existem protecções de plano, state ledger, catálogo assinado e caminhos firmware Gaslux (ver ARCHITECTURE). [PENDENTE] A adaptação ao instalador Pop!_OS e estratégia USB-free do artefacto exacto não estão comprovadas nesta investigação. Não confundir existência de scripts com execução de instalação nativa.

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
- [Actions histórica](https://github.com/LMhdez/gaslux/actions/runs/44490023468): **COMPROVADO somente para as verificações que o job e os artefactos realmente contêm**, e sujeito a revalidação do HEAD actual.
- [ISSUE #3](https://github.com/LMhdez/gaslux/issues/3) indica gates não resolvidos; PRs citadas acima oferecem trabalho experimental, não prova universal.
- [PENDENTE] Associar manifesto de artefactos, digest, SHA exacto do workflow e nível de evidência (fixtures vs Live vs instalado vs dual boot vs rollback).

## 18. Testes adicionais obrigatórios
Lint/documentação e contratos C#/Pester/Python/Bash; autenticação ISO offline; VM descartável com ISO real; primeiro boot sem ISO; Windows 10 BIOS/MBR onde elegível, Windows 10 e 11 UEFI/GPT; disco único/segundo disco, partições complexas, Secure Boot admissível; update/reboot de kernel e loader; reinstall/uninstall; falhas de hash, disco permutado, ISO truncada, rede ausente, SIGKILL/power-cut e recovery BCD/WinRE. Escritas somente em VM autorizada, sem discos host. [PENDENTE]

## 19. Plano incremental de implementação
(1) Confirmar HEAD e upstream/media fixada; (2) automatizar inspecção read-only + hashes; (3) testes negativos dos gates; (4) validar handoff em Live; (5) autorizar escritor apenas sobre VM com snapshot e identidade comprovada; (6) executar instalador real; (7) provar primeiro boot sem ISO; (8) dual boot Windows; (9) update e reboot; (10) rollback completo; (11) revisão humana. Cada etapa deve deixar evidência ligada a commit, run, artefactos e manifestos; nunca continuar numa falha.

## 20. Critério objectivo de estabilidade
Não basta existir ISO/hash válido, CI verde, Live boot ou raiz extraída. Requer ISO oficial autenticada, instalação nativa de Pop!_OS numa VM descartável Windows realmente instalado, boot Linux e Windows independentes, kernel/bootloader actualizados, Windows WinRE/BCD/ESP preservados, uninstall e rollback completos, incluindo injecção de falhas e testes negativos dos layouts suportados. Hardware só depois de backup/restauro sob autorização explícita.

---

## Anexo técnico — System76 24.04, distinst e prova de ISO (19-11-2026)

### ISO oficial, identidade e trust model
[DOCUMENTADO — upstream] O [repositório System76 da imagem Pop!_OS](https://github.com/pop-os/iso) e o [instalador distinst](https://github.com/pop-os/distinst) definem as responsabilidades dos componentes `casper`, `distinst` e `pop-installer`; confirmar sempre o conteúdo da variante concreta. [IMPLEMENTADO — laboratório da PR #232] [`windows10_popos_official_iso_signed_lab.py`](https://github.com/LMhdez/gaslux/blob/85c9ea30b75c763314e775d4daddf10d5357109e/auto_tests/tools/windows10_popos_official_iso_signed_lab.py) consulta a API oficial `https://api.pop-os.org/builds/24.04/intel`, exige URL com build inteiro em `iso.pop-os.org`, valida `SHA256SUMS` com `SHA256SUMS.gpg` e fingerprint System76 `63C46DF0140D738961429F4E204DD8AEC33A7AFF`, e confronta nome, tamanho, digest e bytes locais. A PR #228 fixou **experimentalmente** a ISO Intel build 20, 2 955 067 392 bytes, SHA `a0ef3842ab710db4f4407cf3499560b59dddbbcd59bee17beab7b0e99dc22b4c`; isso **não** acrescenta Pop a `release-config.json`. Como a API devolve builds variáveis, fixar a versão e assinar o manifesto antes de qualquer candidato de produção; não inferir que o build 20 continua actual.

### Ficheiros e argumentos de arranque observados
[IMPLEMENTADO — código de laboratório] [`gaslux_q4os_calamares_gui_laboratory.sh`](https://github.com/LMhdez/gaslux/blob/6b6d5521dbd4c2c26712fb57cb6ae5b29e0c69bb/auto_tests/tools/gaslux_q4os_calamares_gui_laboratory.sh) possui um caminho Pop que pesquisa exactamente uma pasta ISO de nome `casper_pop-os_24.04_amd64_intel_<build>`, exige nela `vmlinuz.efi` e `initrd.gz`, e lança kernel/initramfs por GRUB OVMF com `boot=casper live-media-path=/<pasta>` e consola série. Este é **um mecanismo de laboratório isolado** e não uma garantia de que o initramfs da versão detecta o staging NTFS do Windows sem USB. [PENDENTE] Capturar `grub.cfg`, El Torito, EFI binaries, `filesystem.squashfs`, `*.manifest-remove`, `os-release` e versão binária de `/usr/bin/distinst` de ISO autenticada para regressões futuras.

### Instalador nativo: diferenças operacionais verificáveis
[DOCUMENTADO — código upstream] [`pop-os/distinst`](https://github.com/pop-os/distinst) expõe integração Rust, C e Vala; a instalação envolve extracção do SquashFS, remoções por manifesto e configuração no destino, não equivale a copiar uma raiz Live do Gaslux. [IMPLEMENTADO — **preview inerte**, PR #232] [`gaslux_popos_distinst_preview.py`](https://github.com/LMhdez/gaslux/blob/85c9ea30b75c763314e775d4daddf10d5357109e/auto_tests/tools/gaslux_popos_distinst_preview.py) gera argumentos de `distinst` para VM sintética com `--squashfs`, `--remove`, `--hostname`, `--keyboard`, `--lang`, `--block`, `--use` e `--no-efi-vars`. **Não executa o comando**. Em especial, `--use DISK:ESP:reuse:mount=/boot/efi` pretende reutilizar a ESP, enquanto `fat32` pode **formatá-la**. Em Windows/Gaslux, não basta passar `reuse`: é obrigatório provar a ausência de escritas a `EFI/Microsoft`, preservação de BootOrder e totalidade do write-set; até lá o instalador nativo continua BLOQUEADO. UEFI recorre a systemd-boot; BIOS/MBR GRUB necessita prova da variante concreta. Secure Boot habilitado e full-disk encryption de Linux no mesmo disco Windows são rejeitados pelo actual [`gaslux_popos_preflight.py`](https://github.com/LMhdez/gaslux/blob/dev/assets/live/gaslux_popos_preflight.py).

### Resultados CI actuais e causa específica
[COMPROVADO — apenas Live e diagnóstico] [PR #232](https://github.com/LMhdez/gaslux/pull/232) HEAD `85c9ea30b75c763314e775d4daddf10d5357109e`, [Actions #44561473570](https://github.com/LMhdez/gaslux/actions/runs/44561473570), job genuíno Win10+Pop **FAILURE**. O log mostra guest Pop iniciado, FAT de controlo montada, SHA de scripts validado; depois a leitura da quinta partição recusou **`owned Pop partition 5 signature probe refused: blkid exit=0 type='' stderr=''`**. [Artefacto #14552075432](https://github.com/LMhdez/gaslux/actions/runs/44561473570/artifacts/14552075432). A prova `popSignedIsoGpgVerified` saiu **false** no relatório desta execução; o helper GPG existe no código, mas a saída do ensaio falhado NÃO permite classificá-la como assinada/verificada. [PENDENTE] Esclarecer se a quinta partição foi propositadamente criada sem FS e ajustar os critérios *pré-instalação* sem permitir contornar a identificação GUID/offset; só então repetir a auditoria Live e confirmar assinatura upstream com logs completos.

### Sequência one-shot específica e STOP
1. Resolver ISO imutável/API e verificar GPG fingerprint+manifesto+SHA/tamanho; obter `distinst --version`, estruturas de `casper` e `manifest-remove`.
2. Provar Live no mesmo Windows 10 COW só-leitura e identificar cada partição com GUID/offset/sector e sem falsos positivos de `blkid`; comparar GPT primária/secundária e Windows ESP/BCD/WinRE.
3. Assinar/autenticar plano com ESP de Windows **reuse sem format**, Linux root exclusivamente possuída; preparar recovery/snapshot antes de qualquer escrita, e disallow NVRAM/ESP unowned.
4. Exercitar `distinst` real apenas em child QCOW2 com autorização e prova do write-set; configurar utilizador, língua, teclado e timezone sem depender de prompts GUI.
5. Arrancar Pop instalado sem ISO, arranque Windows, actualização de kernel/systemd-boot, dois novos boots, remoção e rollback in-place sob injecção de falhas.
**STOP** para desconhecimento de CLI/ISO ou tentativa de formatar FAT Windows; este anexo não fornece comando de instalação autorizado.

---

## ONE-SHOT EXECUTION PLAYBOOK
**Pré-requisitos exactos:** acesso GitHub conta LMHDEZ, HEAD `dev` confirmado, `AI_POLICY.md`, `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/distro-backends/SHARED_CONTRACTS.md`, mídia oficial e digest/assinatura validados; runner VM descartável com QEMU/SeaBIOS/OVMF conforme firmware e snapshot recuperável. Sem estes elementos, STOP.

**Branch recomendada:** `feature/popos-native-backend-verified` a partir do HEAD revisto de `dev`, evitando branches empilhadas obsoletas. **PRs candidatas:** #221, #223, #228, #232. Verificar SHA/head/diff antes do cherry-pick.

**Ficheiros a inspeccionar e possivelmente alterar apenas numa futura PR funcional:** `Installation/`, `Scripts/modules/`, `Scripts/uefi/`, `assets/live/`, `schemas/`, adaptadores de distro e testes. **Não alterar sem gates:** `release-config.json` estável, `EFI/Microsoft`, boot Windows, partições alheias, assinaturas/catálogo e contratos Mint/Zorin.

**Interfaces obrigatórias:** preflight tipado → catálogo assinado/ISO validada → plano e ledger duráveis → handoff autenticado → provisioning de target possuído → instalador nativo → bootloader da distribuição → first-boot evidence → verificação Windows → manutenção/uninstall/rollback.

**Execução faseada e testes:** primeiro `ruff check`, `pytest`, `dotnet test`, Pester e ShellCheck conforme workflows existentes e HEAD; verificar nomes e argumentos reais dos workflows antes de executar. Seguidamente lançar apenas workflow explicitamente autorizado com VM descartável, snapshot e hash. Sucesso de cada fase exige relatório de identidade, logs independentes e hashes; nunca métricas auto-reportadas. A lista de workflows experimentais nas PRs #221, #223, #228, #232 é *candidata*, não comando autorizado.

**Falhas previsíveis/correcções:** assinatura errada → descartar a imagem; root ISO não visível → corrigir initramfs/handoff antes de escrever; UUID errado → bloquear; ausência de slot MBR → bloquear, não mexer em EBR; instalador tenta reformatar ESP/Windows → bloquear; bootloader incompleto → restaurar só ficheiros possuídos e confirmar Windows; update altera entrada Windows → reverter com checkpoint e negar sucesso.

**Interrupção obrigatória:** qualquer geometria, hash, conta, firma/assinatura, Secure Boot, propriedade, WinRE/BCD ou estado de recuperação não comprovado; Windows sem boot validado; tentativa de usar disco físico; parâmetros, caminhos de ISO ou opções unattended desconhecidos.

**Provas de conclusão:** SHA commit, PR, workflow/run, artefactos e respectivos SHA-256, cadeia de assinatura upstream, serial/GUID/offsets, pré/pós Windows BCD/WinRE/EFI/MBR, arranques Linux e Windows pós-instalação e pós-update, remoção, rollback e relatório independente. **Nunca declarar estável sem a matriz completa.**
