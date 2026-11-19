# Bazzite — ONE-SHOT backend dossier

**Revisão:** 2026-11-19. **Maturidade:** EXPERIMENTAL / PENDENTE: não autorizado para catálogo estável. Ver [contratos gerais](SHARED_CONTRACTS.md). **Não usar este documento como autorização de escrita.**

## 1. Resumo executivo e estado
Teste Cosign sobre payload/chave sintéticos não autentica ISO real nem demonstra instalação Atomic. O objectivo é uma instalação nativa automatizada ao lado do Windows, com prova independente dos dois boots e recuperação. Compatibilidade upstream não equivale a suporte validado no Gaslux.

## 2. Fontes oficiais, versões e proveniência
- [Origem oficial/media](https://bazzite.gg/) — versão/release: **não fixada no catálogo estável**. [DOCUMENTADO como endereço de referência; revalidar disponibilidade, conteúdo e assinatura na data da execução.]
- [Documentação upstream](https://docs.bazzite.gg/General/Installation_Guide/) — instruções gerais, não aprovação de boot sem USB. [DOCUMENTADO; verificar versão, data e parâmetros antes de automatizar.]
- [Configuração Gaslux main](https://github.com/LMhdez/gaslux/blob/main/release-config.json) — não contém esta distribuição. [IMPLEMENTADO]
- [Arquitectura Gaslux](https://github.com/LMhdez/gaslux/blob/dev/docs/ARCHITECTURE.md), [Issue de estabilidade #3](https://github.com/LMhdez/gaslux/issues/3) e [PR multidistro #7](https://github.com/LMhdez/gaslux/pull/7). [IMPLEMENTADO/critério documental]
- PRs/threads experimentais relacionadas: [#172](https://github.com/LMhdez/gaslux/pull/172), [#175](https://github.com/LMhdez/gaslux/pull/175). **Consultar HEAD, estado de merge, logs e branches antes de reutilizar.**
- Evidência histórica de CI para contexto: [Actions](https://github.com/LMhdez/gaslux/actions/runs/44147851375); a existência ou êxito do workflow não certifica todas as etapas. [PENDENTE: rever job e artefactos exactos.]

## 3. Arquitectura de arranque
**Estratégia:** cadeia Fedora Atomic e deployment ostree/rpm-ostree; implementação EFI e política Secure Boot exigem comprovação da ISO exacta. **Modo:** APENAS UEFI/GPT no Gaslux; BIOS/MBR BLOQUEADO antes de escrita; Secure Boot que requeira MOK manual BLOQUEADO.
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
**Instalador:** instalação Fedora Atomic conforme ISO oficial (Anaconda/fluxo atomic comprovado por release), não copiar squashfs.
**Mecanismo previsto:** Provar instalador Atomic e layout de deployment; validar assinatura ISO/artefactos, subvolumes e loader por release, falhas de update e rollback do deployment.
[INVESTIGAR] Ler fontes upstream/versão binária efectiva, argumentos ou API suportados, modo unattended, ficheiros YAML/JSON/scripts declarados, mapeamento de contas/UID, locale, teclado, fuso horário, password hashing e grupos, pacote manager, formatos root/ESP e tratamento de erros. Não usar cliques por coordenadas sem estado observável: identificar janelas/elementos e pré/pós-condições; qualquer click manual não é estratégia de produção unattended. Não escrever um pseudo-instalador que só copia raiz Live.

## 7. Particionamento e protecção de Windows
[CONTRATO] Capturar disk serial, firmware, tabela e sector real; comparar GUIDs/assinatura, início/tamanho exacto em bytes e todas as partições; possuir explicitamente cada intervalo afectado. Nunca mudar ESP/EFI Windows, OEM, Recovery, WinRE, BCD, BitLocker/Device Encryption ou discos não seleccionados. MBR: validar quatro slots, primária activa, partição estendida/lógicas/EBR e endereçamento; recusar qualquer cadeia EBR sem método testado. GPT: validar primária/secundária, GUIDs, ESP, NVRAM e limite do resize. Segundo disco exige o mesmo nível de identificação e prova de boot. [BLOQUEADO quando não comprovado]

## 8. Configuração instalada e primeiro boot
Verificar deployment montado, rpm-ostree status, entrada EFI, primeiro boot, update/rebase e Windows intacto. [PENDENTE — exigir evidência de comandos executados no convidado, versões e verificações independentes] Aplicar locale, teclado, timezone, password e permissões de forma transaccional; verificar também instalação real de pacotes, serviços, fstab por UUID e root montada. Sem ISO montada no boot de aceitação.

## 9. Bootloader, kernel e manutenção
cadeia Fedora Atomic e deployment ostree/rpm-ostree; implementação EFI e política Secure Boot exigem comprovação da ISO exacta. Manter Windows Boot Manager intacto, cópias EFI/boot code apenas onde a transacção detenha posse, e entradas Windows válidas. Revalidar entradas e hashes antes/depois da instalação e de cada update de kernel/loader. Hooks APT/dpkg de Mint/Zorin não são transferíveis sem adaptação a pacman, distinst ou Atomic. [PENDENTE — prova por distro]

## 10. Actualizações e desinstalação
Testar upgrade de pacotes, regeneração de initramfs, kernel novo, loader novo, reboot Linux, reboot Windows e operação de remoção. Backup imutável de EFI/BCD/MBR/NVRAM e ownership por transacção; a desinstalação não pode apagar um artefacto partilhado/unowned. Reinicializar a verificação Windows/WinRE após remoção. [PENDENTE — não inferir de update numa raiz Linux isolada]

## 11. Recuperação e rollback
Antes da mutação: baseline geométrico/WinRE/BCD/ESP ou MBR, encriptação, estado boot, hashes, snapshot de VM e recovery runtime. Em cada fase: checkpoint durável; em falha, compensação inversa apenas sobre recursos possuídos, revalidar disco e sector, recuperar arranque e medir o Windows após reinício verdadeiro. Queda de energia e falha parcial EFI/rede são testes obrigatórios. Sem arranque Windows e comparações de integridade não existe rollback COMPROVADO. [BLOQUEADO para hardware real]

## 12. Código Gaslux reutilizável
[IMPLEMENTADO — caminhos confirmados pela documentação do projecto; conferir conteúdo/ref de cada um] `Installation/` (plano/ledger), `Scripts/modules/` (PowerShell, storage/rollback), `Scripts/uefi/`, `assets/live/` (verificação/handoff/first boot), `schemas/`, `iso-tools/`, `Libertix.Tests/`, `PowerShell.Tests/`, `auto_tests/`. Preservar o fluxo Mint/Zorin e separar módulos específicos da família Linux.

## 13. PRs, branches e commits a reutilizar
#172, #175. Resolver IDs, HEADs, base empilhada e diffs efectivos no momento da implementação; não aplicar commits de PR antigos cegamente. A PR #7 foi integrada em `dev`; `main` não contém necessariamente o mesmo `AGENTS.md`. Reaproveitar somente partes cujo comportamento foi confirmado e não duplicar guardas.

## 14. Problemas conhecidos e causas
Teste Cosign sobre payload/chave sintéticos não autentica ISO real nem demonstra instalação Atomic. Problemas gerais: parâmetros de initramfs desconhecidos, Windows ISO/UEFI prompt, discos que mudam de ordem, entrada NVRAM que não persiste, partição estendida difícil de compensar, confiança Secure Boot incompleta, instaladores que reformatam ESP/Windows por defeito. A causa exacta de uma falha é PENDENTE até log + reprodução + commit.

## 15. Soluções tecnicamente verificadas vs. hipóteses
[IMPLEMENTADO] Existem protecções de plano, state ledger, catálogo assinado e caminhos firmware Gaslux (ver ARCHITECTURE). [PENDENTE] A adaptação ao instalador Bazzite e estratégia USB-free do artefacto exacto não estão comprovadas nesta investigação. Não confundir existência de scripts com execução de instalação nativa.

## 16. Matriz de compatibilidade
| Ambiente | Compatibilidade no Gaslux | Gate |
|---|---|---|
| Windows 10 BIOS/MBR | BLOQUEADO | slots/EBR/sector real/MBR/PBR/BCD |
| Windows 10 UEFI/GPT | PENDENTE | ESP/NVRAM/BCD/WinRE/Windows boot |
| Windows 11 UEFI/GPT | PENDENTE | TPM/BitLocker/ESP/WinRE/Secure Boot |
| Segundo disco | PENDENTE | serial real e BootOrder independente |
| Secure Boot | PENDENTE conforme versão e chaves de firmware | prova de loader instalado, sem enrollment manual |
| BIOS/GPT ou UEFI/MBR | BLOQUEADO sem teste explícito | nunca converter automaticamente |

## 17. Testes existentes e evidências
- [Actions histórica](https://github.com/LMhdez/gaslux/actions/runs/44147851375): **COMPROVADO somente para as verificações que o job e os artefactos realmente contêm**, e sujeito a revalidação do HEAD actual.
- [ISSUE #3](https://github.com/LMhdez/gaslux/issues/3) indica gates não resolvidos; PRs citadas acima oferecem trabalho experimental, não prova universal.
- [PENDENTE] Associar manifesto de artefactos, digest, SHA exacto do workflow e nível de evidência (fixtures vs Live vs instalado vs dual boot vs rollback).

## 18. Testes adicionais obrigatórios
Lint/documentação e contratos C#/Pester/Python/Bash; autenticação ISO offline; VM descartável com ISO real; primeiro boot sem ISO; Windows 10 BIOS/MBR onde elegível, Windows 10 e 11 UEFI/GPT; disco único/segundo disco, partições complexas, Secure Boot admissível; update/reboot de kernel e loader; reinstall/uninstall; falhas de hash, disco permutado, ISO truncada, rede ausente, SIGKILL/power-cut e recovery BCD/WinRE. Escritas somente em VM autorizada, sem discos host. [PENDENTE]

## 19. Plano incremental de implementação
(1) Confirmar HEAD e upstream/media fixada; (2) automatizar inspecção read-only + hashes; (3) testes negativos dos gates; (4) validar handoff em Live; (5) autorizar escritor apenas sobre VM com snapshot e identidade comprovada; (6) executar instalador real; (7) provar primeiro boot sem ISO; (8) dual boot Windows; (9) update e reboot; (10) rollback completo; (11) revisão humana. Cada etapa deve deixar evidência ligada a commit, run, artefactos e manifestos; nunca continuar numa falha.

## 20. Critério objectivo de estabilidade
Não basta existir ISO/hash válido, CI verde, Live boot ou raiz extraída. Requer ISO oficial autenticada, instalação nativa de Bazzite numa VM descartável Windows realmente instalado, boot Linux e Windows independentes, kernel/bootloader actualizados, Windows WinRE/BCD/ESP preservados, uninstall e rollback completos, incluindo injecção de falhas e testes negativos dos layouts suportados. Hardware só depois de backup/restauro sob autorização explícita.

---

## Anexo técnico — Fedora Atomic, ISO Legacy e estado da UI (19-11-2026)

### Imagem, assinatura e matrizes
[DOCUMENTADO upstream] [Manual partitioning](https://docs.bazzite.gg/General/Installation_Guide/manual_partitioning/) e [Legacy installation](https://docs.bazzite.gg/General/Installation_Guide/legacy-install/) diferem entre gerações da ISO. Os guias Legacy descrevem **Anaconda** e a selecção `Installation Destination → Advanced Custom (Blivet-GUI)`, com `/boot/efi`, `/boot`, Btrfs root e subvolumes para `/`, `/var`, `/var/home`; NÃO validar como fluxo da nova ISO sem rever o payload. [IMPLEMENTADO — dev] [`gaslux_bazzite_preflight.py`](https://github.com/LMhdez/gaslux/blob/dev/assets/live/gaslux_bazzite_preflight.py) recusa firmware não UEFI/GPT, Secure Boot activo sem enrollment unattended, menos de 8192 MiB RAM de laboratório ou 50 GiB disco, root sem Btrfs ou instalador diferente de `fedora-atomic-native`. [`schemas/distribution-capabilities.schema.json`](https://github.com/LMhdez/gaslux/blob/dev/schemas/distribution-capabilities.schema.json) fixa `bios:none`, `uefi:grub`. Estas regras são gates Gaslux, não prova de que uma ISO real está pronta.

[IMPLEMENTADO — prova de origem diferente] O workflow [`gaslux-bazzite-atomic-origin.yml`](https://github.com/LMhdez/gaslux/blob/dev/.github/workflows/gaslux-bazzite-atomic-origin.yml) autentica assinatura **OCI** de `ghcr.io/ublue-os/bazzite:stable` por `cosign verify` com a chave vendorizada `assets/keys/bazzite-upstream-cosign.pub` e valida attestation GitHub para o digest OCI. **OCI assinado não significa ISO Legacy 42 autenticada**; não utilizar o digest de imagem de container como SHA de ISO. As PRs #214/#250 fazem laboratório com ISO Legacy 42 não independente criptograficamente atestada; não existe tamanho/digest dessa ISO no catálogo estável.

### Ecrãs, clicks observados e segurança do assistente
[COMPROVADO — screenshots de laboratório, não instalador] [PR #214](https://github.com/LMhdez/gaslux/pull/214) e [Actions #44443420174](https://github.com/LMhdez/gaslux/actions/runs/44443420174), artefacto [#14492713616](https://github.com/LMhdez/gaslux/actions/runs/44443420174/artifacts/14492713616), observaram num OVMF QEMU **sem disco** o ecrã Bazzite 42 com opções `Automatic`, `Custom`, `Advanced Custom (Blivet-GUI)` desactivadas por ausência de discos. Isso prova o **texto de selecção**, não o editor Blivet nem instalação. As acções VNC na branch #250 são ligadas a screenshot, OCR/TSV e contexto do guest: `Continue` em (1225,770) de [Run #44375068915](https://github.com/LMhdez/gaslux/actions/runs/44375068915) e `Installation Destination` em (758,328) de [Run #44378715492](https://github.com/LMhdez/gaslux/actions/runs/44378715492). As coordenadas são **exclusivas daquela resolução/screenshot**; nunca codificá-las no assistente Gaslux.

[COMPROVADO — falha do teste mais recente] [PR #250](https://github.com/LMhdez/gaslux/pull/250), HEAD `1f909b2a78e8eb4c2042251f4a0a9468fb3b6ff2`, [Actions #44576081171](https://github.com/LMhdez/gaslux/actions/runs/44576081171): jobs `contracts` e `prior-blue-button` **SUCCESS**, mas `readonly-gpt-stage3` **FAILURE**: `GUEST_PROBE=FAIL`, `Missing mandatory Custom selection evidence`. [Artefacto #14557722347](https://github.com/LMhdez/gaslux/actions/runs/44576081171/artifacts/14557722347). O editor Blivet-GUI **não ficou demonstrado**, nem foi autorizado `Begin Installation`, escrita em partição, ESP ou chaves. As flags continuam `installationAuthorized=false`, `partitionWriteAuthorized=false`, `windowsEspWriteAuthorized=false`. A [issue #254](https://github.com/LMhdez/gaslux/issues/254) acompanha os bloqueios.

### Atomic diferente de Linux convencional
[DOCUMENTADO upstream] Uma instalação Bazzite deve comprovar deployment `bootc`/OSTree e integridade Btrfs, e uma actualização deve demonstrar o novo deployment, boot e recuperação, não apenas instalar RPM com `dnf`; consultar [gestão de actualizações e rollback](https://docs.bazzite.gg/Installing_and_Managing_Software/Updates_Rollbacks_and_Rebasing/). O auditor [`gaslux_candidate_target_audit.py`](https://github.com/LMhdez/gaslux/blob/dev/assets/live/gaslux_candidate_target_audit.py) inspeciona `ostree/deploy` e entradas `ostree`, mas explicitamente devolve `linuxBootVerified=false`, `windowsBootVerified=false` e `installationAuthorized=false`. A orientação upstream de enrollment MOK manual para Secure Boot não cumpre o fluxo sem intervenção, logo **Secure Boot ligado BLOQUEADO**.

### Playbook de passos UI/autorização
1. Autenticar criptograficamente a ISO inteira e versão, comparar com assinatura da origem upstream; distinguir Legacy/actual, OVMF e pacote Anaconda/Blivet binários e versões **do próprio payload**. Se só houver digest OCI ou SHA sem autoridade oficial, STOP.
2. Repetir `Installation Destination` em OVMF com COW GPT **read-only**, identificar disco por serial e cada label de UI por screenshot/OCR autenticado e geometria do controlo. Registar antes/depois de cada clique **sem tocar Done/Begin Installation**.
3. Investigar se existe API de Anaconda/Kickstart/Blivet que aceite write-set estrito e partições preexistentes Windows. Se um único botão puder formatar/recriar Windows ESP, STOP; não confiar no ecrã como autorização.
4. Apenas após trust de ISO + manifesto de writes + recuperação e snapshots, testar instalação Atomic real em VM descartável; provar deployment/GRUB/Windows, update, rollback de deployment e rollback Windows depois de falhas.
5. BIOS/MBR sempre falha imediata **antes de leitura de artefactos para instalação ou qualquer escrita**. Nunca enrollment de MOK automático.

---


### Restrições de produto do instalador novo verificadas em fonte oficial
[DOCUMENTADO — upstream] O [guia Legacy da Bazzite](https://docs.bazzite.gg/General/Installation_Guide/legacy-install/) declara expressamente que as ISOs Legacy continuam disponíveis porque o **instalador novo ainda não suporta particionamento manual**. O [guia actual](https://docs.bazzite.gg/General/Installation_Guide/install-guide/) remete casos que exigem particionamento manual para a mídia Legacy. Este bloqueio upstream é independente de Bazzite conseguir arrancar em UEFI/GPT: para preservar Windows e controlar cada intervalo, a selecção da ISO/instalador é parte do preflight; **não se pode tratar o novo instalador como pronto para uso desatendido em disco partilhado**. A [documentação Secure Boot](https://docs.bazzite.gg/General/Installation_Guide/secure_boot/) exige confirmação pelo MokManager em certas cadeias, incompatível com a regra Gaslux sem intervenção. 

---

## ONE-SHOT EXECUTION PLAYBOOK
**Pré-requisitos exactos:** acesso GitHub conta LMHDEZ, HEAD `dev` confirmado, `AI_POLICY.md`, `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/distro-backends/SHARED_CONTRACTS.md`, mídia oficial e digest/assinatura validados; runner VM descartável com QEMU/SeaBIOS/OVMF conforme firmware e snapshot recuperável. Sem estes elementos, STOP.

**Branch recomendada:** `feature/bazzite-native-backend-verified` a partir do HEAD revisto de `dev`, evitando branches empilhadas obsoletas. **PRs candidatas:** #172, #175. Verificar SHA/head/diff antes do cherry-pick.

**Ficheiros a inspeccionar e possivelmente alterar apenas numa futura PR funcional:** `Installation/`, `Scripts/modules/`, `Scripts/uefi/`, `assets/live/`, `schemas/`, adaptadores de distro e testes. **Não alterar sem gates:** `release-config.json` estável, `EFI/Microsoft`, boot Windows, partições alheias, assinaturas/catálogo e contratos Mint/Zorin.

**Interfaces obrigatórias:** preflight tipado → catálogo assinado/ISO validada → plano e ledger duráveis → handoff autenticado → provisioning de target possuído → instalador nativo → bootloader da distribuição → first-boot evidence → verificação Windows → manutenção/uninstall/rollback.

**Execução faseada e testes:** primeiro `ruff check`, `pytest`, `dotnet test`, Pester e ShellCheck conforme workflows existentes e HEAD; verificar nomes e argumentos reais dos workflows antes de executar. Seguidamente lançar apenas workflow explicitamente autorizado com VM descartável, snapshot e hash. Sucesso de cada fase exige relatório de identidade, logs independentes e hashes; nunca métricas auto-reportadas. A lista de workflows experimentais nas PRs #172, #175 é *candidata*, não comando autorizado.

**Falhas previsíveis/correcções:** assinatura errada → descartar a imagem; root ISO não visível → corrigir initramfs/handoff antes de escrever; UUID errado → bloquear; ausência de slot MBR → bloquear, não mexer em EBR; instalador tenta reformatar ESP/Windows → bloquear; bootloader incompleto → restaurar só ficheiros possuídos e confirmar Windows; update altera entrada Windows → reverter com checkpoint e negar sucesso.

**Interrupção obrigatória:** qualquer geometria, hash, conta, firma/assinatura, Secure Boot, propriedade, WinRE/BCD ou estado de recuperação não comprovado; Windows sem boot validado; tentativa de usar disco físico; parâmetros, caminhos de ISO ou opções unattended desconhecidos.

**Provas de conclusão:** SHA commit, PR, workflow/run, artefactos e respectivos SHA-256, cadeia de assinatura upstream, serial/GUID/offsets, pré/pós Windows BCD/WinRE/EFI/MBR, arranques Linux e Windows pós-instalação e pós-update, remoção, rollback e relatório independente. **Nunca declarar estável sem a matriz completa.**
