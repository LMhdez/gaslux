# Zorin OS — ONE-SHOT backend dossier

> **Atualização de navegação (22-11-2026):** este dossier mantém a análise histórica de 19-11. Revalidar HEADs, PRs/merges, media e artefactos antes de usar as propostas. Ver [histórico e instruções por agente](../AGENT_HISTORICAL_PLAYBOOK.md), [índice GitHub Actions/VM](../CI_VM_EVIDENCE_INDEX.md) e [contratos partilhados](SHARED_CONTRACTS.md). Propostas antigas de criação de branch/PR não substituem a regra atual de reutilização e consolidação; testes QEMU descartáveis têm autorização delimitada em [AGENTS](../../AGENTS.md).

**Revisão:** 2026-11-19. **Maturidade:** IMPLEMENTADO: entrada no catálogo main e runtime de família Ubuntu; instalação integral em todos os cenários e rollback continuam dependentes de prova real. Ver [contratos gerais](SHARED_CONTRACTS.md). **Não usar este documento como autorização de escrita.**

## 1. Resumo executivo e estado
A regeneração de initramfs em laboratório Zorin não equivale a uma actualização de kernel/GRUB em dual boot. O objectivo é uma instalação nativa automatizada ao lado do Windows, com prova independente dos dois boots e recuperação. Compatibilidade upstream não equivale a suporte validado no Gaslux.

## 2. Fontes oficiais, versões e proveniência
- [Origem oficial/media](https://mirrors.univ-reims.fr/IMAGES/zorinos/18/Zorin-OS-18.1-Core-64-bit.iso) — versão/release: **18.1 Core**. [DOCUMENTADO como endereço de referência; revalidar disponibilidade, conteúdo e assinatura na data da execução.]
- [Documentação upstream](https://help.zorin.com/docs/getting-started/install-zorin-os/) — instruções gerais, não aprovação de boot sem USB. [DOCUMENTADO; verificar versão, data e parâmetros antes de automatizar.]
- [Configuração Gaslux main](https://github.com/LMhdez/gaslux/blob/main/release-config.json) — fonte dos metadados exactos da ISO. [IMPLEMENTADO]
- [Arquitectura Gaslux](https://github.com/LMhdez/gaslux/blob/dev/docs/ARCHITECTURE.md), [contratos de segurança Mint/Zorin](../ARCHITECTURE.md) e [PR multidistro #7](https://github.com/LMhdez/gaslux/pull/7). [IMPLEMENTADO/critério documental]
- PRs/threads experimentais relacionadas: [#167](https://github.com/LMhdez/gaslux/pull/167), [#181](https://github.com/LMhdez/gaslux/pull/181), [#219](https://github.com/LMhdez/gaslux/pull/219). **Consultar HEAD, estado de merge, logs e branches antes de reutilizar.**
- Evidência histórica de CI para contexto: [Actions](https://github.com/LMhdez/gaslux/actions/runs/44147851404); a existência ou êxito do workflow não certifica todas as etapas. [PENDENTE: rever job e artefactos exactos.]

## 3. Arquitectura de arranque
**Estratégia:** GRUB BIOS e GRUB EFI com shim conforme binários assinados presentes. **Modo:** BIOS/MBR e UEFI/GPT na infraestrutura existente; exigir prova fim-a-fim independente.
[DOCUMENTADO/pendente por mídia] Em BIOS o arranque envolve MBR/PBR, BCD e eventual cadeia GRUB; em UEFI começa em entradas NVRAM/ESP, sem sobrepor `EFI/Microsoft`. Os caminhos são mutuamente distintos. Recusar associações firmware/tabela não ensaiadas. Não alterar chaves Secure Boot ou privilégios de arranque automaticamente.

## 4. Estrutura, identidade e autenticação da ISO
- Artefacto: `Zorin-OS-18.1-Core-64-bit.iso`.
- SHA-256 fixado: `44649b97bd307fc4c8529205d098ebbf98575a1e1ba2ee7d7005b697af1721d5`; tamanho exacto: `3909091328` bytes. [IMPLEMENTADO — release-config.json/main; revalidar assinatura real do catálogo e hash da imagem descarregada].
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
**Instalador:** instalador Ubuntu/Zorin realmente presente na ISO 18.1; nome, versão e automatização exactos requerem inspecção da imagem.
**Mecanismo previsto:** Preservar o backend Ubuntu existente, verificar layout squashfs e binários na ISO; unattended apenas após comparar mecanismos reais do instalador.
[INVESTIGAR] Ler fontes upstream/versão binária efectiva, argumentos ou API suportados, modo unattended, ficheiros YAML/JSON/scripts declarados, mapeamento de contas/UID, locale, teclado, fuso horário, password hashing e grupos, pacote manager, formatos root/ESP e tratamento de erros. Não usar cliques por coordenadas sem estado observável: identificar janelas/elementos e pré/pós-condições; qualquer click manual não é estratégia de produção unattended. Não escrever um pseudo-instalador que só copia raiz Live.

## 7. Particionamento e protecção de Windows
[CONTRATO] Capturar disk serial, firmware, tabela e sector real; comparar GUIDs/assinatura, início/tamanho exacto em bytes e todas as partições; possuir explicitamente cada intervalo afectado. Nunca mudar ESP/EFI Windows, OEM, Recovery, WinRE, BCD, BitLocker/Device Encryption ou discos não seleccionados. MBR: validar quatro slots, primária activa, partição estendida/lógicas/EBR e endereçamento; recusar qualquer cadeia EBR sem método testado. GPT: validar primária/secundária, GUIDs, ESP, NVRAM e limite do resize. Segundo disco exige o mesmo nível de identificação e prova de boot. [BLOQUEADO quando não comprovado]

## 8. Configuração instalada e primeiro boot
Validar ID zorin, root UUID, conta, GRUB, Windows Boot Manager e segunda inicialização após update. [PENDENTE — exigir evidência de comandos executados no convidado, versões e verificações independentes] Aplicar locale, teclado, timezone, password e permissões de forma transaccional; verificar também instalação real de pacotes, serviços, fstab por UUID e root montada. Sem ISO montada no boot de aceitação.

## 9. Bootloader, kernel e manutenção
GRUB BIOS e GRUB EFI com shim conforme binários assinados presentes. Manter Windows Boot Manager intacto, cópias EFI/boot code apenas onde a transacção detenha posse, e entradas Windows válidas. Revalidar entradas e hashes antes/depois da instalação e de cada update de kernel/loader. Hooks APT/dpkg de Mint/Zorin não são transferíveis sem adaptação a pacman, distinst ou Atomic. [PENDENTE — prova por distro]

## 10. Actualizações e desinstalação
Testar upgrade de pacotes, regeneração de initramfs, kernel novo, loader novo, reboot Linux, reboot Windows e operação de remoção. Backup imutável de EFI/BCD/MBR/NVRAM e ownership por transacção; a desinstalação não pode apagar um artefacto partilhado/unowned. Reinicializar a verificação Windows/WinRE após remoção. [PENDENTE — não inferir de update numa raiz Linux isolada]

## 11. Recuperação e rollback
Antes da mutação: baseline geométrico/WinRE/BCD/ESP ou MBR, encriptação, estado boot, hashes, snapshot de VM e recovery runtime. Em cada fase: checkpoint durável; em falha, compensação inversa apenas sobre recursos possuídos, revalidar disco e sector, recuperar arranque e medir o Windows após reinício verdadeiro. Queda de energia e falha parcial EFI/rede são testes obrigatórios. Sem arranque Windows e comparações de integridade não existe rollback COMPROVADO. [BLOQUEADO para hardware real]

## 12. Código Gaslux reutilizável
[IMPLEMENTADO — caminhos confirmados pela documentação do projecto; conferir conteúdo/ref de cada um] `Installation/` (plano/ledger), `Scripts/modules/` (PowerShell, storage/rollback), `Scripts/uefi/`, `assets/live/` (verificação/handoff/first boot), `schemas/`, `iso-tools/`, `Libertix.Tests/`, `PowerShell.Tests/`, `auto_tests/`. Preservar o fluxo Mint/Zorin e separar módulos específicos da família Linux.

## 13. PRs, branches e commits a reutilizar
#167, #181, #219. Resolver IDs, HEADs, base empilhada e diffs efectivos no momento da implementação; não aplicar commits de PR antigos cegamente. A PR #7 foi integrada em `dev`; `main` não contém necessariamente o mesmo `AGENTS.md`. Reaproveitar somente partes cujo comportamento foi confirmado e não duplicar guardas.

## 14. Problemas conhecidos e causas
A regeneração de initramfs em laboratório Zorin não equivale a uma actualização de kernel/GRUB em dual boot. Problemas gerais: parâmetros de initramfs desconhecidos, Windows ISO/UEFI prompt, discos que mudam de ordem, entrada NVRAM que não persiste, partição estendida difícil de compensar, confiança Secure Boot incompleta, instaladores que reformatam ESP/Windows por defeito. A causa exacta de uma falha é PENDENTE até log + reprodução + commit.

## 15. Soluções tecnicamente verificadas vs. hipóteses
[IMPLEMENTADO] Existem protecções de plano, state ledger, catálogo assinado e caminhos firmware Gaslux (ver ARCHITECTURE). [PENDENTE] A adaptação ao instalador Zorin OS e estratégia USB-free do artefacto exacto não estão comprovadas nesta investigação. Não confundir existência de scripts com execução de instalação nativa.

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
- [Actions histórica](https://github.com/LMhdez/gaslux/actions/runs/44147851404): **COMPROVADO somente para as verificações que o job e os artefactos realmente contêm**, e sujeito a revalidação do HEAD actual.
- [ISSUE #3](https://github.com/LMhdez/gaslux/issues/3) indica gates não resolvidos; PRs citadas acima oferecem trabalho experimental, não prova universal.
- [PENDENTE] Associar manifesto de artefactos, digest, SHA exacto do workflow e nível de evidência (fixtures vs Live vs instalado vs dual boot vs rollback).

## 18. Testes adicionais obrigatórios
Lint/documentação e contratos C#/Pester/Python/Bash; autenticação ISO offline; VM descartável com ISO real; primeiro boot sem ISO; Windows 10 BIOS/MBR onde elegível, Windows 10 e 11 UEFI/GPT; disco único/segundo disco, partições complexas, Secure Boot admissível; update/reboot de kernel e loader; reinstall/uninstall; falhas de hash, disco permutado, ISO truncada, rede ausente, SIGKILL/power-cut e recovery BCD/WinRE. Escritas somente em VM autorizada, sem discos host. [PENDENTE]

## 19. Plano incremental de implementação
(1) Confirmar HEAD e upstream/media fixada; (2) automatizar inspecção read-only + hashes; (3) testes negativos dos gates; (4) validar handoff em Live; (5) autorizar escritor apenas sobre VM com snapshot e identidade comprovada; (6) executar instalador real; (7) provar primeiro boot sem ISO; (8) dual boot Windows; (9) update e reboot; (10) rollback completo; (11) revisão humana. Cada etapa deve deixar evidência ligada a commit, run, artefactos e manifestos; nunca continuar numa falha.

## 20. Critério objectivo de estabilidade
Não basta existir ISO/hash válido, CI verde, Live boot ou raiz extraída. Requer ISO oficial autenticada, instalação nativa de Zorin OS numa VM descartável Windows realmente instalado, boot Linux e Windows independentes, kernel/bootloader actualizados, Windows WinRE/BCD/ESP preservados, uninstall e rollback completos, incluindo injecção de falhas e testes negativos dos layouts suportados. Hardware só depois de backup/restauro sob autorização explícita.

---

## Anexo técnico — Zorin 18.1, ISO e dupla inicialização isolada (19-11-2026)

### Base e autenticidade
[DOCUMENTADO] [Zorin OS 18.1](https://zorin.com/os/details/) usa base Ubuntu 24.04 LTS. O [guia oficial de integridade Zorin](https://help.zorin.com/docs/getting-started/check-the-integrity-of-your-copy-of-zorin-os/) publica exactamente o SHA-256 `44649b97bd307fc4c8529205d098ebbf98575a1e1ba2ee7d7005b697af1721d5` para **18.1 Core x64**; corresponde a `main/release-config.json` (3 909 091 328 bytes). O guia público descreve hash, **não demonstra neste ponto uma assinatura GPG detached específica da ISO**. [PENDENTE] Se for exigida proveniência criptográfica upstream mais forte, obter e verificar um manifesto assinado genuíno, não inventar chave.

### Instalador e desenho real do Gaslux
[DOCUMENTADO] O upstream descreve interface de instalação em [Zorin Help](https://help.zorin.com/docs/getting-started/install-zorin-os/). Existem referências contraditórias entre variantes/versões à família Ubiquity/Subiquity; [PENDENTE] obter `dpkg-query`, caminhos do executável, `--version`, manifestos e ficheiros de configuração **da ISO 18.1 Core SHA acima** antes de afirmar um nome/API unattended. A base Ubuntu não determina automaticamente o instalador. O backend Gaslux partilha o `debian-squashfs` de Mint e testa dpkg, `update-grub` e `update-initramfs`; isso prova capacidades da raiz, não a UI/CLI nativa. Se o instalador oficial reescrever a ESP por defeito, é **BLOQUEADO** até existir controlo estrito sobre o write-set.

### Resultado reproduzível de laboratório
[COMPROVADO — OVMF isolado] [PR #224](https://github.com/LMhdez/gaslux/pull/224), HEAD `3a10dac2d85dd19849a0736d8f57558827277794`, consolidou #219. [Run #44582546627](https://github.com/LMhdez/gaslux/actions/runs/44582546627), job `genuine-second-boot`, **SUCCESS**, [artefacto #14560995967](https://github.com/LMhdez/gaslux/actions/runs/44582546627/artifacts/14560995967): ISO oficial validada por tamanho/hash, raiz Zorin em GPT isolada, arranque sem ISO, regeneração de `initramfs` instalado e segundo login série no mesmo disco. Log mostra `vmlinuz-6.17.0-20-generic` e `update-initramfs: Generating /boot/initrd.img-6.17.0-20-generic`, com mensagens `cryptsetup` sobre sysfs ausente; registar como diagnóstico, não ocultar. Workflow real [`.github/workflows/zorin-installed-initramfs-reboot.yml`](https://github.com/LMhdez/gaslux/blob/3a10dac2d85dd19849a0736d8f57558827277794/.github/workflows/zorin-installed-initramfs-reboot.yml) usa `auto_tests/tools/gaslux_zorin_installed_target_lab.sh` e exige `installedZorinInitramfsRegenerationRebootVerified=true`.

**Não comprovado:** instalação executada pelo instalador nativo, Windows nesse disco, actualização do pacote kernel (apenas rebuild initramfs), GRUB de produção, Windows Boot Manager, BIOS/MBR, reentrada/rollback. [PENDENTE] localizar nome/versionamento do instalador 18.1 na imagem autenticada e definir interface de automatização suportada.

### Sequência de acções do agente
1. Inspeccionar apenas leitura: lista de `casper`, manifestos dpkg do SquashFS, `os-release`, nomes da UI/CLI do instalador e assinatura/versão; guardar resultados ligados ao hash.
2. Reutilizar `gaslux_zorin_installed_target_lab.sh` da PR #224 para **provas de boot isolado**, nunca como substituto da transacção Gaslux.
3. Preparar Windows real descartável com propriedade GPT e restore point, executar instalação Gaslux no intervalo possuído e comparar hashes WinRE/BCD/ESP; sem autorização de reformatar ESP Windows.
4. Arrancar Zorin, Windows, fazer upgrade real de kernel, repetir dois boots, remover apenas recursos próprios e validar Windows. Qualquer divergência implica STOP e rollback verificável.

---

## ONE-SHOT EXECUTION PLAYBOOK
**Pré-requisitos exactos:** acesso GitHub conta LMHDEZ, HEAD `dev` confirmado, `AI_POLICY.md`, `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/distro-backends/SHARED_CONTRACTS.md`, mídia oficial e digest/assinatura validados; runner VM descartável com QEMU/SeaBIOS/OVMF conforme firmware e snapshot recuperável. Sem estes elementos, STOP.

**Branch recomendada:** `feature/zorin-native-backend-verified` a partir do HEAD revisto de `dev`, evitando branches empilhadas obsoletas. **PRs candidatas:** #167, #181, #219. Verificar SHA/head/diff antes do cherry-pick.

**Ficheiros a inspeccionar e possivelmente alterar apenas numa futura PR funcional:** `Installation/`, `Scripts/modules/`, `Scripts/uefi/`, `assets/live/`, `schemas/`, adaptadores de distro e testes. **Não alterar sem gates:** `release-config.json` estável, `EFI/Microsoft`, boot Windows, partições alheias, assinaturas/catálogo e contratos Mint/Zorin.

**Interfaces obrigatórias:** preflight tipado → catálogo assinado/ISO validada → plano e ledger duráveis → handoff autenticado → provisioning de target possuído → instalador nativo → bootloader da distribuição → first-boot evidence → verificação Windows → manutenção/uninstall/rollback.

**Execução faseada e testes:** primeiro `ruff check`, `pytest`, `dotnet test`, Pester e ShellCheck conforme workflows existentes e HEAD; verificar nomes e argumentos reais dos workflows antes de executar. Seguidamente lançar apenas workflow explicitamente autorizado com VM descartável, snapshot e hash. Sucesso de cada fase exige relatório de identidade, logs independentes e hashes; nunca métricas auto-reportadas. A lista de workflows experimentais nas PRs #167, #181, #219 é *candidata*, não comando autorizado.

**Falhas previsíveis/correcções:** assinatura errada → descartar a imagem; root ISO não visível → corrigir initramfs/handoff antes de escrever; UUID errado → bloquear; ausência de slot MBR → bloquear, não mexer em EBR; instalador tenta reformatar ESP/Windows → bloquear; bootloader incompleto → restaurar só ficheiros possuídos e confirmar Windows; update altera entrada Windows → reverter com checkpoint e negar sucesso.

**Interrupção obrigatória:** qualquer geometria, hash, conta, firma/assinatura, Secure Boot, propriedade, WinRE/BCD ou estado de recuperação não comprovado; Windows sem boot validado; tentativa de usar disco físico; parâmetros, caminhos de ISO ou opções unattended desconhecidos.

**Provas de conclusão:** SHA commit, PR, workflow/run, artefactos e respectivos SHA-256, cadeia de assinatura upstream, serial/GUID/offsets, pré/pós Windows BCD/WinRE/EFI/MBR, arranques Linux e Windows pós-instalação e pós-update, remoção, rollback e relatório independente. **Nunca declarar estável sem a matriz completa.**


## Actualização de reconciliação da evidência (2026-11-22 UTC)

A [PR #277](https://github.com/LMhdez/gaslux/pull/277) foi encerrada sem merge; a [PR #281](https://github.com/LMhdez/gaslux/pull/281) continua draft, HEAD `79264bd147f5d3e71de59b0f126e5906cfafa52e` e depende historicamente de #277 → #264. A [CI #45021477864](https://github.com/LMhdez/gaslux/actions/runs/45021477864) demonstrou que oito ficheiros sintéticos podem ser copiados para o `dev` `8e68a475d6397ba8fef2e0f9f83758545e202a5f` e testados com o reader canónico #307, sem incorporar o backend experimental #264. A branch `integration/zorin-277-281-fd-nowriter-dev-20261122` isola esta evidência; é uma contribuição de diagnóstico, **não** autorização de escrita. A instalação Zorin, dual boot, actualização, recuperação Windows e estabilidade requerem provas E2E separadas.

**Nota de HEAD (22-11-2026 13:55 UTC):** a branch #281 avançou para `a26c0cda741323f0d4457aa662daa85279e726e5` após a execução `45021477864` no commit `79264bd147f5d3e71de59b0f126e5906cfafa52e`. Os quatro ficheiros operacionais (verificador, dois testes e schema) mantiveram exatamente os mesmos Git blob SHAs nesta mudança; a documentação evoluiu. A CI `45021477864` não deve ser atribuída a `a26c0cda` sem check próprio.
