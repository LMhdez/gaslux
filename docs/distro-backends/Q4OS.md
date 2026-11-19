# Q4OS — ONE-SHOT backend dossier

**Revisão:** 2026-11-19. **Maturidade:** EXPERIMENTAL / PENDENTE: não autorizado para catálogo estável. Ver [contratos gerais](SHARED_CONTRACTS.md). **Não usar este documento como autorização de escrita.**

## 1. Resumo executivo e estado
Teste QMP teclado com Windows DVD bloqueado no prompt não demonstra Windows Setup; não repetir esperas cegas. O objectivo é uma instalação nativa automatizada ao lado do Windows, com prova independente dos dois boots e recuperação. Compatibilidade upstream não equivale a suporte validado no Gaslux.

## 2. Fontes oficiais, versões e proveniência
- [Origem oficial/media](https://q4os.org/downloads1.html) — versão/release: **não fixada no catálogo estável**. [DOCUMENTADO como endereço de referência; revalidar disponibilidade, conteúdo e assinatura na data da execução.]
- [Documentação upstream](https://q4os.org/dqa014.html) — instruções gerais, não aprovação de boot sem USB. [DOCUMENTADO; verificar versão, data e parâmetros antes de automatizar.]
- [Configuração Gaslux main](https://github.com/LMhdez/gaslux/blob/main/release-config.json) — não contém esta distribuição. [IMPLEMENTADO]
- [Arquitectura Gaslux](https://github.com/LMhdez/gaslux/blob/dev/docs/ARCHITECTURE.md), [Issue de estabilidade #3](https://github.com/LMhdez/gaslux/issues/3) e [PR multidistro #7](https://github.com/LMhdez/gaslux/pull/7). [IMPLEMENTADO/critério documental]
- PRs/threads experimentais relacionadas: [#59](https://github.com/LMhdez/gaslux/pull/59), [#207](https://github.com/LMhdez/gaslux/pull/207), [#210](https://github.com/LMhdez/gaslux/pull/210), [#220](https://github.com/LMhdez/gaslux/pull/220), [#226](https://github.com/LMhdez/gaslux/pull/226). **Consultar HEAD, estado de merge, logs e branches antes de reutilizar.**
- Evidência histórica de CI para contexto: [Actions](https://github.com/LMhdez/gaslux/actions/runs/44476677560); a existência ou êxito do workflow não certifica todas as etapas. [PENDENTE: rever job e artefactos exactos.]

## 3. Arquitectura de arranque
**Estratégia:** GRUB BIOS/EFI conforme a ISO e instalação nativa; rever actualizações e localização exacta da instalação. **Modo:** BIOS/MBR e UEFI/GPT a provar para mídia/versão; sem provas de end-to-end.
[DOCUMENTADO/pendente por mídia] Em BIOS o arranque envolve MBR/PBR, BCD e eventual cadeia GRUB; em UEFI começa em entradas NVRAM/ESP, sem sobrepor `EFI/Microsoft`. Os caminhos são mutuamente distintos. Recusar associações firmware/tabela não ensaiadas. Não alterar chaves Secure Boot ou privilégios de arranque automaticamente.

## 4. Estrutura, identidade e autenticação da ISO
- Artefacto: `PENDENTE: identificar ISO Live/Install oficial fixada`.
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
**Instalador:** Calamares SE estiver realmente na ISO verificada, caso contrário instalador nativo que a edição efectivamente forneça.
**Mecanismo previsto:** Distinguir instalador Windows-in-folder de instalação nativa particionada; inspeccionar conteúdo e CLI/config do Calamares exacto antes de autorizar gravações.
[INVESTIGAR] Ler fontes upstream/versão binária efectiva, argumentos ou API suportados, modo unattended, ficheiros YAML/JSON/scripts declarados, mapeamento de contas/UID, locale, teclado, fuso horário, password hashing e grupos, pacote manager, formatos root/ESP e tratamento de erros. Não usar cliques por coordenadas sem estado observável: identificar janelas/elementos e pré/pós-condições; qualquer click manual não é estratégia de produção unattended. Não escrever um pseudo-instalador que só copia raiz Live.

## 7. Particionamento e protecção de Windows
[CONTRATO] Capturar disk serial, firmware, tabela e sector real; comparar GUIDs/assinatura, início/tamanho exacto em bytes e todas as partições; possuir explicitamente cada intervalo afectado. Nunca mudar ESP/EFI Windows, OEM, Recovery, WinRE, BCD, BitLocker/Device Encryption ou discos não seleccionados. MBR: validar quatro slots, primária activa, partição estendida/lógicas/EBR e endereçamento; recusar qualquer cadeia EBR sem método testado. GPT: validar primária/secundária, GUIDs, ESP, NVRAM e limite do resize. Segundo disco exige o mesmo nível de identificação e prova de boot. [BLOQUEADO quando não comprovado]

## 8. Configuração instalada e primeiro boot
Verificar ID Q4OS, root UUID, GRUB e Windows; instalar nativamente na VM e reiniciar sem ISO. [PENDENTE — exigir evidência de comandos executados no convidado, versões e verificações independentes] Aplicar locale, teclado, timezone, password e permissões de forma transaccional; verificar também instalação real de pacotes, serviços, fstab por UUID e root montada. Sem ISO montada no boot de aceitação.

## 9. Bootloader, kernel e manutenção
GRUB BIOS/EFI conforme a ISO e instalação nativa; rever actualizações e localização exacta da instalação. Manter Windows Boot Manager intacto, cópias EFI/boot code apenas onde a transacção detenha posse, e entradas Windows válidas. Revalidar entradas e hashes antes/depois da instalação e de cada update de kernel/loader. Hooks APT/dpkg de Mint/Zorin não são transferíveis sem adaptação a pacman, distinst ou Atomic. [PENDENTE — prova por distro]

## 10. Actualizações e desinstalação
Testar upgrade de pacotes, regeneração de initramfs, kernel novo, loader novo, reboot Linux, reboot Windows e operação de remoção. Backup imutável de EFI/BCD/MBR/NVRAM e ownership por transacção; a desinstalação não pode apagar um artefacto partilhado/unowned. Reinicializar a verificação Windows/WinRE após remoção. [PENDENTE — não inferir de update numa raiz Linux isolada]

## 11. Recuperação e rollback
Antes da mutação: baseline geométrico/WinRE/BCD/ESP ou MBR, encriptação, estado boot, hashes, snapshot de VM e recovery runtime. Em cada fase: checkpoint durável; em falha, compensação inversa apenas sobre recursos possuídos, revalidar disco e sector, recuperar arranque e medir o Windows após reinício verdadeiro. Queda de energia e falha parcial EFI/rede são testes obrigatórios. Sem arranque Windows e comparações de integridade não existe rollback COMPROVADO. [BLOQUEADO para hardware real]

## 12. Código Gaslux reutilizável
[IMPLEMENTADO — caminhos confirmados pela documentação do projecto; conferir conteúdo/ref de cada um] `Installation/` (plano/ledger), `Scripts/modules/` (PowerShell, storage/rollback), `Scripts/uefi/`, `assets/live/` (verificação/handoff/first boot), `schemas/`, `iso-tools/`, `Libertix.Tests/`, `PowerShell.Tests/`, `auto_tests/`. Preservar o fluxo Mint/Zorin e separar módulos específicos da família Linux.

## 13. PRs, branches e commits a reutilizar
#59, #207, #210, #220, #226. Resolver IDs, HEADs, base empilhada e diffs efectivos no momento da implementação; não aplicar commits de PR antigos cegamente. A PR #7 foi integrada em `dev`; `main` não contém necessariamente o mesmo `AGENTS.md`. Reaproveitar somente partes cujo comportamento foi confirmado e não duplicar guardas.

## 14. Problemas conhecidos e causas
Teste QMP teclado com Windows DVD bloqueado no prompt não demonstra Windows Setup; não repetir esperas cegas. Problemas gerais: parâmetros de initramfs desconhecidos, Windows ISO/UEFI prompt, discos que mudam de ordem, entrada NVRAM que não persiste, partição estendida difícil de compensar, confiança Secure Boot incompleta, instaladores que reformatam ESP/Windows por defeito. A causa exacta de uma falha é PENDENTE até log + reprodução + commit.

## 15. Soluções tecnicamente verificadas vs. hipóteses
[IMPLEMENTADO] Existem protecções de plano, state ledger, catálogo assinado e caminhos firmware Gaslux (ver ARCHITECTURE). [PENDENTE] A adaptação ao instalador Q4OS e estratégia USB-free do artefacto exacto não estão comprovadas nesta investigação. Não confundir existência de scripts com execução de instalação nativa.

## 16. Matriz de compatibilidade
| Ambiente | Compatibilidade no Gaslux | Gate |
|---|---|---|
| Windows 10 BIOS/MBR | PENDENTE | slots/EBR/sector real/MBR/PBR/BCD |
| Windows 10 UEFI/GPT | PENDENTE | ESP/NVRAM/BCD/WinRE/Windows boot |
| Windows 11 UEFI/GPT | PENDENTE | TPM/BitLocker/ESP/WinRE/Secure Boot |
| Segundo disco | PENDENTE | serial real e BootOrder independente |
| Secure Boot | PENDENTE conforme versão e chaves de firmware | prova de loader instalado, sem enrollment manual |
| BIOS/GPT ou UEFI/MBR | BLOQUEADO sem teste explícito | nunca converter automaticamente |

## 17. Testes existentes e evidências
- [Actions histórica](https://github.com/LMhdez/gaslux/actions/runs/44476677560): **COMPROVADO somente para as verificações que o job e os artefactos realmente contêm**, e sujeito a revalidação do HEAD actual.
- [ISSUE #3](https://github.com/LMhdez/gaslux/issues/3) indica gates não resolvidos; PRs citadas acima oferecem trabalho experimental, não prova universal.
- [PENDENTE] Associar manifesto de artefactos, digest, SHA exacto do workflow e nível de evidência (fixtures vs Live vs instalado vs dual boot vs rollback).

## 18. Testes adicionais obrigatórios
Lint/documentação e contratos C#/Pester/Python/Bash; autenticação ISO offline; VM descartável com ISO real; primeiro boot sem ISO; Windows 10 BIOS/MBR onde elegível, Windows 10 e 11 UEFI/GPT; disco único/segundo disco, partições complexas, Secure Boot admissível; update/reboot de kernel e loader; reinstall/uninstall; falhas de hash, disco permutado, ISO truncada, rede ausente, SIGKILL/power-cut e recovery BCD/WinRE. Escritas somente em VM autorizada, sem discos host. [PENDENTE]

## 19. Plano incremental de implementação
(1) Confirmar HEAD e upstream/media fixada; (2) automatizar inspecção read-only + hashes; (3) testes negativos dos gates; (4) validar handoff em Live; (5) autorizar escritor apenas sobre VM com snapshot e identidade comprovada; (6) executar instalador real; (7) provar primeiro boot sem ISO; (8) dual boot Windows; (9) update e reboot; (10) rollback completo; (11) revisão humana. Cada etapa deve deixar evidência ligada a commit, run, artefactos e manifestos; nunca continuar numa falha.

## 20. Critério objectivo de estabilidade
Não basta existir ISO/hash válido, CI verde, Live boot ou raiz extraída. Requer ISO oficial autenticada, instalação nativa de Q4OS numa VM descartável Windows realmente instalado, boot Linux e Windows independentes, kernel/bootloader actualizados, Windows WinRE/BCD/ESP preservados, uninstall e rollback completos, incluindo injecção de falhas e testes negativos dos layouts suportados. Hardware só depois de backup/restauro sob autorização explícita.

---

## Anexo técnico — Q4OS 6.10 r2, Calamares nativo e risco EFI fallback (19-11-2026)

### Versão de ISO real e proveniência
[IMPLEMENTADO em `dev`, fora do catálogo estável] [`.github/workflows/gaslux-q4os-official-iso.yml`](https://github.com/LMhdez/gaslux/blob/dev/.github/workflows/gaslux-q4os-official-iso.yml) fixa a ISO **Q4OS 6.10 r2 x64**, URL `https://downloads.sourceforge.net/project/q4os/stable/q4os-6.10-x64.r2.iso`, SHA-256 `1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d`. A página [SourceForge do artefacto](https://sourceforge.net/projects/q4os/files/stable/q4os-6.10-x64.r2.iso/download) divulga o digest; o workflow verifica tamanho **por intervalo** (entre 1,5 e 3 GB), não grava tamanho exacto fixado. [PENDENTE] Registar tamanho exacto e assinatura upstream independente (se existir) antes de atribuir nível de trust para release. Não está em `release-config.json`.

[DOCUMENTADO/IMPLEMENTADO a partir da ISO de laboratório] O workflow lê a ISO `ro`, localiza `live/*.squashfs`, extrai `etc/os-release` com **ID=debian**, VERSION_ID=13, além de marcador Q4OS separado; o facto de `ID != q4os` é esperado nesta edição. O [`gaslux_q4os_preflight.py`](https://github.com/LMhdez/gaslux/blob/dev/assets/live/gaslux_q4os_preflight.py) valida ID Debian 13 e `q4os_version`, mas explicita `q4osIdentityBoundToIso=false` sem a ligação criptográfica ao payload. Diferenciar média [Live vs instalação nativa](https://q4os.org/downloads1.html) e WinSetup/instalação em pasta Windows: o WinSetup não prova particionamento nativo.

### Boot exacto de laboratório e instalador identificado
[IMPLEMENTADO em PR #256] [`gaslux_q4os_calamares_gui_laboratory.sh`](https://github.com/LMhdez/gaslux/blob/6b6d5521dbd4c2c26712fb57cb6ae5b29e0c69bb/auto_tests/tools/gaslux_q4os_calamares_gui_laboratory.sh) monta a ISO em leitura e exige exactamente um `live/vmlinuz-<versão>` e `live/initrd.img-<versão>`. Gera GRUB EFI de laboratório que procura kernel com `search --no-floppy --file` e usa `boot=live components` com consola série. Isso foi concebido para QEMU/OVMF, **não** constitui caminho de boot Windows sem USB já aceite. [PENDENTE] Registar conteúdo ISO El Torito, GRUB, EFI/BIOS e drivers NTFS/staging no initramfs real da versão.

[IMPLEMENTADO — auditor de configuração extraída] [`assets/live/gaslux_q4os_calamares_policy.py`](https://github.com/LMhdez/gaslux/blob/6b6d5521dbd4c2c26712fb57cb6ae5b29e0c69bb/assets/live/gaslux_q4os_calamares_policy.py) valida configuração da ISO 6.10 com `etc/q4os_version=6.10-deb13u1`, ficheiros `/etc/calamares/settings.conf` e `/etc/calamares/modules/{partition,unpackfs,mount,fstab,bootloader,grubcfg,users,packages,displaymanager}.conf`. A execução real de Calamares passa por `partition → mount → unpackfs → q4oshook2 → grubcfg → bootloader → q4oshook3 → packages → initramfs → q4oshook5 → umount`, entre outras etapas; a origem da cópia é **`/run/live/medium/live/filesystem.squashfs`**, root `ext4`, ESP `/boot/efi`, gestor de pacotes `apt`, e `grubInstall=grub-install`. Esta descrição está ligada ao auditor específico da ISO e **não implica que Calamares já tenha sido autorizado ou executado**. [PENDENTE] Enumerar versão executável Calamares, GUI object IDs e argumentos de automação real sem partir do pressuposto de que clicks fixos servem.

### Risco confirmado por configuração: substituição de EFI/BOOT
[BLOQUEADO até mitigação demonstrada] O auditor identifica `installEFIFallback=true` na configuração do bootloader nativo da ISO. Executar Calamares directamente numa ESP Windows partilhada **poderia sobrescrever `EFI/BOOT/BOOTX64.EFI`**, mesmo sem tocar em `EFI/Microsoft`. Um instalador seguro tem de desligar/encapsular o fallback de forma verificável, manter checksums EFI antes/depois e usar apenas artefactos com ownership. `windowsEspFallbackWriteAuthorized=false` é a política do auditor. Não basta preservar `bootmgfw.efi`.

### Caminho gráfico já investigado
[IMPLEMENTADO — GUI lab, sem escritor] [PR #256](https://github.com/LMhdez/gaslux/pull/256), HEAD `6b6d5521dbd4c2c26712fb57cb6ae5b29e0c69bb`: os gates `GASLUX_Q4OS_LAUNCH_INSTALLER`, `ADVANCE_WELCOME`, `ADVANCE_LOCATION`, `ADVANCE_KEYBOARD`, `SELECT_SOFTWARE`, `ADVANCE_SOFTWARE`, `ADVANCE_PARTITIONS`, `NATIVE_COW_VIEW_ONLY` exigem pré-condições encadeadas e ecrãs verificados com VNC/OCR. Os passos são observação condicionada, **não instalação**. A PR #256 consolida hardening dos manifestos de evidência contra symlinks via `O_NOFOLLOW`/`O_DIRECTORY`, não executa Calamares sobre Windows. Investigar object IDs reais via Calamares e introspecção; na ausência de API unattended confiável, BLOQUEADO.

### Próxima execução e critérios de paragem
1. Repetir ISO 6.10 com SHA fixo, extrair os ficheiros Calamares para auditoria read-only e ligar hashes de cada módulo ao ISO certificado.
2. Determinar a alteração controlada `installEFIFallback=false`/método de boot que não escreva caminhos Windows ou EFI fallback sem autorização; testar fail-closed em fixtures e QEMU ESP sintética, **sem alterar ESP Windows**.
3. Mapear as páginas Welcome→Location→Keyboard→Software→Partitions→Users→Summary e identificadores/validadores da UI, com prova screenshot/manifesto por transição. Não usar coordenadas absolutas como API estável.
4. Apenas com write-set autenticado e recuperação preparada, autorizar Calamares numa VM descartável com Windows real; validar boot de ambos e WinRE/BCD/EFI, updates/reinstalação/desinstalação/rollback in-place.
5. Em caso de instalador tentar criar novo layout, escrever fallback EFI, tocar OEM/Recovery ou falhar identidade de disco, **STOP**. O hash ISO por si só não autoriza um disco.

---

### Sequência verificável de cliques e validadores da GUI Q4OS (apenas VM de ensaio)
[IMPLEMENTADO em `auto_tests/tools/gaslux_q4os_calamares_gui_laboratory.sh`, PR #256, linhas 338–510] Cada transição parte de um PNG capturado por VNC, comparação `changed-centre`, `visual_gate` de identidade da página e, se aplicável, SHA de origem. **As coordenadas abaixo são exclusivas da resolução/gráfico da VM do ensaio; não constituem uma API estável nem comandos para o utilizador.**

| Pré-estado identificado | Ponto VNC ensaiado (x,y) | Acção apenas permitida | Pós-condição exigida |
|---|---:|---|---|
| Modal do primeiro arranque Q4OS | (585,391) | `OK`, condicionado ao SHA exacto do modal | Modal desapareceu; recapturar e validar desktop |
| Desktop com welcome fechado | (948,93) fechar e (57,39) duplo clique | Fechar janela e abrir launcher da instalação | `after-close` confirma ícone; novo frame central |
| Calamares Welcome | (1002,644) | `Next` | `calamares-location` no screenshot seguinte |
| Calamares Location | (1002,644) | `Next` | `calamares-keyboard` |
| Calamares Keyboard | (1002,644) | `Next` | `calamares-software-unselected` |
| Calamares Software | (392,166) | Seleccionar **Q4OS Desktop** | `calamares-desktop-selected` |
| Calamares Software seleccionado | (1002,644) | `Next` | `calamares-synthetic-cow-partitions`, só VM |
| Calamares Partitions **em GPT COW totalmente sintética** | (334,280) | Activar **radio Erase disk para mera observação** — absolutamente proibido em Windows/host | `changed-centre` e `calamares-synthetic-cow-partitions-selected` |
| Partitions com COW sintético autorizado | (1002,644) | `Next` abre Users **sem instalar** | `calamares-users`, sem introduzir credenciais |

O laboratório **nunca** clica `Install`, `Done`, confirmação de formatação nem cria utilizador; o último passo captura o ecrã Users e deixa `GASLUX_Q4OS_CALAMARES_USERS_VIEW_VERIFIED=PASS`. O radio `Erase disk` só existe nesta fixture descartável **com prova da identidade do disco sintético e garantia de que o instalador não executou jobs**: nunca copiar para uma cadeia Windows. A aplicação Gaslux tem de controlar a UI por identidade do elemento/estado e cancelar perante ecrãs desconhecidos, mesmo com screenshot e coordenadas válidas. **PENDENTE:** hashes de screenshots por fase e IDs de widget Qt/Calamares, que não estão publicados como contrato de produção; futura automação deve usar API unattended ou introspecção robusta, não estes pixels.

---

## Investigação operacional adicional — duas VMs com ISO 6.10 r2 (19-11-2026)

O trabalho de reconhecimento experimental usa [`boot-maps/q4os.md`](boot-maps/q4os.md), [`ui-maps/q4os.json`](ui-maps/q4os.json) e [`evidence/q4os-manifest.json`](evidence/q4os-manifest.json). Os dois schemas de prova estão em [`schemas/distro-ui-map.schema.json`](../../schemas/distro-ui-map.schema.json) e [`schemas/distro-ui-evidence.schema.json`](../../schemas/distro-ui-evidence.schema.json); a [suite](../../auto_tests/tests/test_q4os_ui_map_contract.py) recusa promoção de transições sem artefactos e SHA por VM.

[EXPERIMENTO EM CURSO] O [workflow `q4os-ui-repro-2vm.yml`](../../.github/workflows/q4os-ui-repro-2vm.yml) usa a ISO oficial `q4os-6.10-x64.r2.iso` após SHA-256, executa o harness exacto no commit `6b6d5521dbd4c2c26712fb57cb6ae5b29e0c69bb`, e tem uma matrix de **dois runners/OVMF/COW independentes** sem disco Windows. Pretende verificar visualmente nove estados e oito transições até Users **em branco** e obter capturas PNG e OCR. A existência da execução não comprova a transição; o manifesto deve conter o ID dos dois artefactos e os hashes dos PNG originais antes de mudar `pending` para `verified`. Nenhum comando de instalação nativa, password ou Summary foi autorizado.

Os primeiros ensaios revelaram erros novos no pipeline de evidências: `unsquashfs -cat | awk` produziu `Broken pipe` com `pipefail` e o refactor para output temporário foi inicialmente inserido com escapes de newline literais. Ambos foram corrigidos **no workflow de laboratório, não no instalador Gaslux**; registar nova CI no manifesto. A inspeção da ISO confirmou `installEFIFallback=true` e `nativeCalamaresConfigVerified=true`. A versão do executável Calamares (pacote `dpkg`) e screenshots da execução devem ser recolhidas antes de assumir estados observados.


## ONE-SHOT EXECUTION PLAYBOOK
**Pré-requisitos exactos:** acesso GitHub conta LMHDEZ, HEAD `dev` confirmado, `AI_POLICY.md`, `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/distro-backends/SHARED_CONTRACTS.md`, mídia oficial e digest/assinatura validados; runner VM descartável com QEMU/SeaBIOS/OVMF conforme firmware e snapshot recuperável. Sem estes elementos, STOP.

**Branch recomendada:** `feature/q4os-native-backend-verified` a partir do HEAD revisto de `dev`, evitando branches empilhadas obsoletas. **PRs candidatas:** #59, #207, #210, #220, #226. Verificar SHA/head/diff antes do cherry-pick.

**Ficheiros a inspeccionar e possivelmente alterar apenas numa futura PR funcional:** `Installation/`, `Scripts/modules/`, `Scripts/uefi/`, `assets/live/`, `schemas/`, adaptadores de distro e testes. **Não alterar sem gates:** `release-config.json` estável, `EFI/Microsoft`, boot Windows, partições alheias, assinaturas/catálogo e contratos Mint/Zorin.

**Interfaces obrigatórias:** preflight tipado → catálogo assinado/ISO validada → plano e ledger duráveis → handoff autenticado → provisioning de target possuído → instalador nativo → bootloader da distribuição → first-boot evidence → verificação Windows → manutenção/uninstall/rollback.

**Execução faseada e testes:** primeiro `ruff check`, `pytest`, `dotnet test`, Pester e ShellCheck conforme workflows existentes e HEAD; verificar nomes e argumentos reais dos workflows antes de executar. Seguidamente lançar apenas workflow explicitamente autorizado com VM descartável, snapshot e hash. Sucesso de cada fase exige relatório de identidade, logs independentes e hashes; nunca métricas auto-reportadas. A lista de workflows experimentais nas PRs #59, #207, #210, #220, #226 é *candidata*, não comando autorizado.

**Falhas previsíveis/correcções:** assinatura errada → descartar a imagem; root ISO não visível → corrigir initramfs/handoff antes de escrever; UUID errado → bloquear; ausência de slot MBR → bloquear, não mexer em EBR; instalador tenta reformatar ESP/Windows → bloquear; bootloader incompleto → restaurar só ficheiros possuídos e confirmar Windows; update altera entrada Windows → reverter com checkpoint e negar sucesso.

**Interrupção obrigatória:** qualquer geometria, hash, conta, firma/assinatura, Secure Boot, propriedade, WinRE/BCD ou estado de recuperação não comprovado; Windows sem boot validado; tentativa de usar disco físico; parâmetros, caminhos de ISO ou opções unattended desconhecidos.

**Provas de conclusão:** SHA commit, PR, workflow/run, artefactos e respectivos SHA-256, cadeia de assinatura upstream, serial/GUID/offsets, pré/pós Windows BCD/WinRE/EFI/MBR, arranques Linux e Windows pós-instalação e pós-update, remoção, rollback e relatório independente. **Nunca declarar estável sem a matriz completa.**
