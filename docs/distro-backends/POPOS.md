# Pop!_OS 24.04 (candidato System76 de laboratório) — investigação e execução Gaslux

**Data:** 2026-11-19 UTC. **Identidade/backend:** popos / ID=pop / backend System76 distinst. **Snapshot:** main 90b044ba435b2b4b4db6c5813ca4698b37e4a555, dev 34d50646783498000eb13dbaf8a63220e63ff719. Estes HEADs não são autoridade futura. Consultar [contratos partilhados](SHARED_CONTRACTS.md), [índice](README.md) e revalidar PR/Actions antes de trabalhar.

**Rótulos:** DOCUMENTADO = fonte oficial; IMPLEMENTADO = código identificado; COMPROVADO = teste/artefacto verificável **no âmbito indicado**; PENDENTE = investigação ou prova por fazer; BLOQUEADO = não escrever ou promover. Não extrapolar de ISO Live ou GPT sintética para instalação real.

## 1. Resumo executivo e estado de maturidade

**EXPERIMENTAL e fora do catálogo estável.** Existem provas de identificação GPG da ISO, ELF distinst, instalação native Linux-only em VM e arranque Windows após criar ESP/root próprias; ainda não existe, nesta investigação, uma cadeia completa e comprovada de instalação distinst no mesmo disco Windows com ambos os boots, atualizações e rollback.

## 2. Fontes oficiais e versões consultadas

- [System76 — download de Pop!_OS](https://system76.com/download-pop/), [instalação](https://support.system76.com/support/install-pop/) e [reparação e bootloaders](https://support.system76.com/support/bootloader), consulta 2026-11-19.
- [distinst — fonte upstream](https://github.com/pop-os/distinst), [código CLI](https://github.com/pop-os/distinst/blob/master/cli/src/main.rs), [reuse.rs](https://github.com/pop-os/distinst/blob/master/cli/src/configure/reuse.rs), [kernelstub](https://github.com/pop-os/kernelstub). As branches upstream de hoje não são substituto do SHA instalado na ISO histórica.
- [PR Gaslux #33](https://github.com/LMhdez/gaslux/pull/33), [#39](https://github.com/LMhdez/gaslux/pull/39), [#50](https://github.com/LMhdez/gaslux/pull/50), [#221](https://github.com/LMhdez/gaslux/pull/221) e [#232](https://github.com/LMhdez/gaslux/pull/232).

## 3. Arquitetura de arranque

**DOCUMENTADO System76:** instalação UEFI habitualmente usa systemd-boot/kernestub; BIOS/Legacy usa GRUB (ver página oficial Bootloader). O EFI executável, diretório ESP e loader entries devem ser identificados na ISO e target exatos. **IMPLEMENTADO em laboratório:** OVMF com GRUB EFI temporário para arrancar ISO real read-only; não equivale ao loader Pop instalado. Para Windows→Linux sem USB, a escolha GRUB loopback/EFI chainload/kernel+initrd está **PENDENTE** para o meio exato; validar descoberta do SquashFS/root após boot e retorno ao Windows se primeiro reinício falhar. BIOS/MBR não herda prova de UEFI.

## 4. Estrutura e autenticação da ISO

**IMPLEMENTADO em experiência, não release-config.json:** candidatos Pop!_OS 24.04 Intel/genérico, ISO System76 com GPG/SHA-256 e binário distinst ELF ligado à mesma imagem em [PR #33](https://github.com/LMhdez/gaslux/pull/33). Tamanho, SHA-256, fingerprint da chave, edição/versão exatos e confirmação de política Secure Boot **PENDENTES** de transcrição ligada a um commit e manifesto assinado; não transplantar digests de outra ISO. Varianten NVIDIA/Intel exigem caminhos separados. A página System76 recomenda Secure Boot desligado para instalar; Gaslux não altera firmware/chaves nem automatiza o desligar.

## 5. Sequência completa Windows → Linux

Em [PR #33](https://github.com/LMhdez/gaslux/pull/33) foi extraído o ELF /usr/bin/distinst do live root e ligado ao SHA do ISO; **não** foi validada neste dossier uma árvore completa ISO El Torito/UEFI/kernel/initramfs/squashfs. Registar manifesto das rotas reais, hash por componente, carregamento no initramfs e nome do loader presente. Não copiar live rootfs para sistema instalado como se fosse instalação distinst. Identificação pós-boot ID=pop e versão instalada não se infere de nome do ISO.

**Contrato partilhado:** vincular nonce/transação/autorização, ISO, disco, partição, firmware, programa executado e plano a um handoff autenticado. Preparar recuperação com baseline verificável **antes de escrever**. Checkpoint durável por fase e compensação idempotente por recurso pertencente à transação. Em falha, não descartar o overlay antes de observar Windows recuperar e arrancar. Prova serial/OCR/log não basta sem inspeção independente de geometria/boot.

## 6. Instalador nativo e automatização

**DOCUMENTADO:** distinst é motor System76 (Rust e interfaces nativas) com API/CLI de criação/reutilização de partições e configuração de instalação. A sintaxe válida deve ser apurada no ELF exato e código fonte correspondente; não inventar flags. **Aviso material em #39:** distinst use partition:fat32 pode chamar format_with, mesmo sobre a ESP Windows; o modo :reuse evita essa chamada no source observado mas precisa de prova de não escrita e ownership na versão efetiva. **COMPROVADO de forma limitada:** [Actions #43988375734](https://github.com/LMhdez/gaslux/actions/runs/43988375734) registou conclusão de uma **instalação distinst real** em GPT Linux-only; esse job falhou na fase de shutdown e não provou segundo boot naquela execução. Verificar artefactos/SHAs de tentativas posteriores antes de concluir N3.

## 7. Particionamento e proteção Windows

**Contrato transversal — IMPLEMENTADO na base, não necessariamente integrado neste backend:** Windows 10/11 pré-valida firmware e tabela, serial/identificador persistente, bytes por setor, capacidade, offsets, NTFS shrink, estado BitLocker/Device Encryption, BCD, WinRE, OEM/Recovery, ESP e BootOrder/BootNext ou MBR/PBR/active flag. No ambiente Live repetir a identificação e comparar com plano tipado. Nunca selecionar o primeiro /dev/sdX nem confiar apenas na letra C:. Recusar qualquer geometria divergente, partição estrangeira, GPT sem CRC consistente ou EBR não auditada. Não converter tabela/firmware, formatar Windows/ESP nem alterar chaves Secure Boot.

**IMPLEMENTADO em laboratórios isolados:** [#178](https://github.com/LMhdez/gaslux/pull/178) deriva quinta ESP e sexta raiz **pertencentes ao plano** num Windows10 realmente instalado em overlay QCOW2; [#221](https://github.com/LMhdez/gaslux/pull/221) prova boot Windows com essas duas partições staged, **antes de instalar Pop**. ESP dedicada reduz risco de formatação da ESP Microsoft, mas introduz risco de Windows entry ausente em systemd-boot (PR #67). Um ESP partilhado só é aceitável com o write-set nativo examinado, sem formatting ou fallback EFI Microsoft. UEFI/GPT no mesmo disco é candidato experimental; BIOS/MBR, EBR e segundo disco requerem provas próprias.

## 8. Configuração do sistema instalado

O backend deve provisionar conta/senha protegida, login, sudo, locale pt-PT, layout de teclado, timezone, fstab por UUID/PARTUUID, pacotes/serviços System76, kernelstub e kernel real. Medir os valores no convidado após primeiro boot, não confiar apenas em saída "install successful". Configuração ubuntu-family genérica pode ser reutilizada quando semanticamente idêntica, mas não substituir as fases de distinst, root, ESP e updates. PENDENTE schema unattended exato e mecanismos de GUI/IPC da release.

## 9. Bootloader e manutenção

**DOCUMENTADO:** systemd-boot em UEFI gera entries e kernelstub preserva kernels; GRUB em BIOS precisa de estratégia independente. O Windows Boot Manager deve continuar acessível por firmware entry própria e/ou entrada testada; [#67](https://github.com/LMhdez/gaslux/pull/67) observou ausência de Windows em menu systemd-boot com ESP separada. Não assumir que BootOrder por si só oferece ao utilizador menu dual boot. Validar EFI binaries, PARTUUID, entrada Windows, BootNext/NVRAM, update kernelstub e limites de espaço da ESP; recusar encriptação/firmware não verificáveis.

## 10. Atualizações e desinstalação

Atualizar kernel, systemd-boot/kernelstub e pacotes através das ferramentas reais do Pop, reiniciar Linux e Windows após update e validar kernel/root/EFI/BCD. Em BIOS validar GRUB, em UEFI entrada EFI própria. Reinstalação deve criar transação nova; remover apenas ficheiros/ESP/root/EFI/NVRAM identificados pelo plano anterior. Desinstalar Pop não equivale a eliminar Windows Boot Manager nem a restaurar ESP por copiar defaults.

## 11. Recuperação e rollback

**Obrigatório:** guardar baseline de partições e hashes/testemunhos, EFI/BCD/WinRE/NVRAM ou MBR/PBR, encriptação e caminho de boot Windows; testar acesso à recuperação; em corte de energia, download falhado, falta de espaço, erro nativo ou bootloader parcial, parar escrita e restaurar apenas recursos transacionais após reidentificar disco. Validar no Windows realmente arrancado geometria, BitLocker/WinRE/BCD e BootOrder/ESP ou MBR. Snapshot/COW protege o laboratório, não prova a recuperação de produto; se não for possível provar, marcar recuperação incompleta e não declarar sucesso. Em especial, simular `distinst` interrompido após format root e durante cópia de EFI, systemd-boot Windows entry ausente, falta de espaço ESP, fonte GPG inválida, BootNext recusado e poweroff falhado após instalação. O teste de Windows boot da #221 não constitui recovery após instalação Pop; é um estágio anterior.

## 12. Código Gaslux reutilizável

**IMPLEMENTADO/experiências:** plan/ledger/schemas, Scripts/modules/, probe de disco e ESP, preflight System76 read-only da [PR #60](https://github.com/LMhdez/gaslux/pull/60) (dev), helper de fases Ubuntu-family da [#62](https://github.com/LMhdez/gaslux/pull/62), protótipo distinst #33/#39/#50, COW Windows #178/#221/#232. Não usar o pipeline do Debian squashfs Mint/Zorin como instalador Pop; não copiar wrapper GRUB/dpkg para EFI systemd-boot.

## 13. PRs, branches e commits relevantes

- [PR #33](https://github.com/LMhdez/gaslux/pull/33), SHA 48be24b6031733646b45192624fe2186bb6c18d0: GPG ISO e binário distinst; [#38](https://github.com/LMhdez/gaslux/pull/38) CLI em convidado; [#39](https://github.com/LMhdez/gaslux/pull/39), SHA 75cdaa2e82053e25eebbbd3fbbc3e51ca294d3da: preflight de ESP, não instalado em dev.
- [PR #50](https://github.com/LMhdez/gaslux/pull/50), [Actions #43988375734](https://github.com/LMhdez/gaslux/actions/runs/43988375734) e SHA 6295782713b77d4ca98c808cfc9ba7557c917bd9: instalação System76 Linux-only + falha no poweroff numa tentativa; outro commit pode alterar estado.
- [PR #177](https://github.com/LMhdez/gaslux/pull/177), [#178](https://github.com/LMhdez/gaslux/pull/178), [#221](https://github.com/LMhdez/gaslux/pull/221), SHA 1926df2ecb37eed11805a02f2a683e8ef38feaa4: Windows real após ESP/root staged (sem Pop instalado).
- [PR #232](https://github.com/LMhdez/gaslux/pull/232), draft aberta, SHA 85c9ea30b75c763314e775d4daddf10d5357109e: Live ISO Pop numa COW real Windows10 read-only. [#67](https://github.com/LMhdez/gaslux/pull/67) Windows entry separada em systemd-boot.

## 14. Problemas conhecidos e causas identificadas

**BLOQUEADO:** aceitar argumento distinst que reformata ESP Windows, tratar helper de reboot Linux-only como dual boot, usar mini-ISO Debian como instalador, substituir Windows EFI, forçar Secure Boot off/MOK e reutilizar nome de disco /dev/vda sem serial. O job #43988375734 tinha progresso nativo bem-sucedido, mas falhou no shutdown: falha na automação não deve ser ocultada ou declarada segundo boot. Win11/BIOS/MBR/segundo disco e atualizações continuam pendentes.

## 15. Soluções tecnicamente verificadas

**DOCUMENTADO:** distinst upstream e reutilização :reuse em vez :fat32 como estratégia a validar; **COMPROVADO em laboratório:** distinst Linux-only chegou a concluir instalação (não boot) no Actions #43988375734; Windows real iniciou após staging ESP/root no #221, **sem Pop instalado**; PR #232 mostra percurso de Live, read-only. **PENDENTE:** sequência one-shot Windows→distinst→Linux primeiro boot→Windows boot→rollback na mesma VM. Justificação: a coexistência de provas independentes não garante a mesma transação.

## 16. Matriz de compatibilidade

| Cenário | Estado Gaslux 2026-11-19 |
|---|---|
| Win10 UEFI/GPT, disco único | Stage ESP/root e boot Windows em #221; dual boot Pop nativo PENDENTE |
| Win11 UEFI/GPT | PENDENTE ISO nativa, N4/N5 |
| Win10 BIOS/MBR | GRUB é caminho upstream, Gaslux BLOQUEADO sem ensaios |
| Segundo disco UEFI | PENDENTE ESP/Windows entry e autoridade física |
| Secure Boot ativo | BLOQUEADO enquanto a versão upstream exigir desativação |
| UEFI/MBR, BIOS/GPT, EBR desconhecida | BLOQUEADO |

## 17. Testes existentes e evidências

**DOCUMENTADO:** distinst upstream e reutilização :reuse em vez :fat32 como estratégia a validar; **COMPROVADO em laboratório:** distinst Linux-only chegou a concluir instalação (não boot) no Actions #43988375734; Windows real iniciou após staging ESP/root no #221, **sem Pop instalado**; PR #232 mostra percurso de Live, read-only. **PENDENTE:** sequência one-shot Windows→distinst→Linux primeiro boot→Windows boot→rollback na mesma VM. Justificação: a coexistência de provas independentes não garante a mesma transação.

Runs e commits disponíveis na secção 13; a palavra SUCCESS de contratos não prova N4/N5.

## 18. Testes ainda necessários

**N0:** contratos C#/Pester/Python/Bash, linters, hashes/identidade/ownership/negativas. **N1:** ISO oficial imutável, assinaturas e árvore interna/boot/installer. **N2:** boot do Live autenticado, mas não instalação. **N3:** instalador **nativo** executado, primeiro e segundo boot Linux instalado sem ISO, conta/localização/loader. **N4:** Windows 10 BIOS/MBR, Win10 UEFI/GPT e Win11 UEFI/GPT quando aplicáveis, disco único/segundo, ambos SO num **mesmo Windows QCOW2 real**. **N5:** updates, reinstalação/desinstalação, powercut em cada etapa, rollback e WinRE/BCD/ESP/MBR comprovados. **N6:** hardware real só com autorização, backup e restauro demonstrado. Não somar ensaios de discos diferentes para alegar N4.

1. Identificar ISO e ELF distinst por assinatura GPG/key fingerprint/commit e listar CLI/actions reais. 2. Determinar modelo ESP escolhível e a lista exata de writes (including reuse). 3. Reproduzir #50 com segundo boot sem ISO. 4. Integrar plano/handoff autenticados no Windows QCOW2 stage #221; provar Pop native + Windows dual boot no **mesmo** overlay. 5. Atualizar kernelstub, simular falhas, reinstalar/remover e verificar BCD/WinRE/EFI. 6. Auditar BIOS/MBR e segundo disco separadamente.

## 19. Plano de implementação ordenado

1. Identificar ISO e ELF distinst por assinatura GPG/key fingerprint/commit e listar CLI/actions reais. 2. Determinar modelo ESP escolhível e a lista exata de writes (including reuse). 3. Reproduzir #50 com segundo boot sem ISO. 4. Integrar plano/handoff autenticados no Windows QCOW2 stage #221; provar Pop native + Windows dual boot no **mesmo** overlay. 5. Atualizar kernelstub, simular falhas, reinstalar/remover e verificar BCD/WinRE/EFI. 6. Auditar BIOS/MBR e segundo disco separadamente.

## 20. Critérios objetivos de estabilidade

Só permitir em release as combinações concretas com prova N5 de instalação nativa, primeiro boot Linux e Windows no mesmo QCOW2 realmente instalado, atualizações e rollback/desinstalação com dados/WinRE/BCD/EFI/BitLocker preservados. A ligação da evidência a commit, runner, firmware, ISO e geometria é obrigatória; hardware requer backup/restauro testados e autorização.

## ONE-SHOT EXECUTION PLAYBOOK

### Pré-requisitos exatos, branch e referências

- **GitHub LMhdez**; branch sugerida: feature/popos-distinst-shared-windows-<fase> derivada de dev HEAD auditado. Revalidar base, HEAD, PRs/commits indicados na secção 13 e Actions no mesmo SHA. Não atuar com credenciais DINISIHO. Não fazer merge automático.
- Artefactos ISO autenticamente versionados por tamanho/SHA/signature/key; firmware/tabela testados; disk/partition IDs e offsets exatos; screenshot/CLI/version nativa; autorização de laboratório COW e recuperação Windows preparada. Se qualquer um falhar, não executar writes.
- **Ficheiros a modificar apenas quando requisito de implementação:** backend System76 específico, capacidades/schema, testes Windows/COW, adaptador EFI/systemd-boot; preservar código Mint/Zorin e release-config estável. **Ficheiros a não modificar:** release-config.json/main estável, RSA signing keys, EFI/Microsoft, Windows OEM/Recovery, writers de outras distribuições e qualquer dado real. Comparar regressões de Mint e Zorin.
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
- **STOP específico:** ELF/ISO não autenticados, argumentos distinst formatam ESP alheia, Windows menu/Boot Manager ausente, Secure Boot ativo, NVRAM/BCD incoerente, recovery sem provas.
- Não alterar automaticamente chaves Secure Boot nem converter tabela; não usar teste sintético para declarar estabilidade.

### Evidências necessárias para concluir

SHA/commit da implementação, SHA/size/signature da imagem e trust chain, exactos bytes/setor/GUID/PARTUUID/offsets, firmware e NVRAM/BCD/WinRE, snapshots originais, logs host+guest, hashes witness Windows antes/depois, native installation + firstboot Linux sem media, boot Windows efetivo, dois SO após updates, falha injetada e rollback/desinstalação completo, testes por layout e PR revista por humano. A estabilidade depende de provas N5, não do volume desta documentação.
