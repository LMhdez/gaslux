# Gaslux — inventário operacional dos seis backends

**Snapshot de investigação:** 2026-11-19 (UTC). **Base de desenvolvimento:** dev @ 34d50646783498000eb13dbaf8a63220e63ff719; **main observada:** 90b044ba435b2b4b4db6c5813ca4698b37e4a555. Esta documentação **não** concede autorização de escrita nem declara estabilidade. Revalidar os HEADs, as PRs, os artefactos e as versões upstream antes de atuar.

## Como ler esta investigação

- **DOCUMENTADO**: upstream oficial ou contrato de arquitetura publicado, com URL e, quando relevante, versão.
- **IMPLEMENTADO**: ficheiro ou commit concreto contém código; não implica execução validada.
- **COMPROVADO**: experiência identificável por commit, Actions, log/artefacto e âmbito exato; o resultado não se estende a outros cenários.
- **PENDENTE**: parâmetro, transição, interface ou prova ainda não confirmados.
- **BLOQUEADO**: a operação não é permitida; falhar antes da primeira escrita.
- Um sucesso de CI sintético, Live ISO ou rootfs extraída **não** demonstra instalação nativa, dual boot, atualização ou rollback.
- Respeitar as diferenças entre main (release de Mint/Zorin), dev (contratos integrados) e PRs experimentais empilhadas. A PR #7 foi integrada em **dev**, não constitui prova de merge em main.

## Matriz — capacidade upstream vs suporte Gaslux

| Backend | Firmware / tabela permitidos em estudo | Boot instalado esperado | Instalador/método | Estado Gaslux em 2026-11-19 | Evidência representativa | Bloqueio e próxima etapa |
|---|---|---|---|---|---|---|
| Mint 22.3 Cinnamon | BIOS/MBR e UEFI/GPT no caminho herdado; validar layout e Secure Boot por máquina | GRUB BIOS ou shim+GRUB EFI do sistema | Debian/Ubuntu SquashFS com orquestração Gaslux; upstream Ubiquity é alternativa, **não** o caminho atual | Catalogado em main; cobertura real completa por cenário ainda exige evidência individual | release-config.json; PRs #174, #181, #185, #212 e #242 (experiências) | Provar instalação e dois arranques no **mesmo** Windows QCOW2, atualização e reversão |
| Zorin 18.1 Core | BIOS/MBR e UEFI/GPT no caminho herdado, condicionado à matriz testada | GRUB BIOS ou shim+GRUB EFI | Backend Debian/Ubuntu de Gaslux; identificar executável instalador da ISO concreta | Catalogado em main; provas de root/boot em laboratório não equivalem a end-to-end | release-config.json; PRs #167, #176, #219, #224 | Testar Windows instalado, kernel update, retorno ao Windows e rollback |
| CachyOS 260809 (ISO de laboratório) | UEFI/GPT em laboratório; BIOS/MBR **não provado** no Gaslux | GRUB/alternativas Arch específicas, seleção deve ser fixada por backend | Archiso + pacstrap/pacman; Calamares/TUI upstream são distintos | Experimental; issue #3 permanece release gate | PRs #36, #165, #171, #184, #215; Actions #43954231860 | Integrar handoff assinado Windows→Archiso, primeira instalação completa compartilhada, ambos os arranques e rollback |
| Pop!_OS 24.04 (laboratório) | UEFI/GPT investigado; BIOS/MBR upstream possível mas não provado no Gaslux | systemd-boot UEFI, GRUB BIOS | System76 distinst (CLI/API versionadas) | Experimental, só provas parciais de VM | PRs #33, #39, #50, #178, #221, #232 | Reproduzir distinst em Windows QCOW2 mantendo ESPs/Boot Manager; validar entrada Windows e recuperação |
| Bazzite Atomic (ISO legacy 42 observada) | **UEFI/GPT exclusivamente**; BIOS/MBR BLOQUEADO | GRUB/EFI do Fedora Atomic, confirmar variante exata | Instalador nativo Fedora Atomic/Anaconda, workflow ostree/bootc; Blivet na ISO legacy | Experimental, ISO legacy sem proveniência independente autorizadora | PRs #214, #222, #250, #255; Actions #44368046013 | Autenticidade ISO atual, versão instalada, write-set do instalador, sem MOK automática |
| Q4OS 6.10 r2 (laboratório) | UEFI/GPT em laboratório; BIOS/MBR carece de prova de fluxo Gaslux | GRUB Debian/Calamares, impedir EFI fallback sobre Windows | Calamares verificado na ISO concreta; Windows installer em pasta NÃO é dual boot nativo | Experimental; UI/ensaios sintéticos, execução Calamares não comprovada | PRs #44, #49, #59, #209, #237, #256 | Validar plano nativo de todas as tarefas Calamares, instalar em COW Windows, arrancar ambos e recuperar |

O estado "catalogado" significa **selecionável no canal main**, não certificação universal das combinações. As variantes Secure Boot e segundo disco necessitam de casos próprios; Bazzite Secure Boot com inscrição MOK interativa fica bloqueado.

## Origem e integridade

- Fonte de verdade estável: [release-config.json](../../release-config.json) e [schema](../../schemas/release-config.schema.json), com versões, tamanhos e SHA-256 para Mint/Zorin; não copiar as ISOs do laboratório para o catálogo sem metadados assinados.
- A assinatura RSA de catalog.json e releases.json, chaves e separação main/dev são explicadas em [ARCHITECTURE.md](../ARCHITECTURE.md). Uma hash registada numa PR não substitui assinatura de catálogo.
- Uma PR fechada sem merge pode conter uma experiência útil, mas o seu código não existe necessariamente na base selecionada. Confirmar head SHA, diff, dependências, execuções de Actions e link de artefactos antes de reutilizar.
- A árvore experimental contém testes com discos GPT **sintéticos**, Windows **realmente instalado** e Live **oficial**. Não os confundir.

## Leitura obrigatória para cada agente

1. [SHARED_CONTRACTS.md](SHARED_CONTRACTS.md) — invariantes comuns, cadeia de autoridade, ledger, boot e evidências.
2. Documento da distribuição: [Mint](MINT.md), [Zorin](ZORIN.md), [CachyOS](CACHYOS.md), [Pop!_OS](POPOS.md), [Bazzite](BAZZITE.md), [Q4OS](Q4OS.md).
3. [ARCHITECTURE.md](../ARCHITECTURE.md), [AGENTS.md](../../AGENTS.md), [AI_POLICY.md](../../AI_POLICY.md), [CONTRIBUTING.md](../../CONTRIBUTING.md), [MULTIDISTRO_PLAN.md](../MULTIDISTRO_PLAN.md), [UEFI_BOOTNEXT_BOOTORDER.md](../UEFI_BOOTNEXT_BOOTORDER.md).
4. Estado vivo: [issues](https://github.com/LMhdez/gaslux/issues), [PRs](https://github.com/LMhdez/gaslux/pulls), [Actions](https://github.com/LMhdez/gaslux/actions), [issue #3](https://github.com/LMhdez/gaslux/issues/3) e [PR #7](https://github.com/LMhdez/gaslux/pull/7).

## Procedimento de revisão contínua

Rever em cada sessão: data da ISO, identificação real do instalador, configuração de boot, hashes/assinaturas, versão do catálogo, branches integradas, problemas reportados, estado do workflow no **mesmo SHA** e evidências pós-reinício. Para cada divergência, editar o documento de origem, não ajustar silenciosamente um comando arriscado. Os playbooks são **sequências de gates** para outro agente; não são scripts executáveis de alteração de discos.

## Inventário de testes e limites

- Contratos: schemas/, Installation/ e Scripts/modules/ contra assets/live/; C#, Pester, pytest, Ruff, shell syntax, ShellCheck, documentação e ligações.
- Simulação: GPT sintética, pré-visualização de plano e OCR não provam autoridade para escrita.
- Boot Live: exige ISO oficial autenticada, guest boot e telemetria do convidado; não comprova instalação.
- Sistema Linux instalado: arrancar kernel/root e observar serviços em novo arranque com ISO removida; uma rootfs extraída pode ser um ensaio útil, mas não comprova instalador nativo.
- Dual boot: ambos os sistemas **no mesmo overlay Windows realmente instalado**, provas independentes de Linux e Windows e hashes de ESP/BCD/WinRE. Testar também as atualizações.
- Recuperação: voltar a arrancar Windows, verificar geometria, boot, BitLocker/WinRE/BCD e artefactos próprios, com snapshots/reversão; logs de sucesso isolados não bastam.

**Política de aceitação:** [issue #3](https://github.com/LMhdez/gaslux/issues/3) para CachyOS e o contrato geral de segurança em ARCHITECTURE.md. Nenhuma linha desta matriz autoriza promoção de estado experimental para estável.

## Fontes e datas

Consulta de 2026-11-19: repositório [LMhdez/gaslux](https://github.com/LMhdez/gaslux); [Mint verification](https://linuxmint-installation-guide.readthedocs.io/en/latest/verify.html); [Zorin ISO integrity](https://help.zorin.com/docs/getting-started/check-the-integrity-of-your-copy-of-zorin-os/); [CachyOS downloads](https://wiki.cachyos.org/cachyos_basic/download/); [System76 bootloader](https://support.system76.com/support/bootloader); [Bazzite install guide](https://docs.bazzite.gg/General/Installation_Guide/install-guide/); [Q4OS installation](https://www.q4os.org/dqa018.html). Links upstream refletem documentação consultada, não testemunham um teste Gaslux.
