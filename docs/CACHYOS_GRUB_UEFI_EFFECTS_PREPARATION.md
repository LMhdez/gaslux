# CachyOS GRUB UEFI / ESP — preparação de medição DENY-only

**Observação:** 22-11-2026 UTC. PR dependente da #349, HEAD base `097a8c16726b89a6ba2be4af469ea438f0345d17`. Esta intervenção não executa GRUB, QEMU, Archiso, Windows nem escritas em discos. A PR #349 continua à espera de revisão Safety.

## 1. Versão exigida e proveniência

O percurso real `assets/live/cachyos-stage-target.sh` contém `pacstrap -K ... grub efibootmgr ...` **sem versão, epoch, SHA-256 do pacote, origem de repositório fixada ou assinatura do binário `grub-install`**. O módulo `assets/live/cachyos-uefi-lab.py` define as flags GRUB, não a implementação do executável. Por isso, a **versão exata efetivamente usada pelo backend é `GRUB_PACKAGE_VERSION_UNPINNED`**. Os repositórios upstream podem servir versões diferentes conforme a arquitetura; nunca selecionar uma versão encontrada online como prova de pacote instalado na VM.

Referências de contexto upstream, não evidência da imagem CachyOS instalada: [pacotes CachyOS](https://packages.cachyos.org/), [manual `grub-install` Arch](https://man.archlinux.org/man/grub-install.8.en), [ArchWiki GRUB](https://wiki.archlinux.org/title/GRUB).

Antes de qualquer laboratório de **execução GRUB**, o Integrador deve fixar o checkpoint da rootfs Arch efetivamente instalada e registar em privado a versão e epoch de `grub`, hash SHA-256 do pacote e validação independente da assinatura Pacman, hash do ELF `/usr/bin/grub-install`, binários auxiliares, módulos `/usr/lib/grub/x86_64-efi`, dependências, ABI, pacman database e identidade imutável do artefacto. Não executar `grub-install --version` num host de produção: a consulta deve ser feita sobre ficheiros autenticados ou num guest descartável autorizado. Nesta PR não existe essa prova.

**Parecer Safety específico da #349 ainda não publicado à data de criação desta PR.** O laboratório mutável continua desarmado. Uma Action verde de preparação não implica aprovação Safety.

## 2. Laboratório UEFI/GPT futuro: requisitos bloqueantes

| Fronteira | Requisito antes de autorizar execução | Estado nesta intervenção |
| --- | --- | --- |
| Runner | VM descartável sem discos, `/dev` ou volume host disponibilizados ao guest | NÃO EXECUTADO |
| Origem | rootfs e GRUB autenticados por versão, assinatura, SHA-256 | NÃO COMPROVADO |
| Disco | RAW/QCOW2 **privado**, GPT primária/secundária e PMBR com CRC e GUID, FD e ownership de transação | NÃO EXECUTADO |
| ESP | FAT32 privada com partição ESP GUID/PARTUUID e offsets provados, ficheiros Microsoft/OEM **sintéticos rotulados** | NÃO EXECUTADO |
| Firmware | OVMF CODE autenticado e VARS privadas; BootOrder/BootNext capturados por bytes antes/depois | NÃO EXECUTADO |
| Checkpoints | base e overlay independentes; restaurabilidade verificada, hash antes/depois e energia interrompida | NÃO EXECUTADO |
| Instrumentação | HOST/FD + Local Peer de `dev`, leitura GPT canónica e FAT32 existente; QMP + trace por nó com vínculo independente | NÃO EXECUTADO |
| Safety | aprovação diferencial da #349 e da fronteira de escrita VM, confinamento e rollback verificados | **PENDENTE** |

Não basta observar `--no-nvram` ou `--no-extra-removable`. Só imagens OVMF/ESP medidas e verificadas, com identificação do processo, backing e nó QEMU, poderiam comprovar o efeito efetivo de tais flags. A ausência de entrada BootNext declarada pelo próprio guest não é prova independente.

## 3. Adaptador offline: três provas separadas

`auto_tests/tools/cachyos_grub_uefi_effects_offline.py` **não é um instalador**, nem reimplementa QEMU, GPT ou FAT32.

1. `grub_source_readiness()`: reutiliza as quatro fontes fixadas da #349; devolve `GRUB_VERSION_AND_SIGNED_BINARIES_UNPINNED` e `canRunGrubInstall=false`. Nunca usa o GRUB do host.
2. `compare_synthetic_snapshots()`: compara **inventários sintéticos autodeclarados e amostras** antes/depois, com limites de tipos e geometria. Enumera criação/modificação/remoção de ficheiros, LBA nas amostras, GPT/PMBR, OVMF VARS e BootOrder/BootNext. Recusa transações e ESP estrangeiras, proteção Microsoft/EFI/BOOT/OEM/Recovery, alterações GPT/NVRAM, setores fora da ESP, inventários truncados e colisões de caixa no FAT. Resultado máximo `SYNTHETIC_SAMPLED_EFFECTS_DENY_ONLY`: `sectorCoverageComplete=false`, `actualGrubInstallExecuted=false`, `grubEffectiveWriteSetProven=false`, `authorization=false`. Um ficheiro `EFI/Gaslux-CachyOS/grubx64.efi` pode ser classificado como **previsto**, nunca aprovado.
3. `preview_efi_cleanup_owned_files()`: compara um diretório efémero `EFI/Gaslux-CachyOS` com **a lista exata** de ficheiros e SHA-256 esperados, usando dirfd e aberturas no-follow, sem recorrer ao `shutil.rmtree` existente. Recusa ficheiros extra, symlinks, hardlinks, diretórios inesperados, marker de outra transação, conteúdos alterados ou inexistentes. Devolve `canDelete=false`, `deleteActionPresent=false` **mesmo se o inventário corresponder**. Não remove nada.

Estes contratos não conferem autoridade a recibos JSON fornecidos pelo próprio laboratório, não demonstram ausência de writes intermediárias e não realizam medição setor-a-setor completa. Os spans sintéticos representados nos testes **não são o write-set de GRUB**. Não podem ser usados para desbloquear qualquer writer, restaurar Windows ou declarar boot comprovado.

## 4. Medição operacional futura, apenas depois dos gates

Fase inicial: criar base + clones privados e imagem ESP FAT32 sintética (com marcadores EFI explicitamente não-Microsoft) em QEMU/OVMF, capturar hashes GPT/PMBR/ESP/FAT/FSInfo/diretórios, `/boot`, Windows/OEM simulados, OVMF VARS e registos `Boot####`, `BootOrder`, `BootNext`; comprovar origem/FD/backing e restaurabilidade. Travar completamente qualquer acesso a discos do host.

Somente se Safety aprovar a execução, fixar o pacote GRUB/ELF/módulos e arrancar uma VM descartável para chamar as **flags exatas** do laboratório; parar e capturar novo checkpoint independente, a par de trace QEMU temporal e diffs completos de bytes de sectores FAT32/metadados, ficheiros, GPT e VARS. Comparar com as 13 classes da #349; qualquer delta desconhecido, FAT32 metadata sem atribuição, ficheiro estrangeiro, fallback EFI, BCD ou BootOrder/BootNext diferente → **DENY**, sem interpretação causal precipitada.

Para compensação, construir primeiro manifesto de ficheiros criados pelo instalador com hashes e identidade de transação; evitar `rmtree` por completo. Exigir verificação individual e recusar diretórios com crianças estrangeiras; só uma futura implementação sob aprovação Safety poderia apagar os próprios artefactos por FD, protegida contra troca de inode. Não usar a rotina de preview como delete.

**Conclusão desta PR:** `GRUB_VERSION_UNPINNED`, `GRUB_EFFECTIVE_WRITESET_NOT_OBSERVED`, `GRUB_ROLLBACK_NOT_VERIFIED`, `P4=NOT_VERIFIED`, `approvedMutation=false`, `productionStorageWritesAuthorized=false`, `releaseEligible=false`, `stable=false`. Nenhum Windows real, BCD histórico ou imagem com dados foi utilizada.
