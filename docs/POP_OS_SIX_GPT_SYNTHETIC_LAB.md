# Pop!_OS — laboratório GPT sintético de seis partições (pré-revisão Safety)

**Estado:** experimental, sem Windows genuíno, sem instalação, sem QEMU guest e sem qualquer autorização de writer. Dependência explícita da [PR #232](https://github.com/LMhdez/gaslux/pull/232). Safety [#265](https://github.com/LMhdez/gaslux/pull/265) / [#267](https://github.com/LMhdez/gaslux/pull/267), Observer [#259](https://github.com/LMhdez/gaslux/pull/259) e Integrator [#290](https://github.com/LMhdez/gaslux/pull/290) continuam referências de auditoria, não autorizações.

## Evidência anterior e limite

A [Actions #44893175522](https://github.com/LMhdez/gaslux/actions/runs/44893175522) comprovou Pop real com instalação completa System76 em modo reuse, systemd-boot, primeiro arranque, GPT/RAW preservados e recuperação por reconstrução de overlay num QCOW2 Linux-only **de duas partições**. Não demonstra segurança numa GPT de seis partições. A [Actions #44764397442](https://github.com/LMhdez/gaslux/actions/runs/44764397442), sem reuse, evidenciou alterações GPT/PARTUUID e não fornece um percurso seguro.

## Geometria determinística

Disco RAW descartável de 32 GiB / 67 108 864 setores de 512 bytes; disk GUID 81ab6d0e-0f88-4923-a24b-8748f15890e1; serial virtio planeado GASLUXPOPSIXGPT. Sem ISO, NTFS ou qualquer ficheiro Windows real.

| # | Partição sintética | LBA inicial | LBA final | Capacidade | Escritas futuras |
|---|---|---:|---:|---:|---|
| 1 | ESP protegida simulada, FAT32 com ficheiro-canário | 2 048 | 534 527 | 260 MiB | Proibidas |
| 2 | MSR protegida simulada | 534 528 | 567 295 | 16 MiB | Proibidas |
| 3 | Dados protegidos simulados | 567 296 | 1 615 871 | 512 MiB | Proibidas |
| 4 | Recovery protegida simulada | 1 615 872 | 3 188 735 | 768 MiB | Proibidas |
| 5 | ESP Pop pertencente à transação, FAT32 -s 8 | 3 188 736 | 5 285 887 | 1 GiB | Apenas após Safety |
| 6 | Raiz Pop pertencente à transação, ext4 | 5 285 888 | 64 006 143 | 28 GiB | Apenas após Safety |

GUID de tipo, PARTUUID e LBA fixados em auto_tests/tools/gaslux_popos_six_gpt_contract.py e no schema. Os 28 GiB de raiz correspondem à dimensão que já suportou instalação nativa completa; não se depende de compressão. Todas as áreas não alocadas e a GPT primária/secundária ficam proibidas no write-set.

## Implementação e limites de confiança

A preparação só funciona num novo diretório privado RUNNER_TEMP/gaslux-pop-six-gpt-* num GitHub-hosted runner Linux com consentimento específico de **preflight-only**. Usa ficheiros regulares O_EXCL; sgdisk --verify e sfdisk --json fornecem validação GPT e CRC sem novo parser binário. mkfs.fat -s 8 configura a ESP Pop com FAT32 de 4 KiB por cluster, conforme o ensaio de EFI [#44891786929](https://github.com/LMhdez/gaslux/actions/runs/44891786929). A raiz é formatada apenas no RAW sintético antes do checkpoint.

Além dos testes de identidade via blkid, o preflight executa duas rondas independentes de `fsck.fat -n` e `e2fsck -fn` sobre **cópias temporárias e dispersas** das partições FAT32 #1/#5 e ext4 #6, antes e depois da injeção de falha/recuperação. Nunca executa fsck sobre o RAW imutável, o filho QCOW2 ou `/dev/*`. Guardam-se `filesystem-fsck-before.json` e `filesystem-fsck-after.json`, vinculados à transação e com permissões de produção falsas. O resultado só significa integridade nos sistemas de ficheiros sintéticos preparados, não Linux instalado.

O checkpoint contém SHA-256 do RAW completo, PMBR/GPT e GPT backup, quatro hashes integrais de regiões protegidas, ficheiro-canário em EFI/Microsoft/GASLUX-SIMULATED-PROTECTED-CANARY.txt na ESP simulada, canários nos setores protegidos #2–#4 e em quatro setores não atribuídos. O child QCOW2 tem backing absoluto conhecido e começa sem alocações próprias. OVMF VARS usa cópias privadas, não o template partilhado.

Uma experiência separada de recuperação injeta uma escrita numa cópia COW da partição #3 **simulada**, verifica recusa, descarta só a cópia e recria uma vazia a partir do checkpoint. Injeta também uma falha numa cópia VARS independente, rejeita diferenças e comprova recuperação idêntica. Nenhum mecanismo toca em disco físico, /dev/loop, ESP Microsoft genuína ou Windows.

O contrato de write-set permite apenas setores totalmente contidos em #5 ou #6. Recusa GPT primária/secundária, PMBR, #1–#4, setores não alocados, operações discard/zero, limites inválidos, manifestos divergentes, hashes alterados, symlinks e hardlinks. O verificador de trace QEMU é **inertemente offline**, para uso após futura revisão de topologia com um único disco virtio gravável; não demonstra completude da observação. O resumo nominal mantém observationComplete=false, guestBioCompletionVerified=false e ovmfTransientWritesProvenAbsent=false.

O plano fixa ISO SHA-256 a0ef3842ab710db4f4407cf3499560b59dddbbcd59bee17beab7b0e99dc22b4c, GPG FPR 63C46DF0140D738961429F4E204DD8AEC33A7AFF e ELF distinst SHA-256 8bfedbc2d6921c440449ec1fda8c4e4d1c0078d69db5aa5832d9a7bf8b13e1a5. **Não se descarrega nem autentica ISO neste preflight** (isoIndependentlyAuthenticatedHere=false). Metadados inertes fixam apenas os seletores reuse de #5 e #6 e --no-efi-vars. Não existem comandos de instalação.

## CI e artefactos

.github/workflows/popos-six-gpt-preflight-only.yml corre apenas contratos Python, regressões Pop/Windows deny-only, Ruff, schema, preparação e recuperação com ficheiros sintéticos num runner GitHub. Não instala QEMU, não invoca System76, não inicia máquina virtual. Os artefactos incluem apenas JSON de prova e hashes; não incluem RAW, QCOW2, firmware, discos Windows ou ISOs.

Campos obrigatórios permanentemente false:
productionInstallationAuthorized, windowsWriterAuthorized, sameDiskDualBootVerified, windowsInPlaceRollbackProven, releaseEligible, stable.

## Gate operacional seguinte

Revisão GASLUX-SAFETY **específica** antes de sequer propor a única experiência QEMU nativa seis-GPT. Aprovação deve confirmar inventário de seis PARTUUID, canários, checkpoint, cadeia QCOW2, serial/dispositivo vinculado à transação, monitorização externa QEMU e eventos de descarte, integridade de GPT e ESP protegida, segregação OVMF e condições de recusa. Uma aprovação autoriza no máximo **um laboratório sintético Linux-only**, não escritor Windows nem dual boot.

Preflight sintético e recuperação por descarte do overlay NÃO são rollback Windows in-place, dual boot, atualização segura ou estabilidade.


## Correções Safety F-01–F-04 (PR #296, apenas preparação)

- **F-01:** o workflow deixa de executar `rm -rf` e o laboratório deixa de fazer `unlink` dos filhos, VARS e cópias de fsck. O exportador abre o diretório por FD, verifica dev/inode, recusa symlinks/hardlinks e preserva o diretório original em caso de troca de pathname. Os ficheiros temporários são deixados ao mecanismo de descarte do runner. **Limite:** POSIX não oferece `unlinkat` condicional por inode; perante adversário concorrente da mesma UID não há prova suficiente para limpeza ativa. A ausência de eliminação deliberada é a medida fail-closed. O exportador não autentica por si só o conteúdo produzido por processos não fiáveis.
- **F-02:** o parser de trace só aceita uma operação por registo, com gramática integral e um único identificador virtual, recusa concatenação, discard/zero e eventos desconhecidos. Mesmo um trace aceite é **PARSED_UNTRUSTED**, não uma atestação de QEMU/FD/child/backing/transação nem barreira preventiva. `observedWritesConfinedToOwnedPopPartitions=false` e `observationComplete=false`.
- **F-03:** uma falha injetada só é detetada por extents QCOW2 alocados na janela esperada; exceção tipada distinta de falhas de ferramenta, JSON ou timeout. O filho corrompido fica retido para diagnóstico e outro filho é criado com exclusividade e validado.
- **F-04:** mapas QCOW2 exigem cobertura contígua completa, tipos coerentes e ausência de alocações próprias, incluindo `depth=0,zero=true`. Um mapa textual não prova por si só autenticidade do backing.

Nenhum resultado autoriza execução System76, QEMU guest, Windows genuíno, operações de produção ou merge. Reauditoria independente GASLUX-SAFETY é obrigatória.
