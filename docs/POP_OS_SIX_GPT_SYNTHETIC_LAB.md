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

Uma experiência separada injeta uma escrita de 4096 bytes com padrão 0x5a numa cópia COW da partição #3 **simulada**. A deteção exige simultaneamente identidade do child fixada por descritor, backing e transação validados, extent de dados pertencente ao child no intervalo esperado e leitura do padrão através de `qemu-io -P`. Falhas do executável, JSON inválido, timeout ou troca de inode não produzem `ProtectedFaultDetected`. O child injetado é **abandonado, não eliminado por pathname**; a recuperação utiliza outro child criado exclusivamente, confirmado vazio. A cópia OVMF VARS injetada também é abandonada; a restauração é comprovada numa nova cópia com outro nome. Os ficheiros são eliminados apenas pelo descarte externo do runner efémero, não por uma rotina de limpeza baseada em pathnames. Isto não é recuperação Windows in-place.

O contrato de write-set permite apenas setores totalmente contidos em #5 ou #6. Recusa GPT primária/secundária, PMBR, #1–#4, setores não alocados, operações discard/zero, limites inválidos, manifestos divergentes, hashes alterados, symlinks e hardlinks. O verificador de trace QEMU é **inertemente offline**, para uso após futura revisão de topologia com um único disco virtio gravável; não demonstra completude da observação. O resumo nominal mantém observationComplete=false, guestBioCompletionVerified=false e ovmfTransientWritesProvenAbsent=false.

O plano fixa ISO SHA-256 a0ef3842ab710db4f4407cf3499560b59dddbbcd59bee17beab7b0e99dc22b4c, GPG FPR 63C46DF0140D738961429F4E204DD8AEC33A7AFF e ELF distinst SHA-256 8bfedbc2d6921c440449ec1fda8c4e4d1c0078d69db5aa5832d9a7bf8b13e1a5. **Não se descarrega nem autentica ISO neste preflight** (isoIndependentlyAuthenticatedHere=false). Metadados inertes fixam apenas os seletores reuse de #5 e #6 e --no-efi-vars. Não existem comandos de instalação.

## Limites de propriedade e de observação (F-01 a F-04)

O workflow seis-GPT deixa de executar `rm -rf` e não autoriza `unlink()`, `rmdir()` ou substituição de recursos por pathname. O controlador `gaslux_popos_six_gpt_ownership.py` fixa descritores dos diretórios privado, pai e evidência, verifica `st_dev/st_ino`, UID, permissões e inventário fechado dos ficheiros. Cada ficheiro observado mantém um descritor original aberto; substituição de nomes/inodes, hardlinks, symlinks, diretórios trocados, ficheiros inesperados ou criação parcial provocam recusa sem apagar recursos de origem incerta. Os quatro JSON de prova são exportados por descritor de diretório com `O_CREAT|O_EXCL|O_NOFOLLOW` e limite de dimensão. Com ENOSPC pode restar evidência **parcial**, nunca uma prova positiva de CI. Não se exportam RAW, QCOW2 ou firmware.

**Limitação de ameaça:** em POSIX, `stat()` seguido de `unlink()` não permite comparar/remover atomicamente o inode perante adversário da mesma UID. A estratégia adotada é **não eliminar nada** por pathname. Os utilitários externos legados (`sgdisk`, `mkfs`, `qemu-img`, `qemu-io`, `mcopy`) ainda abrem pathnames por iniciativa própria; o monitor deteta substituições antes/depois de cada etapa, mas isso **não impede necessariamente corridas durante uma chamada**. A autorização de escrita continua negada. Não se deve extrapolar esta propriedade para execução concorrente hostil, discos reais ou produção. Requer auditoria Safety e eventual isolamento reforçado antes de qualquer writer.

O parser textual QEMU aceita, no máximo, uma identidade virtio coerente, recusa eventos desconhecidos, concorrência de dispositivos, concatenação, discard, zeroes e setores inválidos; o resultado é apenas `PARSED_UNTRUSTED`. `traceProvenanceAuthenticated=false`, `virtioDeviceBound=false`, `observationComplete=false` e confinamento independentemente autenticado são sempre falsos. Não existe qualquer autorização a partir de traces fornecidos pelo produtor.

O mapa `qemu-img` é validado com cobertura integral, sequência contígua e tipos estritos; é recusado qualquer extent relevante introduzido no overlay, incluindo `depth=0,data=false,zero=true`. O contrato reconhece o campo `compressed` realmente devolvido pelo `qemu-utils` 8.2.2 sem aceitar campos arbitrários. Ensaios offline exercitam child vazio, escrita de dados, zero-mapping, mapa malformado/omisso/sobreposto e backing errado, sem arrancar guests.

## CI e artefactos

.github/workflows/popos-six-gpt-preflight-only.yml corre apenas contratos Python, regressões Pop/Windows deny-only, Ruff, schema, preparação e recuperação com ficheiros sintéticos num runner GitHub. Instala apenas `qemu-utils` para `qemu-img` e `qemu-io` em ficheiros QCOW2 descartáveis. Não invoca `qemu-system`, `distinst` ou System76, nem inicia qualquer máquina virtual. O job de preparação/recuperação depende de contratos, regressões, lint, formatação, schema e ShellCheck aprovados. Os artefactos incluem apenas JSON de prova e hashes; não incluem RAW, QCOW2, firmware, discos Windows ou ISOs.

Campos obrigatórios permanentemente false:
productionInstallationAuthorized, windowsWriterAuthorized, sameDiskDualBootVerified, windowsInPlaceRollbackProven, releaseEligible, stable.

## Gate operacional seguinte

Revisão GASLUX-SAFETY **específica** antes de sequer propor a única experiência QEMU nativa seis-GPT. Aprovação deve confirmar inventário de seis PARTUUID, canários, checkpoint, cadeia QCOW2, serial/dispositivo vinculado à transação, monitorização externa QEMU e eventos de descarte, integridade de GPT e ESP protegida, segregação OVMF e condições de recusa. Uma aprovação autoriza no máximo **um laboratório sintético Linux-only**, não escritor Windows nem dual boot.

Preflight sintético e recuperação por descarte do overlay NÃO são rollback Windows in-place, dual boot, atualização segura ou estabilidade.
