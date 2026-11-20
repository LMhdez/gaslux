# Pop!_OS 24.04 / System76 — six-GPT write-set (experimental)

**Estado: FAIL-CLOSED; nenhuma instalação nativa autorizada em Windows genuíno.**

Este relatório regista as operações identificadas na implementação upstream
`pop-os/distinst`, commit
[282dfc441ee608e963930d0ce01f04b672ca4f71](https://github.com/pop-os/distinst/tree/282dfc441ee608e963930d0ce01f04b672ca4f71).
**A leitura deste código não prova que o ELF da ISO Pop autenticada foi compilado
exatamente a partir desse commit.** Esta correspondência e a instrumentação do
binário real continuam necessárias antes de qualquer escrita.

## Evidência do laboratório

- [PR #232](https://github.com/LMhdez/gaslux/pull/232).
- [Actions #44704752379](https://github.com/LMhdez/gaslux/actions/runs/44704752379):
  Windows 10 genuíno e Pop 24.04 live arrancados no mesmo QCOW2, GPT de seis
  partições auditada sem executar a instalação.
- [Actions #44706721311](https://github.com/LMhdez/gaslux/actions/runs/44706721311):
  sucesso no HEAD `7c3ba65399de`, Windows 10 genuíno e Pop live, GPT verificada, filhos QCOW2 e SHA de ambos os pais verificados, filho criado/destruído, encerramento controlado, `distinstExecutionAuthorized=false`. Artefacto [#14616336862](https://github.com/LMhdez/gaslux/actions/runs/44706721311/artifacts/14616336862), ZIP SHA-256 `ba217122e0af84d3edd8a7e44336291e9424f4cab756ac24bc596808ede8a263`.
- ISO fixada: build 20 Intel, 2955067392 bytes,
  SHA-256 `a0ef3842ab710db4f4407cf3499560b59dddbbcd59bee17beab7b0e99dc22b4c`;
  assinatura do manifesto GPG com fingerprint
  `63C46DF0140D738961429F4E204DD8AEC33A7AFF`.

## Sequência efetiva identificada no código upstream

| Componente | Comportamento | Risco/limite |
| --- | --- | --- |
| [`cli/src/configure/reuse.rs`](https://github.com/pop-os/distinst/blob/282dfc441ee608e963930d0ce01f04b672ca4f71/cli/src/configure/reuse.rs) | `:reuse` não pede formatação; `:ext4` chama `partition.format_with` e `flags=` pode alterar atributos | ESP Pop #5 apenas reuse; ext4 raiz #6; nenhum flags |
| [`cli/src/configure/mod.rs`](https://github.com/pop-os/distinst/blob/282dfc441ee608e963930d0ce01f04b672ca4f71/cli/src/configure/mod.rs) | Inscreve dispositivos passados por `--block` e processa operações de partições | Apenas disco virtio autenticado; proibir new-table/delete/move/new |
| [`src/installer/steps/partition.rs`](https://github.com/pop-os/distinst/blob/282dfc441ee608e963930d0ce01f04b672ca4f71/src/installer/steps/partition.rs) | Executa `disk.commit()` para discos registados, formata e faz `blockdev --rereadpt` | Efeitos GPT/PMBR ou partições estrangeiras não demonstrados |
| [`crates/disks/src/config/disk.rs`](https://github.com/pop-os/distinst/blob/282dfc441ee608e963930d0ce01f04b672ca4f71/crates/disks/src/config/disk.rs) | `commit` compara o estado; se não houver diff, não executa alterações; se houver, aplica remove/change/create | A invocação de commit não prova por si só uma escrita, nem garante ausência de uma |
| [`src/installer/steps/bootloader.rs`](https://github.com/pop-os/distinst/blob/282dfc441ee608e963930d0ce01f04b672ca4f71/src/installer/steps/bootloader.rs) | Pop UEFI chama `bootctl install --path=/boot/efi --no-variables` e `update-initramfs`; `efibootmgr --create` depende de MODIFY_BOOT_ORDER | Apenas ESP Pop #5, sem alteração BootOrder/BootNext |
| [`src/installer/steps/configure/chroot_conf.rs`](https://github.com/pop-os/distinst/blob/282dfc441ee608e963930d0ce01f04b672ca4f71/src/installer/steps/configure/chroot_conf.rs) | `kernelstub --esp-path /boot/efi ... --loader --manage-only --force-update`; lógica adicional de recovery quando montada | Pode escrever EFI/recovery; Windows ESP #1 e WinRE nunca podem ser montadas |
| [`src/installer/steps/mod.rs`](https://github.com/pop-os/distinst/blob/282dfc441ee608e963930d0ce01f04b672ca4f71/src/installer/steps/mod.rs) | `--no-efi-vars` evita bind-mount de efivars no chroot | Não substitui auditoria de NVRAM real |

## Contrato implementado

`auto_tests/tools/windows10_popos_native_write_set.py` reutiliza
`preview_native_handoff` e `reconcile_owned_pair`, sem duplicar a identidade do
disco administrada por GASLUX-SAFETY. Valida a proposta de transação,
correspondência do digest do handoff e dos checkpoints dos dois pais QCOW2,
GUID, serial, setores e exatamente seis GPT.

Recursos previstos: formatação FAT32 da ESP Pop #5, formatação ext4 da raiz
#6, montagens `/boot/efi` e `/`, instalação em #6 e ficheiros systemd-boot
em #5. A lista de exclusão inclui offsets/comprimentos completos de todas
as partições Windows #1–#4, `EFI/Microsoft`, BCD e WinRE.
Operações GPT/MBR, NVRAM, BootOrder/BootNext e qualquer alteração fora desses
intervalos são proibidas.

O script `windows10_popos_native_realwin10_install_guest.sh` tem uma **recusa incondicional antes de `mkfs.vfat` e `distinst`**, mesmo após prewrite sintético. Regressão estática confirma que o marcador `GASLUX_POP_NATIVE_WRITESET_UNPROVEN` antecede qualquer operação de escrita.

**Os booleanos no handoff e no checkpoint são apenas alegações do chamador.**
O digest liga os documentos, mas não substitui a assinatura com confiança
ancorada externamente. O adaptador nunca abre disco, não invoca programas,
não prepara um comando executável e devolve sempre
`distinstExecutionAuthorized=false` e
`productionInstallationAuthorized=false`.

## Bloqueios antes de qualquer instalação nativa

1. GASLUX-SAFETY deve definir um atestado partilhado de identidade e geometria
   ligado à transação, ao plano assinado e ao host/guest. Não alterar os seus
   contratos nesta branch.
2. Estabelecer checkpoint durável e recuperação operacional antes do primeiro
   write; verificar backing QCOW2 e SHA na mesma sessão do guest.
3. Instrumentar o `distinst` **extraído da ISO oficial autenticada** para
   medir a sequência de escritas, GPT primária/secundária, offsets, FAT,
   ext4, ESP Microsoft, EFI/systemd e OVMF NVRAM. Uma análise de código
   upstream ou CLI com `--use` não garante contenção efetiva.
4. Recusar se qualquer operação implícita ultrapassar #5/#6; só depois
   executar numa VM descartável e verificar arranque Pop e Windows,
   atualizações, BCD/WinRE e rollback.

A aprovação dos testes positivos prova somente um contrato inerte bem
formado. **Não há instalação, dual boot ou recuperação nativa comprovados.**


## Intervenção 20/11/2026 09:33 UTC — Safety #265 e distinst real

Na [PR Safety #265](https://github.com/LMhdez/gaslux/pull/265), HEAD
`8ed912c6934c33354b0a814201c7217043bd0197`, o módulo
`assets/live/libertix_disk_identity_gate.py` fornece leitura de imagem
regular GPT e comparação exata de identidade, geometria e partições
(`partitionStyle`, `partitionTableId`, `sizeBytes`,
`logicalSectorSizeBytes`, `partitions`). Não entrega qualquer assinatura
autenticada inter-ambiente Windows/QEMU/Linux nem permissão de escrever.

O adaptador Pop
`auto_tests/tools/windows10_popos_safety_attestation_adapter.py`
transforma **apenas linhas já medidas pela auditoria GPT Pop** no formato
Safety #265, sem reimplementar parser GPT. Compara snapshots e recusa
modificações ao GUID do disco, PARTUUID, offset, dimensão, quantidade de
partições ou geometria. Todos os pedidos de autorização
`assess_pop_safety_handoff()` são recusados, **até quando um JSON simula
assinatura, entidade emissora, validade e atestado host/guest**. A presença
desses campos não prova assinatura de origem independente.

`classify_distinst_trace()` compara operações sintéticas bem tipadas com
os intervalos declarados #5/#6. Rejeita eventuais alterações GPT/MBR,
formatação oculta, operação desconhecida, ESP Windows, destino EFI errado,
NVRAM, disco trocado, intervalos divergentes, ausência de medição
independente e alteração da cadeia QCOW2. **Mesmo com eventos
sintaticamente admissíveis, `allWritesObserved=false` e
`distinstExecutionAuthorized=false`**; não há prova de observação
completa de blocos ou ficheiros por fonte independente.

A execução QEMU real [#44706721311](https://github.com/LMhdez/gaslux/actions/runs/44706721311),
no HEAD histórico `7c3ba653`, confirmou a cadeia GPG da ISO build 20,
SHA-256 `a0ef3842ab710db4f4407cf3499560b59dddbbcd59bee17beab7b0e99dc22b4c`,
e o hash do executável `/usr/bin/distinst` observado no Pop live:
`8bfedbc2d6921c440449ec1fda8c4e4d1c0078d69db5aa5832d9a7bf8b13e1a5`.
Não corresponde necessariamente à revisão corrente do código upstream;
identidade de ELF e GPG são provas distintas.

O novo `auto_tests/tools/windows10_popos_distinst_readonly_observer.py`
prepara uma investigação **não gráfica** em convidado Pop 24.04 QEMU:
exige consentimento específico, sinal de manifesto GPG verificado e
hash exato do ELF; a única invocação é `/usr/bin/distinst --help`, sem
argumentos de disco. Não foi executado com a ISO nesta intervenção;
não representa trace de instalação, não consulta disco, não determina
eficácia de `disk.commit()`, nem comprova alteração de ESP/NVRAM. A
medição de chamadas de sistema e diferenças de setores num **disco
sintético sem Windows** é a próxima experiência dependente de
instrumentação e isolamento efetivos.

**Resultado B:** interface Safety publicada com recusas por falta de
autenticação; investigação reprodutível iniciada, mas **grafo de operações
real do instalador ainda não observado**. O script com Windows genuíno
continua a recusar incondicionalmente antes de `mkfs.vfat` e `distinst`.
Não se fez merge, instalação nativa, dual boot nem rollback pós-instalação.


## Intervenção 20/11/2026 09:45 UTC — execução autenticada de CLI read-only

### Safety #267
A [PR #267](https://github.com/LMhdez/gaslux/pull/267), HEAD
`f55633c90973f633dda678f583f7730fc2cdc0ce`, introduz
`libertix_prewrite_no_writer.py`. A saída de
`decide_no_writer` contém **exatamente**
`decision=ACCEPT_NO_WRITER`, `transactionId` (32 hex sem separadores),
`planSha256`, `vmId` e `writeCount`.
O contrato admite **apenas** `allocate-free-space` em regiões ainda
não particionadas. As partições Pop #5/#6 do cenário Windows 10 são
pré-existentes: formatar FAT32/ext4 ou instalar bootloader **não é**
uma operação admitida por #267. Mesmo com HMAC de laboratório válido,
`ACCEPT_NO_WRITER` continua a proibir qualquer writer.

O novo `interpret_safety267_no_writer` consome esse mesmo formato:
confronta transação, digest dos bytes canónicos do plano, VM, GUID,
capacidade e tamanho lógico de setor já declarados no contrato Pop.
Expõe apenas resultado diagnóstico com
`nativePartitionFormatterAllowed=false` e
`distinstExecutionAuthorized=false`, sem importação de chaves, sem
credenciais estáticas e sem atestação sintética forjada. HMAC não
substitui certificação da origem das medições host/guest.

### A opção CLI --test NÃO é dry-run

O código upstream fixado
[cli/src/main.rs](https://github.com/pop-os/distinst/blob/282dfc441ee608e963930d0ce01f04b672ca4f71/cli/src/main.rs#L144-L147)
ativa `PARTITIONING_TEST`, mas o retorno condicional surge
**depois** da fase `Step::Partition` e de
`mount_all_targets`, como se verifica em
[src/installer/mod.rs](https://github.com/pop-os/distinst/blob/282dfc441ee608e963930d0ce01f04b672ca4f71/src/installer/mod.rs#L141-L186).
A fase de particionamento pode chamar `disk.commit()`, alterar
metadados e formatar. Logo, **não** é permitido experimentar
`distinst --test` sobre o QCOW2 Windows nem assumir ausência de
efeitos só por constar "test" na CLI. A implementação Rust upstream
pode também divergir da versão realmente instalada na ISO fixada.

### Observação não gráfica do executável real

O laboratório `windows10-popos-signed-live-same-cow.yml` instala
Windows 10 numa VM de laboratório, arranca-o após o estágio GPT e
inicia o Pop live autêntico com a unidade alvo montada pelo QEMU
**exclusivamente read-only**. O controlo serial agora executa primeiro
a auditoria GPT, com manifesto GPG previamente validado no host, e
depois invoca `inspect_distinst_help()` no mesmo guest.

O observador recusa ELF divergente do SHA-256 já extraído da ISO,
exige QEMU, Pop 24.04, consentimento read-only, e chama
**somente** `/usr/bin/distinst --help` com timeout.
O relatório inclui SHA-256 do texto real apresentado pela CLI,
opções efetivamente listadas, código de saída e garantias negativas:
`nativeInstallObserved=false`,
`diskWritesIndependentlyTraced=false`,
`distinstExecutionAuthorized=false`. O host valida também
estes campos, verifica os GUIDs/GPT do QCOW2 e o shutdown controlado.

**Limite essencial:** o `--help` executa o ELF para descrever opções,
não caracteriza operações de particionamento/ESP/rootfs ou efeito de
escrita transitória. Nenhum grafo real de alterações de bloco é obtido
nesta execução. Observação da instalação efetiva exigirá VM sintética
independente, instrumentação autónoma e snapshot recuperável, com
permissão de laboratório específica.
