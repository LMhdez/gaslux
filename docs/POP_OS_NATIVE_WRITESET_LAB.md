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


## Evidência terminal do ELF real — 20/11/2026 10:07 UTC

A observação CLI foi **executada efetivamente** no Pop 24.04 live
autenticado pelo pipeline do [QEMU Actions #44714481745](https://github.com/LMhdez/gaslux/actions/runs/44714481745),
HEAD `efeedcd60a8868d06d1d80e16479dcd19628f708`.
Ambos os jobs terminaram SUCCESS. Este commit **não é** o HEAD
atual da PR #232, mas inclui integralmente o código da observação
real e os seus verificadores do host.

O ELF extraído da ISO build20 e revalidado pelo convidado é
SHA-256 `8bfedbc2d6921c440449ec1fda8c4e4d1c0078d69db5aa5832d9a7bf8b13e1a5`.
O relatório `distinstReadonlyObservation` preservado em
`win10-pop-live-gpt.json` indica `argv=["/usr/bin/distinst","--help"]`,
`cliElfExecutedForHelp=true`, `cliHelpExitCode=0`, **30 linhas de
opções efetivas**, e SHA-256 do stdout
`c370c349e13d5b7fff5331e6b601cde72dcc72fd5dda9373bfad3259ffd3a0e0`.
O stderr estava vazio (SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).

**Opções relevantes efetivamente listadas no ELF:** `--block`,
`--use`, `--squashfs`, `--remove`, `--new-table`, `--move`,
`--delete`, `--new`, `--test`, `--force-bios`, `--force-efi`,
`--no-efi-vars`, `--modify-boot`, `--lang`, `--keyboard`,
`--hostname`, `--username`, `--tz` e opções LVM.
O texto de ajuda de `--test` descreve teste da fase de
particionamento, mas a inspeção de Rust mostra que essa fase pode
efetuar escritas e montagens antes do retorno antecipado. Não foi
invocada. A CLI não forneceu uma opção de planeamento sem efeitos
demonstráveis para caracterizar o write-set completo.

O [artefacto #14619163774](https://github.com/LMhdez/gaslux/actions/runs/44714481745/artifacts/14619163774)
foi descarregado e o digest ZIP SHA-256
`690e7ed7aa3deed852a7a56d392d1ce92188f59172a6379baa90913b798da105`
foi verificado. Foram confrontados os **oito sidecars SHA-256** com
os respetivos conteúdos: **oito válidos, zero discrepâncias**.
`guestGpt` confirma GPT de seis entradas, CRCs primária/secundária,
partições Windows #1–#4 imutáveis no inventário e
`diskWritePerformed=false`. O QEMU terminou com shutdown limpo.
`win10-pop-native-child-checkpoint.json` comprova criação e
eliminação do segundo QCOW2 com hashes dos dois pais conferidos.

**Limite da prova:** a imagem Windows foi apresentada ao guest
como `readonly=on`, mas esta execução não instrumentou as operações
internas de uma instalação. Não há prova de operações reais
`disk.commit`, `mkfs`, mount do alvo, instalação de rootfs,
systemd-boot ou NVRAM. `nativeInstallObserved=false`,
`diskWritesIndependentlyTraced=false`,
`writeSetConfinementEstablished=false`,
`distinstExecutionAuthorized=false`, `rollbackVerified=false`
e `popInstalled=false`. O resultado é **B (CLI read-only real)**;
não é A, P3, dual boot ou estabilidade.


## Laboratório QEMU independente de Windows — 20/11/2026, 11:40 UTC

A intervenção implementou um ensaio separado na
[workflow `popos-synthetic-qemu-write-trace.yml`](../.github/workflows/popos-synthetic-qemu-write-trace.yml),
com os módulos
`auto_tests/tools/windows10_popos_synthetic_qemu_write_smoke.py`
e `auto_tests/tools/windows10_popos_synthetic_qemu_trace_contract.py`.

### Desenho da prova e isolamento

1. Executar apenas em GitHub-hosted Ubuntu 24.04 com `/dev/kvm`,
   `GITHUB_REPOSITORY=LMhdez/gaslux` e consentimento específico
   `I_ACCEPT_ONLY_DISPOSABLE_SYNTHETIC_QEMU_WRITE_TRACE`.
2. Criar um **novo ficheiro regular raw** de 8 GiB, modo exclusivo
   `xb` (não um dispositivo de bloco), com GPT sintética e GUID
   `a6784e03-11a6-4544-b61c-87b66db8e117`, ESP #1 de 64 MiB e
   raiz #2 de 2 GiB. O intervalo de teste no LBA `196608`
   (96 MiB, 512 bytes) fica **fora** dessas partições e das GPT.
3. Validar a GPT sintética primária/secundária com `sgdisk --verify`,
   calcular SHA-256 do raw, criar um QCOW2 filho com backing
   explícito `raw`, e verificar via `qemu-img info --output=json`.
   O raw pai nunca é entregue ao QEMU como drive.
4. Obter a ISO Pop 24.04 Intel build20 pelo verificador GPG
   pré-existente; extrair novamente o hash do ELF do mesmo SquashFS
   e exigir o SHA-256 já observado independentemente:
   `8bfedbc2d6921c440449ec1fda8c4e4d1c0078d69db5aa5832d9a7bf8b13e1a5`.
5. Controlos de boot/OVMF exclusivamente privados:
   GRUB EFI num ficheiro raw temporário, controlo FAT com script
   autorizado e SHA-256, control disk e ISO apenas **read-only**,
   NVRAM OVMF em cópia privada, sem rede ou disco externo.
   Entre as cinco entradas `-drive` do QEMU, os **únicos ficheiros
   escritos** devem ser a cópia NVRAM e o child QCOW2 sintético.
6. Em Pop live, após verificar serial `GASLUX_POP_SYNTH`, geometria
   exata (8 GiB, 512 bytes/setor) e ausência de outro disco RW,
   executar **apenas** um `write(512)` com padrão fixado em
   96 MiB; confirmar leitura de retorno e `fsync`. Este primeiro
   ensaio é propositalmente um writer `python3`, **não o `distinst`**.
7. O host QEMU, fora do processo guest, regista pedidos
   `virtio_blk_handle_write` com os setores e comprimentos.
   O parser exige a escrita prevista no LBA `196608` e recusa
   qualquer outro offset, GPT primária/secundária, formatação ESP,
   operação desconhecida ou evento não classificado.
8. Terminado QEMU, `qemu-img dd` lê o setor da vista QCOW2,
   confirmando os 512 bytes exatos. Compara ainda bytes de
   MBR + GPT primária (LBA 0..33) e GPT backup
   (últimos 33 setores) entre o raw pai e a vista do filho.
   Depois verifica SHA-256 do pai, apaga o filho e volta a
   verificar que o pai está intacto.
9. Apenas são publicados JSON, eventos de escrita textuais
   e respetivos sidecars SHA-256; **nunca ISO, raw, QCOW2,
   NVRAM ou material privado**. Todos os ficheiros de trabalho
   ficam num diretório temporário do runner.

### Limites da monitorização e comparação com #232

O trace é emitido pelo QEMU, não pelo próprio instalador; permite
observar pedidos ao dispositivo virtio. **Não** comprova sucesso
atómico de cada pedido, ausência de escritas transitórias fora
dos eventos selecionados, atividades de discard/write-zeroes,
montagens internas, paths EFI ou o processo guest que iniciou
cada pedido. Alterações à NVRAM privada são avaliadas com hashes
antes/depois; a sua granularidade continua não instrumentada.

A operação de teste é sobre espaço sintético ainda não alocado.
**Não corresponde** ao write-set seis-GPT Windows da #232
(formatações ESP #5 e root #6), nem pode ser convertida
numa autorização de escrita de `distinst`. O relatório mantém
`distinstExecutionAuthorized=false`,
`diskWritesAuthorizedForWindows=false`,
`windowsEspWritesAuthorized=false`,
`installerWritesObserved=false`,
`windowsWriteSetMatchProven=false`,
`productionInstallationAuthorized=false`
e `rollbackAfterNativeInstallVerified=false`.

Uma execução modificadora do `distinst` exigirá **nova experiência**
em child sintético, depois de provar que o monitor observa pedidos
conhecidos e que nenhuma unidade Windows está acessível.
Como já demonstrado em fonte upstream, `--test` não é dry-run:
pode alterar a tabela de partições e formatar antes do retorno.
Nenhuma alteração aos módulos Safety #267 nem às proteções
da instalação nativa com Windows genuíno foi feita.


### Falha QEMU sintética e correção causal (20/11/2026, 12:04 UTC)

A execução [Actions #44732506603](https://github.com/LMhdez/gaslux/actions/runs/44732506603)
arrancou **realmente** o Pop live da ISO autenticada em QEMU,
montou o controlo FAT readonly e verificou
`synthetic-smoke.sh: OK`, mas recusou antes da escrita.
[Artefacto de diagnóstico #14626523648](https://github.com/LMhdez/gaslux/actions/runs/44732506603/artifacts/14626523648),
digest ZIP `sha256:3686f250c804a8a1989bef6001ce29d61368f975345a0dc3c79ea765831ddb90`.

O serial demonstrou:

```text
GASLUX_SYNTH_GUEST_VM_TYPE=kvm
GASLUX_SYNTH_GUEST_SERIAL_SEEN=GASLUX_POP_SYNTH
GASLUX_SYNTH_GUEST_RW_DISKS=zram0
vdc
```

O `zram0` é o mecanismo virtual de memória comprimida do
Pop live e aparece em `lsblk -dn -o NAME,TYPE,RO` como
`disk` gravável. O guard original confundia-o com segundo disco
anexado, impedindo a escrita sintética esperada. A correção
[commit `6d20d4f`](https://github.com/LMhdez/gaslux/commit/6d20d4f1e1de912ba50885b61256b569437f21cb)
exclui **somente** nomes `zram[0-9]+` cuja localização real
seja `/sys/devices/virtual/block/zramN`; qualquer outro
disco gravável, serial diferente, geometria incorreta ou ausência
de identidade prossegue em recusa.

Não houve alterações à autorização da instalação Windows nem
ao Safety #267. Esta falha **não comprova escritas**; o monitor
externo de QEMU permaneceu vazio e o child descartável foi
eliminado. A execução modificadora de `distinst` continua
bloqueada.


## Execução real do distinst em QCOW2 sintético — 20/11/2026, 15:38 UTC

### Resultado

**Critério A atingido para a fase real `distinst --test` de particionamento/formatação, com recusa de write-set.**
Isto não é uma instalação Pop completa nem prova de dual boot.

[Actions #44764397442](https://github.com/LMhdez/gaslux/actions/runs/44764397442)
executou o monitor conhecido e, depois, o `distinst` real numa VM QEMU/KVM
isolada. O job QEMU terminou em `REFUSE_OUT_OF_WRITESET`; o job de contratos
terminou SUCCESS. A recusa é o resultado de segurança esperado para as
escritas GPT observadas, não uma autorização parcial.

### Identidade e isolamento

- QEMU `8.2.2`, KVM, Pop!_OS 24.04 Intel live; assinatura GPG System76
  confirmada (`Good signature`).
- ELF real `/usr/bin/distinst`: SHA-256
  `8bfedbc2d6921c440449ec1fda8c4e4d1c0078d69db5aa5832d9a7bf8b13e1a5`;
  Build ID `9a96a9af917303020505cf71d6d90943c4d2bc79`.
- Versão Debian observada:
  `0.3.2~1758837686~24.04~e395b7c`. O sufixo `e395b7c` é uma
  **indicação de revisão**, não prova de proveniência reprodutível:
  `upstreamCommitMatchProven=false` e
  `reproducibleBuildProvenanceVerified=false`.
- O commit upstream candidato é
  [`e395b7cb4d32ab3ca0cb2e9e557bd2ba53973148`](https://github.com/pop-os/distinst/commit/e395b7cb4d32ab3ca0cb2e9e557bd2ba53973148).
- Apenas um QCOW2 filho de disco GPT sintético de 8 GiB foi apresentado
  como destino gravável, serial `GASLUX_POP_DIST`, GUID
  `7d6e5c4b-3a29-4876-9abc-def012345678`. O raw backing, ISO, controlo FAT
  e OVMF_CODE foram read-only; OVMF_VARS era uma cópia descartável.
  Não havia disco Windows nem NIC na VM.

### Monitor independente — calibração antes do distinst

O primeiro estágio fez uma escrita conhecida de 4096 bytes no offset
`100663296` (96 MiB) de outro destino sintético. O evento
`virtio_blk_handle_write` do QEMU correspondeu exatamente ao intervalo;
o hash do backing permaneceu igual e o QCOW2 filho foi descartado.
O relatório confirma `exactSyntheticSmokeEventMatched=true`,
`baseImageSha256Unchanged=true` e `privateChildDiscarded=true`.
O artefacto de calibração está incluído no ZIP abaixo.

### Execução real e argumentos

O processo terminou com exit code 0, sem timeout. A linha de comando
observada no convidado foi equivalente a:

```text
/usr/bin/distinst
  --squashfs /cdrom/casper_pop-os_24.04_amd64_intel_debug_377/filesystem.squashfs
  --remove /cdrom/casper_pop-os_24.04_amd64_intel_debug_377/filesystem.manifest-remove
  --hostname gaslux-pop-synth
  --block /dev/vdc
  --use /dev/vdc:1:fat32:mount=/boot/efi:flags=esp
  --use /dev/vdc:2:ext4:mount=/
  --no-efi-vars
  --test
```

Não foram passados `--new-table`, `--new` nem `--modify-boot`.
`--no-efi-vars` foi passado. O ensaio não executou a fase de bootloader.

### Descoberta crítica: --use não preservou as entradas GPT

O log emitido pelo próprio processo mostra que, apesar de usar
`--use` para as duas partições existentes, o distinst:

1. Configurou e fez commit da tabela.
2. Executou `remove operations`, removendo as entradas nos setores
   2048 e 1052672.
3. Executou `creation operations`, recriando as duas partições nos
   mesmos offsets.
4. Executou `mkfs.fat -F 32 /dev/vdc1` e
   `mkfs.ext4 -F -q -E lazy_itable_init /dev/vdc2`.
5. Imprimiu que estava a montar os destinos e terminou com
   `PARTITION_TEST enabled: exiting before unsquashing`.

A observação independente do QEMU confirmou os pedidos de escrita GPT;
o tracefs do convidado atribuiu as escritas GPT ao processo `distinst`
(PID 1349). O estado posterior tinha CRCs primária/secundária válidos e
iguais, mas as identidades/entradas não foram preservadas:

- PARTUUID ESP: `1a2b3c4d-5e6f-4789-8abc-def012345678` →
  `ad94aedd-0bbf-4cb6-ad30-3dd29b63c666`.
- PARTUUID root: `2b3c4d5e-6f70-489a-bcde-f0123456789a` →
  `91e017d7-9d77-4525-b2b3-5765b03ba8ae`.
- `endLba` ESP: 1050623 → 1050622.
- `endLba` root: 9441279 → 9441278.
- GUID do disco permaneceu igual; CRCs GPT primária/secundária foram
  novamente validados; os arrays primário e secundário coincidiram.

**Implicação:** não é seguro inferir que `--use` apenas reutiliza uma
partição sem reescrever a tabela. Este build remove e recria as entradas
no ensaio observado. A PR #232 não autoriza estes writes GPT; o contrato
recusou-os e não será alargado para os permitir sem um novo plano e prova
de recuperação.

### Contabilidade de escritas

O QEMU registou `virtio_blk_handle_write` independentemente do
`distinst`:

| Região | Pedidos QEMU | Bytes |
|---|---:|---:|
| ESP sintética (partição 1) | 11 | 1 070 080 |
| Root sintética (partição 2) | 184 | 69 529 600 |
| GPT primária/PMBR | 3 | 61 440 |
| GPT secundária | 3 | 61 440 |
| **Total** | **201** | **70 722 560** |

Os seis pedidos fora do write-set cobriram 40 setores por pedido,
três na GPT primária/PMBR e três na GPT secundária: 122 880 bytes.

O `block_bio_queue` do kernel registou 6490 eventos de escrita
(70 722 560 bytes) e 47 flushes. Os seus 30 eventos fora do write-set
foram atribuídos a `distinst` (PID 1349): 15 eventos de 8 setores
na GPT primária e 15 na GPT secundária. Os bytes e a cobertura
corresponderam aos pedidos QEMU.

O tracepoint `block_rq_issue` registou **zero** eventos. Por isso,
a classificação final, corrigida nesta intervenção, é deliberadamente:
`guestTracefsBioQueueCorroboratesQemu=true`,
`guestTracefsCorroboratesQemu=false` e
`observationComplete=false`. A evidência QEMU/bio demonstra os
pedidos observados, mas não prova cobertura completa de todas as
camadas de I/O.

### Formatação, montagens, EFI e NVRAM

- `mkfs.fat` e `mkfs.ext4` foram observados como processos
  independentes (PIDs 1370 e 1371); os sistemas de ficheiros resultantes
  foram identificados como vfat e ext4 e as verificações read-only
  terminaram sem erro.
- O log do `distinst` declara `mounting all targets` e mostra os
  destinos temporários. Contudo, os tracepoints disponíveis
  `sys_enter_mount` e `sys_exit_mount` produziram zero eventos.
  Os argumentos de montagem não foram resolvidos; portanto, montagens
  não são consideradas independentemente comprovadas. Os logs do
  próprio instalador não substituem a observação.
- O candidato upstream chama `mount_all_targets` antes do retorno
  `PARTITIONING_TEST`, em
  [`src/installer/mod.rs`](https://github.com/pop-os/distinst/blob/e395b7cb4d32ab3ca0cb2e9e557bd2ba53973148/src/installer/mod.rs#L165-L184),
  mas a correspondência binário-fonte não está provada.
- O hash persistente OVMF_VARS antes/depois do processo foi igual:
  `ffc048547271db2301940c6a15a48bae1f818c3d898edce2b913d95ff7b41457`.
  O trace QEMU da sessão inteira contém 50 825 eventos pflash,
  todos em `system.flash1` (incluindo 16 877 `pflash_data_write`).
  O ficheiro não tem timestamps que permitam atribuir esses eventos à
  fase do distinst; por isso, ausência de escritas transitórias NVRAM
  **não está provada**.
- Não houve extração/instalação da rootfs, instalação systemd-boot,
  criação de entrada EFI ou primeiro arranque Linux. O próprio processo
  terminou antes de `unsquashing`.

### Integridade e artefactos

- Raw backing SHA-256 antes/depois:
  `e11355db859d24980a9866a72d87d13a90cbead0f9dedfcc7bee00cf85f0e9a7`.
- `qemu-img check`: sem erros; backing chain verificada.
- QCOW2 filho existia antes da limpeza e foi eliminado depois;
  hash do backing permaneceu igual após a limpeza.
- OVMF_VARS era descartável. Nenhuma imagem de disco, ISO ou NVRAM foi
  publicada no artefacto.
- [Artefacto #14643831419](https://github.com/LMhdez/gaslux/actions/runs/44764397442/artifacts/14643831419):
  ZIP SHA-256
  `e929a8f41c9d6490e0a38534f5b29f5a4844f948ddb481c8dc18d46597f883ed`.
  Os 11 sidecars SHA-256 foram verificados contra os respetivos ficheiros.
- Trace QEMU completo: 2 997 058 bytes, SHA-256
  `bc236d1b6aca41e73a96cbc472b442a16b059b53b5dbd347dba9decb1ca42a1e`.
- Tracefs convidado: 1 083 854 bytes, SHA-256
  `cc4674dd7bbf1858716c4d6e3cf4507529e31c7a7fa16c4052045be56e3e71df`.

### Decisão

`REFUSE_OUT_OF_WRITESET`; `distinstExecutionAuthorized=false`;
`diskWritesAuthorizedForWindows=false`;
`windowsEspWritesAuthorized=false`. A recusa foi mantida apesar do
exit code 0 do instalador. Não foram modificados módulos Safety #267,
nem gates Windows.

A execução comprova a fase de particionamento/formatação do distinst
autêntico sobre disco sintético e demonstra que o write-set atual não
contém as escritas GPT que o binário efetua. Não comprova instalação
Pop completa, bootloader, dual boot, atualização ou rollback pós-write.


### Semântica dos argumentos — fonte upstream candidata e uso real

A CLI no commit candidato
[`cli/src/main.rs`](https://github.com/pop-os/distinst/blob/e395b7cb4d32ab3ca0cb2e9e557bd2ba53973148/cli/src/main.rs#L108-L171)
declara:

| Argumento | Semântica declarada | Nesta execução |
|---|---|---|
| `--block` | Disco a manipular | `/dev/vdc` |
| `--use` | Reutilizar partição existente | ESP e root sintéticas |
| `--new` | Criar nova partição | Não passado |
| `--new-table` | Criar tabela nova, clobbering a existente | Não passado |
| `--test` | Testar a fase de particionamento | Passado; não é dry-run |
| `--no-efi-vars` | Desativar montagem de efivars | Passado |
| `--modify-boot` | Modificar ordem de arranque após instalação | Não passado |

No candidato upstream, a fase
[`steps/partition.rs`](https://github.com/pop-os/distinst/blob/e395b7cb4d32ab3ca0cb2e9e557bd2ba53973148/src/installer/steps/partition.rs#L8-L36)
faz `disk.commit()` e executa formatação antes de
[`installer/mod.rs`](https://github.com/pop-os/distinst/blob/e395b7cb4d32ab3ca0cb2e9e557bd2ba53973148/src/installer/mod.rs#L165-L184)
chamar `mount_all_targets` e só depois retornar por
`PARTITIONING_TEST`. A implementação candidata de
[`mount_all_targets`](https://github.com/pop-os/distinst/blob/e395b7cb4d32ab3ca0cb2e9e557bd2ba53973148/crates/disks/src/config/disks.rs#L185-L265)
usa `sys_mount::Mount::new`. Estes links documentam a revisão
candidata; não provam que o ELF foi reproduzido exatamente dessa fonte.
