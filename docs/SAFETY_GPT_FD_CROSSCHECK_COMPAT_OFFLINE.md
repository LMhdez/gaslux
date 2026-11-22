# GPT FD / crosscheck / Safety — contrato executável OFFLINE (Draft)

## Fixação de origem

A prova é isolada sobre `dev`, sem modificar caminhos de instalação, rollback, schemas de produto ou estados. Em CI, são feitos **checkouts por SHA exato** do próprio repositório, em diretórios separados, com verificação `git rev-parse HEAD` e `git status --porcelain`. Os módulos originais são importados desses checkouts: **não existe segundo parser GPT** nem cópia divergente de `compare_evidence`, `compare_files`, `decide_no_writer` ou `consume_observer_state_no_writer`.

| Origem | SHA imutável | Interface efetiva |
|---|---|---|
| [#265](https://github.com/LMhdez/gaslux/pull/265) base GPT | `8ed912c6934c33354b0a814201c7217043bd0197` | `libertix_disk_identity_gate.py` anterior |
| [#286](https://github.com/LMhdez/gaslux/pull/286) | `9aed36cfdb8c09a461dc38811c326c54180273de` | `inspect_gpt_fd(fd, logical_sector_size=...)`, `assert_snapshot_matches` |
| [#289](https://github.com/LMhdez/gaslux/pull/289) | `e1618388cc996eb83c17cafbb7b0869837ff1af3` | `compare_evidence`, `compare_files`, recusas FD/TOCTOU |
| [#267](https://github.com/LMhdez/gaslux/pull/267) | `0be04192acd542646a5b6cd952e01620379edf5d` | `decide_no_writer`, `consume_observer_state_no_writer` |
| [#287](https://github.com/LMhdez/gaslux/pull/287) | `d7f72b42ef73a788ff1e9b192c732a989c575872` | substituído para este ensaio pela correção #289 |
| [#288](https://github.com/LMhdez/gaslux/pull/288) | `3357438635d4eac40a1fd48322bdf7aa14f84fd5` | `Scripts/modules/Libertix.StorageBaseline.psm1`, somente analisado; **não modificado** |

## Matriz explícita de campos

| #286 GPT por FD | #289 comparador | #288 Windows StorageBaseline | Resultado |
|---|---|---|---|
| `partitionStyle="GPT"` | `partitionStyle="GPT"` | `partitionStyle` | Igualdade estrutural; MBR recusado neste ensaio |
| `partitionTableId="gpt:<GUID>"` | `partitionTableId` (string, não validada como GUID) | `disks[].guid` | Mapear apenas quando GUID canónico e consistente; sem prova de disco físico |
| `sizeBytes` | `sizeBytes` | `disks[].sizeBytes` | Igualdade em bytes |
| `logicalSectorSizeBytes` | `logicalSectorBytes` | `disks[].logicalSectorSizeBytes` | Igualdade em bytes por setor; 512/4096 para #286 |
| `partitions[].partGuid` | `partitions[].id` | `partitions[].guid` | PARTUUID normalizado; sem usar números como identidade estável |
| `partitions[].typeGuid` | `partitions[].typeId` | `partitions[].gptType` | GUID de tipo normalizado |
| `partitions[].offsetBytes` / `sizeBytes` | mesmos campos | mesmos campos | Igualdade de extensões alinhadas |
| `partitions[].number` | ausente | `partitions[].number` | Não é identificador imutável; apenas metadado de slot |
| `partitions[].attributes` | ausente | não há equivalência fiável para todos os bits | Não comparável |
| Ausente | `physicalSectorBytes` | `physicalSectorSizeBytes` | Só uma observação adicional; **não derivar do tamanho lógico** |
| Ausente | `partitionTableSha256` | ausente | **NÃO COMPATÍVEL** sem leitura/hash com definição de âmbito e proveniência externa |
| Ausente | `partitions[].contentSha256` | ausente | **NÃO COMPATÍVEL**; CRC GPT NÃO É hash do conteúdo de partição |
| Ausente | `diskId` | `disks[].uniqueId` | Identidades de camadas diferentes, exigir associação autenticada da máquina/disco |
| Ausente | `transactionId` (32 hex) | `planId` da baseline | Só associável a um plano assinado e transação externa confirmada |
| Ausente | ausente | `sourceVolume`, NTFS serial, flags Windows | Requer coletores próprios; não é prova GPT por FD |

O `StorageBaseline` ainda contém `schemaVersion`, `capturedAtUtc`, inventários de **vários discos**, `inventoryError`, `partition.isActive`, `mbrType`, `accessPaths`, `isReadOnly` e outros campos não observados pelo parser GPT. A seleção do disco de destino requer identidade externa exata; nunca escolher o primeiro disco da lista.

## Fronteiras de proveniência

- **windows**: inventário `Get-Disk/Get-Partition` alegado pela baseline #288. O próprio JSON não autentica a sua origem, instante, integridade, disco escolhido ou que a recolha ocorreu numa VM real.
- **host**: FD somente leitura sobre **ficheiro regular**, validado pelo parser #286. FD fixado e CRC GPT protegem o instante de leitura, não a origem física/Windows do backing nem imutabilidade após o retorno.
- **guest**: inventário alegado como guest. Sem guest real nem coletor independente neste ensaio.
- **guest-immediate**: observação temporal adicional do **mesmo papel guest** usada pela #267; **não equivale** a uma observação Windows independente e nem é uma quarta fonte admitida pelo comparador #289.
- **#267**: HMAC de um payload sintético só prova posse de chave usada no teste. `ACCEPT_NO_WRITER` é **decisão laboratorial sem writer**, nunca autorização para instalação, execução ou mutação. `consume_observer_state_no_writer` depende do verificador Observer real, TrustStore, ReplayGuard e pins externos; não é usado para fabricar prova.

## Prova de composição e recusa

`auto_tests/tools/gpt_fd_crosscheck_offline_compat.py` recebe snapshots da **interface original #286** e o subconjunto de campos Windows de #288; usa `assert_snapshot_matches` original e projeta somente identidade GPT, PARTUUID, tipo e geometria. Não inventa `partitionTableSha256`, `contentSha256`, `physicalSectorBytes` ou `diskId`.

`refuse_operational_composition` exige papéis `windows/host/guest` da #289, preserva `guest-immediate` como papel distinto do #267, verifica a correspondência das projeções, exige hashes **fornecidos** (não calculados pelo adaptador) e chama o `compare_evidence` original #289. Para demonstrar o limite, um teste fornece digests sintéticos **explicitamente falsos**: o comparador aceita três JSON iguais, mas o contrato devolve `DENY_UNAUTHENTICATED_PROVENANCE`, com todas as permissões a `false`. Estes digests são **fixtures negativas**, não provas de conteúdo.

Troca de papel, transação, VM ou run, alterações de disco, PARTUUID, extensão, setor, inventário incompleto ou MBR são recusados. O mesmo `runId` é apenas consistência entre alegações: **não implementa anti-replay**. Mesmo após reinspeção, alterações fora da GPT, ABA e mutações imediatamente posteriores podem escapar. Falsificação de quatro claims idênticas não se torna autenticação.

## Testes e não-objetivos

Workflow CI: `.github/workflows/gpt-fd-crosscheck-compat-offline.yml`. Executa pytest dos módulos originais #286/#267, unittest original e hardening #289, nova suite de integração, Ruff, compileall e verificação de commits. Não faz checkout de guest nem invoca QEMU.

**Não existem**: chave ou assinatura operacional, autorização de escrever, writer, QEMU, VM, boot, operações ESP/BCD/WinRE/NVRAM, comparação de conteúdo de partições reais, recuperação Windows comprovada ou armazenamento de provas com atestação independente. `main` / `dev` permanecem inalteradas. Exige revisão humana e Safety antes de qualquer integração com instalação.
