# Zorin 18.1 — contrato Ubiquity de handoff somente de leitura

**Data:** 22-11-2026 UTC. **Política:** DENY_NO_WRITER; nenhuma execução Ubiquity, partman, mkfs, wipefs ou GRUB; nenhuma permissão de instalação.

## Origem verificada e limites de proveniência

Reutiliza o levantamento real da [PR #264](https://github.com/LMhdez/gaslux/pull/264), no documento [ZORIN_UBIQUITY_NATIVE_CODE_MAP.md](ZORIN_UBIQUITY_NATIVE_CODE_MAP.md). A referência técnica para a ISO Zorin 18.1 Core é o SHA-256 `44649b97bd307fc4c8529205d098ebbf98575a1e1ba2ee7d7005b697af1721d5` e o tamanho de 3 909 091 328 bytes, ambos do catálogo existente.

A análise de código fonte na ISO, reportada nas [Actions #44891962800](https://github.com/LMhdez/gaslux/actions/runs/44891962800), identifica Ubiquity `24.04.5+zorin2`, `usr/bin/ubiquity` SHA-256 `5819ac97c623085d08e55c08afc12e7d70be98795e603b27807bea165fad0b1b`, e o mapa JSON SHA-256 `47f42ce781af0eb39bc19f6c3bf4f2fb20569c5467a8f17d8e6d84b273a08f24`. O mapa era constituído por 58 ficheiros-fonte autenticados como regulares, tendo excluído 10 candidatos que não cumpriam esse requisito. O presente validador **refere** esse mapa imutável, mas **não volta a obter nem autenticar independentemente** o artefacto. Não utiliza como prova de execução real o simples reconhecimento de tokens no código.

## Cadeia nativa, por superfície

| Etapa | Evidência do mapeamento autenticado | Comportamento |
| --- | --- | --- |
| Launcher | `usr/bin/ubiquity`, SHA fixado | Referência de código estática; lançamento não executado |
| Escolha do disco e partições | `usr/lib/ubiquity/plugins/ubi-partman.py`, `initialize_use_disk_mode` linha 738, ficheiro SHA `295e4785bb9477f00c3df565a4698635631d36c5c74f40b87d302578c3a6e50f` | Candidatos de disco e operações partman; escolhas reais não autenticadas |
| Commit da tabela e filesystem | `usr/lib/ubiquity/ubiquity/components/partman_commit.py`, SHA `3de7e27675e1875848c4abc50b40742c5f3c68e92d7b23f54001839851527322` | Potenciais escritas GPT/partman/mkfs; nunca autorizadas |
| Sistema instalado | `usr/lib/ubiquity/plugins/ubi-usersetup.py`, SHA `56a888d8601578faeaf92af662778b1e656136fc1bbb4d6f2a766bb42d39aa72`; plugins de locale/teclado/fuso no mapa #264 | Configuração potencial de conta e destino; sem action graph autenticado |
| GRUB | `usr/lib/ubiquity/ubiquity/components/grubinstaller.py`, `prepare` linhas 30/34, `run` linha 43, SHA `4f2b1e80d5401abf9164f534044162483f6d37df730dff7842ec1d651fad5579` | Pode escrever ESP/MBR/configuração; não autenticado |
| EFI | `usr/share/ubiquity/plugininstall.py`, `configure_bootloader` linha 991, SHA `bf3d60094d1ab2609b6260a61b675581a5efb79f7044a0c0383f3733e52e3b20` | Referência a `/boot/efi`; não prova que preserves `EFI/Microsoft` ou NVRAM |
| Windows chainloader | `usr/share/grub-installer/otheros.sh`, `grub2_write_chain` linha 84 | Referência a Windows no GRUB, não prova boot |

A ISO mapeada **não fornece prova de API autenticada de dry-run, action graph, fencing de partman ou restrição de writes na ESP**. Não inventar uma interface do Ubiquity para estas capacidades.

## Handoff implementado

- `schemas/zorin-ubiquity-handoff-readonly.schema.json`: contrato tipado **específico** da proposta Zorin/Ubiquity, sem duplicação do plano genérico Gaslux. As versões/hashes do instalador e da ISO são cruzadas contra os metadados existentes; os valores da origem são apenas declarações até serem autenticados externamente.
- `auto_tests/tools/zorin_ubiquity_handoff_readonly.py`: valida primeiro o plano original com `schemas/installation-plan.schema.json`; usa `inspect_gpt_fd` e `assert_snapshot_matches` do módulo Safety #307, num FD somente de leitura para ficheiro regular. Compara GPT primária e secundária, tabela, geometria, offsets, GUIDs, alvo Linux e **todas** as partições não Linux protegidas. Não abre uma segunda vez o pathname do disco.
- Referências `planId` e `transactionId` são verificadas por igualdade com o plano fornecido, **não** por assinatura. O campo `expectedGptSnapshotSha256` é um hash de JSON para coerência local; não é assinatura nem prova da proveniência física do QCOW2. Não existe autenticidade da operação Ubiquity observada.
- Nesta versão, a única combinação admitida para **análise estrutural** é UEFI/GPT, Secure Boot desligado, e partições de destino correspondentes à GPT sintética. BIOS/MBR, Secure Boot e Windows 11 permanecem por testar separadamente; nenhuma combinação pode obter autorização operacional.
- Operações hipotéticas no root (`ROOT_CONFIGURE`, `ROOT_FORMAT`) podem ser propostas, mas a resposta é sempre `DENY_NO_WRITER`, sem writer. Commit partman nunca é aceite como plano de ação; GRUB/ESP/NVRAM/MBR são sempre recusados por ação não autorizada.
- Proteções Windows: ESP, MSR, Windows NTFS, Recovery e todas as regiões não pertencentes à raiz Linux. Nem o plano nem o snapshot apresentado provam BCD, WinRE, BitLocker, BootOrder, BootNext ou rollback. Os campos de proveniência/recuperação ficam obrigatoriamente falsos.

## Provas mínimas e dependências

A suite `test_zorin_ubiquity_handoff_readonly.py` constrói exclusivamente um ficheiro GPT sparse sintético, abre FD `O_RDONLY`, e executa A (ISO/versão), B (disco), C (GPT/offset/setor/GUID), D (ESP/partições Windows), E (transação), F (partman), G (GRUB/EFI/NVRAM) e H (proposta válida sem autorização), além de casos negativos de Secure Boot, esquema e descriptor RW.

**Integrador 2:** falta uma interface partilhada de *autenticação* entre plano assinado, snapshot GPT/FD, proveniência QCOW2/guest, transação e checkpoint independente; comparação de IDs e hashes não é suficiente. Não transplantar a ancestralidade experimental #264 para `dev`. **Safety:** auditar o futuro writer fence e os efeitos partman/GRUB, sobretudo partições protegidas, ESP e NVRAM. **Observer:** reutilizar HOST/FD e Local Peer já presentes em `dev`; sem observador independente não se pode elevar a prova de execução.

Próxima intervenção segura: obter uma representação read-only e verificável da configuração efetiva proposta por Ubiquity, caso exista, e demonstrar os seus limites face aos processos partman/GRUB numa VM *sem escritor*. Se Ubiquity não expuser o grafo de ações confiável, usar o backend Debian/Ubuntu existente como alternativa após auditoria, não permitir tentativa de instalação desprotegida.

**Classificação:** `nativeInstallerInvoked=false`; `productionStorageWritesAuthorized=false`; `windowsEspWriteAuthorized=false`; `sameDiskDualBootVerified=false`; `windowsInPlaceRollbackProven=false`; `stable=false`.


## Validação executada (22-11-2026 UTC)

[Actions #45031497831](https://github.com/LMhdez/gaslux/actions/runs/45031497831), HEAD `2724ab65dc3f2a9a1a456501fcb853ffb272c3ee`, **SUCCESS**. O job `readonly-contract` concluiu Ruff lint/format, compileall, validação JSON Schema Draft 2020-12, teste da GPT sintética por FD e cinco suites, num total de **95 testes**: 25 handoff, 21 mapa Ubiquity, 13 discovery, 25 Zorin Windows COW (contratos offline) e 11 Mint Windows COW (contratos offline). Incluiu manifesto textual com hashes SHA-256 dos ficheiros, sem exportar qualquer imagem.

A primeira execução do novo workflow falhou devido a um import de teste não utilizado e formatação; a execução seguinte revelou um grupo adicional na expressão regular GPT do novo schema. Todos esses defeitos foram corrigidos antes da execução acima. Nenhuma falha foi contornada através de redução dos testes ou alteração do leitor Safety.

Esta CI **não executou** o instalador Ubiquity, QEMU, Windows ou um rollback real; não revalida por si só o conteúdo da ISO e não autentica a proveniência do plano ou da operação partman. A classificação permanece `DENY_NO_WRITER`.
