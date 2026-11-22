# GASLUX-ZORIN — Ubiquity 18.1 PRECOMMIT-01 (22-11-2026 UTC)

**Decisão arquitetural: ROUTE B — UBIQUITY_PRECOMMIT_PLAN_UNAVAILABLE** para a versão
`24.04.5+zorin2` na ISO Zorin 18.1 Core fixada. Significa **ausência de prova** de
uma fronteira read-only completa e verificável antes da primeira escrita; NÃO
afirma impossibilidade absoluta de existir uma interface não observada.

## Evidência reaberta e autenticada

- [PR #264](https://github.com/LMhdez/gaslux/pull/264),
  [Actions #44891962800](https://github.com/LMhdez/gaslux/actions/runs/44891962800),
  [artefacto #14702053502](https://github.com/LMhdez/gaslux/actions/runs/44891962800/artifacts/14702053502).
- ZIP SHA-256: `641bf31056addd3e54126d3e636ea524d12d0a4ac16e4188510aef8ae1f08da9`.
- JSON `zorin-native-ubiquity-code-map.json` SHA-256:
  `47f42ce781af0eb39bc19f6c3bf4f2fb20569c5467a8f17d8e6d84b273a08f24`.
- ISO Zorin 18.1 Core: SHA-256
  `44649b97bd307fc4c8529205d098ebbf98575a1e1ba2ee7d7005b697af1721d5`,
  3 909 091 328 bytes, já fixada em `release-config.json`.
- `usr/bin/ubiquity` `24.04.5+zorin2`: SHA-256
  `5819ac97c623085d08e55c08afc12e7d70be98795e603b27807bea165fad0b1b`.
- O mapa contém **58 ficheiros regulares autenticados**, com referências
  estáticas e linha/símbolo/fingerprint; **10 candidatos de `lib/partman/lib/`
  não atestados como ficheiros regulares**, incluindo `commit.sh` e `resize.sh`.
  O conteúdo **integral e a ordem de chamadas destes módulos não fazem parte do
  artefacto**. Não há prova de execução nem de observação de escritas reais.
- Nenhum novo hash foi criado como pretensa identidade da ISO ou do instalador.

Os símbolos/linhas abaixo provêm das referências do mapa original, que
classifica cada ocorrência como `STATIC_CODE_REFERENCE_ONLY`. **Não
representam um trace de operações nem permitem inferir que as linhas foram
executadas nessa sequência.** A primeira mutação efetiva continua
**não identificável com os dados disponíveis**.

## Fronteiras A–G e lacunas de observação

| Fronteira | Código e SHA-256 do ficheiro real | Pré-condições / chamadas visíveis na evidência | Efeito persistente possível e observação | Cancelamento e vínculo ao plano |
| --- | --- | --- | --- | --- |
| A — descoberta/leitura | `usr/bin/ubiquity` — `5819ac97c623085d08e55c08afc12e7d70be98795e603b27807bea165fad0b1b` | Lançador autenticado; não há prova no mapa sobre a primeira operação de disco | Não é possível certificar que o lançamento e a enumeração sejam isentos de escritas | Cancelamento sem escrita **não demonstrado**. Exigir identidade de processo/guest e FD |
| B — seleção de partições | `usr/lib/ubiquity/plugins/ubi-partman.py` — `295e4785bb9477f00c3df565a4698635631d36c5c74f40b87d302578c3a6e50f`; `initialize_use_disk_mode` linha 738 | Token `partman`; referências a `partman_dialog` (linhas 1187/1193/1205), opções e mountpoint | Seleção é visível estaticamente; não há snapshot autenticado da seleção efetiva | Cancelamento read-only **não demonstrado**. Exigir GUID físico, PARTUUID, offset/size e instante da seleção |
| C — preparar alterações | `ubi-partman.py` (SHA acima); `usr/lib/ubiquity/ubiquity/parted_server.py` — `5e20b10341852549ffcc5620fd0eeb35600fba0a7e84d1b306027ad8b82b7952` | Código inclui nome `parted_server` e métodos de UI; o mapa não preserva os argumentos reais das chamadas | Pode haver alterações em memória ou imediatas; **não foi provado que sejam adiadas até `partman_commit`** | Não aceitar proposta de operações sintetizada de tokens. Necessários command/FD trace e fencing antes de chamar |
| D — primeira mutação potencial | `ubi-partman.py`, `parted_server.py`, e `lib/partman/lib/resize.sh` (este último **sem hash de ficheiro regular autenticado**) | Primeira invocação capaz de alterar GPT, NTFS ou metadados não foi localizada em grafo de execução autenticado | **Primeira mutação exata desconhecida**; pode anteceder `partman_commit.run` | Nenhum cancelamento sem escrita foi provado. Bloquear antes da execução de Ubiquity |
| E — commit | `usr/lib/ubiquity/ubiquity/components/partman_commit.py` — `3de7e27675e1875848c4abc50b40742c5f3c68e92d7b23f54001839851527322`; `run` linhas 51/60/62/91/93 | Token `preseed`; `lib/partman/lib/commit.sh` permanece não autenticado | Commit de tabela / operações pode persistir. **O nome da função não prova ser a primeira escrita** | Sem action graph independente não é possível conferir todas as operações contra plano/rollback |
| F — formatação | `ubi-partman.py` `set_default_filesystem` linha 79; `partman_commit.py` SHA acima; `lib/partman/lib/commit.sh` não autenticado | Tipo de FS e mountpoint referenciados; comando efetivo `mkfs` e ordenação não autenticados | Formatação de destino ou partição alheia possível se houver erro de seleção | Sem prova da fronteira entre planeamento e `mkfs`, permanecer DENY |
| G — GRUB, EFI, NVRAM | `usr/lib/ubiquity/ubiquity/components/grubinstaller.py` — `4f2b1e80d5401abf9164f534044162483f6d37df730dff7842ec1d651fad5579`, `prepare` linhas 30/34, `run` 43; `usr/share/ubiquity/plugininstall.py` — `bf3d60094d1ab2609b6260a61b675581a5efb79f7044a0c0383f3733e52e3b20`, `configure_bootloader` linha 991 | `bootdev`, `grub-installer`, `/boot/efi` | Escrita de ficheiros EFI/GRUB ou NVRAM possível; o mapa reporta `nvram` como UNOBSERVED | Não foi demonstrado isolamento de `EFI/Microsoft`, BootNext/BootOrder, ou autorização de escrita |

**Conclusão falsificável:** o mapa autentica localização de *candidatos*, mas
não comprova uma chamada estável e completa para enumerar todas as mudanças
com GUIDs/intervalos/efeitos de filesystem/ESP/NVRAM **antes** de qualquer
mutação. `partman_commit.run` não pode ser assumido como início da escrita.
Não construir um dry-run sintético ou derivar operações de tokens.

## Implementação mínima sem duplicação de contratos

`auto_tests/tools/zorin_ubiquity_precommit_boundary.py` **não é um runner
Ubiquity**. Consome a proposta Zorin já validada pelo contrato #333, o plano
Gaslux existente, o FD GPT da Safety #307 e, facultativamente, o **JSON
autêntico** do artefacto #264. Confere o hash integral do JSON e executa o
validador de consistência e schema **já existentes** para o mapa; mesmo no
caso autenticado, a classificação é `ROUTE_B` + 
`UBIQUITY_PRECOMMIT_PLAN_UNAVAILABLE`, `DENY_NO_WRITER`.

Um candidato read-only fornecido de fora é tratado como dado **não
confiável**, sem assinatura. O módulo rejeita plano incompleto, ações
partman/bootloader alegadamente observadas, primeira escrita anterior ao
gate, mudança de disco entre seleção e commit, alteração de GPT,
transação/instalador divergentes e afirmações de dry-run/action graph. Nunca
comunica operações a um escritor nem ativa a execução do instalador.

## Comparação: backend Debian/Ubuntu existente em `dev`

| Capacidade | Código efetivo de Gaslux | Situação |
| --- | --- | --- |
| Preparação e validação ISO | `assets/live/libertix-install-main.sh` `preflight_legacy_installer_iso_or_die` (~linha 276), `libertix-distribution-common.sh` | Há preflight e identidade ISO antes do destino; desempenho operacional de dual boot não provado |
| Construção do destino | `libertix-install-main.sh`: `wipefs`/ `mkfs.ext4` (~linhas 383–386), `unsquashfs` (~412) | **Extrai SquashFS live**; não equivale automaticamente a instalação nativa completa via Ubiquity |
| Conta e locale | `configure-target-main.sh`: `configure_user`, `configure_locale`, `configure_keyboard`, `configure_timezone`, `configure_common_ubuntu_target` | Contratos implementados; sujeitos a boot e verificação |
| Initramfs e bootloader | `configure-target-main.sh`: `refresh_installed_initramfs`, `configure_grub`, `configure_boot_update_guards`; `libertix-install-main.sh` (~430/434) | Integração BIOS GRUB e EFI assinada, com verificações em código. Não certificar atualizações e ambos os boots com base no código |
| Ficheiros próprios/ownership | `assets/live/libertix-uefi-adapter.sh`: `EFI/Libertix/.libertix-owner`, verificação de partição/GUID/bootnum | Ownership descrita, ainda não provada em recuperação real |
| Recuperação | `assets/live/libertix-rollback-common.sh`: `rollback_windows_layout_best_effort`, MBR/EFI e NTFS; validações de geometria | Recuperação *best effort* implementada; prova independente de rollback in-place Windows não apresentada |
| Ensaios reais | PRs #219/#224 e #264 | Boot isolado Zorin OVMF com initramfs e COW Windows+root com kernel direto; insuficientes para dual boot via bootloader e updates/rollback |

**ROUTE B** é continuar a explorar e provar o backend Debian/Ubuntu
existente **sem declarar que já instala o sistema nativo completo**. Não
substituir este backend por uma cópia de rootfs não auditada; não clonar
Mint; a conformidade da imagem instalada, bootloader, atualização e
recuperação continua a exigir QEMU Windows/Zorin com gates independentes.

## Bloqueio mínimo para Integrador 2 e Safety

Para reconsiderar ROUTE A, recuperar as **instruções integrais da ISO
fixada** (apenas `unsquashfs -cat` dos poucos scripts em causa, com os
hashes já documentados), incluindo `parted_server.py`,
`partman_commit.py`, `lib/partman/lib/commit.sh` e `resize.sh`.
O artefacto atual **não contém** esses ficheiros. Exigir:
1. grafo causal das chamadas (incluindo efeitos antes do commit);
2. serialização completa de operações com disco físico, offsets,
   filesystem, ESP e NVRAM;
3. prova de ausência de escrita até validação do plano/FD/transação;
4. fence independente no HOST, recuperação autenticada e cancelamento
   comprovado antes de qualquer escrita.

Sem essas provas, não existe pre-commit operacional aceitável.
A revisão Safety da PR deve confirmar que a classificação é
apenas negativa. Não reutilizar a árvore histórica #264 em `dev`
nem alterar #328.

**Estado:** `nativeInstallerInvoked=false`,
`productionStorageWritesAuthorized=false`,
`windowsEspWriteAuthorized=false`,
`sameDiskDualBootVerified=false`,
`windowsInPlaceRollbackProven=false`, `stable=false`.
