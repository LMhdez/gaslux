# Gaslux — eliminação conservadora de branches, 2026-11-19

## Âmbito e limites

Operações exclusivamente sobre referências Git antigas na branch de controlo `automation/gaslux-branch-prune-20261119`; não há alterações aos discos, a `main`, a `dev`, ao catálogo estável ou ao instalador.

Critérios cumulativos: branch fora das referências protegidas por PRs abertas, Actions ativas, `main`, `dev` ou controlo; commit final inativo há pelo menos seis horas; HEAD já ancestral da HEAD de `main`, `dev` ou de uma PR aberta; revisão das referências antes de iniciar; eliminação com `git push --force-with-lease` com SHA exato. Lote máximo de 30. Branches com commits exclusivos **não** são eliminadas.

## Provas

- [Auditoria sem escritas — Actions #44586391127](https://github.com/LMhdez/gaslux/actions/runs/44586391127): 261 branches, 93 candidatas inicialmente.
- [Primeira execução — Actions #44586638250](https://github.com/LMhdez/gaslux/actions/runs/44586638250): sucesso, 30 eliminações com lease; 261 → 231 branches confirmado pela API. A diferença entre 93 na auditoria e 92 no início do primeiro lote resulta de referências ativas entretanto reavaliadas.
- Outros lotes só devem ser contabilizados após confirmação da API e evidência Actions.

O histórico dos commits permanece em `main`, `dev` ou nas branches ainda abertas, conforme prova de ancestralidade Git. Esta operação não valida a estabilidade dos backends.

- [Segunda execução — Actions #44586998974](https://github.com/LMhdez/gaslux/actions/runs/44586998974): `SUCCESS`, 30 eliminações adicionais, 231 branches inicial → 201 previstas; 62 candidatas no início. Zero recusas reportadas.

- [Terceira execução — Actions #44587286014](https://github.com/LMhdez/gaslux/actions/runs/44587286014): `SUCCESS`, 30 eliminações adicionais; GitHub API confirmou 171 branches restantes. Tinham sido identificadas 32 referências elegíveis no início do lote.

- [Quarta execução — Actions #44587629589](https://github.com/LMhdez/gaslux/actions/runs/44587629589): `SUCCESS`; duas referências obsoletas adicionais eliminadas com lease. **Total da operação: 92 branches eliminadas, 261 → 169 (incluindo a nova branch de controlo).**

## Encerramento da operação

A configuração do workflow foi revertida para **auditoria exclusivamente de leitura**: `contents: read`, checkout sem credenciais persistentes, comando `audit`. Não há mais exclusões automáticas por futuras atualizações desta branch. Provas de execução e inventário de SHAs estão nos artefactos GitHub Actions e no histórico desta branch. A existência de referências ainda não consolidadas **não** autoriza a sua eliminação nem a promoção de backends experimentais.

## Arquivo histórico seguro — 19-11-2026

- [Actions #44598172401](https://github.com/LMhdez/gaslux/actions/runs/44598172401): auditoria de leitura aprovada, 101 branches com histórico exclusivo e inativas há pelo menos 12h, sem PR aberta nem workflow ativo.
- [Actions #44598523926](https://github.com/LMhdez/gaslux/actions/runs/44598523926): testes Python do filtro de proteção, antiguidade, marcador de arquivo e autorização aprovados.
- [Actions #44598682337](https://github.com/LMhdez/gaslux/actions/runs/44598682337): primeiro lote `SUCCESS`, 15 históricos preservados por commits Git de dois pais, com árvore original de arquivo imutável; 15 referências eliminadas por SHA lease; 171 → 156 branches. Os commits originais permanecem alcançáveis pelo arquivo `archive/gaslux-experiments-preserved-20261119`.

**Atenção:** preservar histórico não significa integrar o código experimental em `main`, `dev` nem no instalador. Todos os trabalhos ainda carecem de validação funcional para promoção.

- [Segundo lote de arquivo — Actions #44599193247](https://github.com/LMhdez/gaslux/actions/runs/44599193247): `SUCCESS`, mais 15 arquivos de dois pais, 15 branches eliminadas com lease; inventário confirmado: 141. **Total de arquivo:** 30 branches. O terceiro lote está a executar no workflow de 25 fontes; a próxima execução será serializada.

- [Terceiro lote de arquivo — Actions #44599432212](https://github.com/LMhdez/gaslux/actions/runs/44599432212): `SUCCESS`, 25 histórias adicionais preservadas no arquivo com árvore imutável e as 25 branches de origem eliminadas com `--force-with-lease`, zero falhas; inventário confirmado: 116. **Total arquivado nesta ronda: 55 branches.**

- [Quarto lote de arquivo — Actions #44599793061](https://github.com/LMhdez/gaslux/actions/runs/44599793061): `SUCCESS`, 25 branches adicionais arquivadas (dois pais, mesma árvore) e 25 referências eliminadas com SHA lease, zero recusas. Inventário confirmado: 91; total acumulado neste arquivo: 80.
- [Tentativa seguinte — Actions #44600351938](https://github.com/LMhdez/gaslux/actions/runs/44600351938): recusou qualquer operação por verificação antiga `len(refs) < 100`; **nenhuma branch eliminada** nesta execução. Corrigida por comparação integral nome+SHA entre `git fetch` e a API paginada de branches.
- [Auditoria e seis testes após correção — Actions #44601401759](https://github.com/LMhdez/gaslux/actions/runs/44601401759): `SUCCESS`, inventário abaixo de 100 validado por igualdade exata das duas fontes, sem mutações.

- [Quinto lote de arquivo — Actions #44601637500](https://github.com/LMhdez/gaslux/actions/runs/44601637500): `SUCCESS`, 21 fontes finais preservadas com segundo pai Git e eliminadas só após verificação remota de ancestralidade. **Total desta consolidação: 101 referências eliminadas e o histórico integral preservado num único arquivo.** De 170 branches iniciais para 70 finais, incluindo uma nova branch de arquivo (redução líquida de 100).
 
## Verificação final e bloqueios
 
O workflow foi revertido para `permissions: contents: read`, `persist-credentials: false`, sem token de autorização de archive/prune. A auditoria final de leitura verifica os 101 commits de dois pais, o SHA do segundo pai, a primeira cadeia de pais, a inexistência das referências originais e a identidade exata da árvore de trabalho do arquivo. Nenhum backend foi promovido ao produto estável; mantém-se a revisão humana e os ensaios de dual boot/rollback exigidos pela issue #3 e pela documentação técnica.

- [Limpeza residual — Actions #44602941537](https://github.com/LMhdez/gaslux/actions/runs/44602941537): `SUCCESS`, a última branch redundante `feature/cachyos-writable-child-cow-firstboot-issue3` tinha HEAD `f563013612a4dff21c0f1c2889474bd6fb11b9ad` já ancestral do HEAD da PR #248; foi eliminada com lease exato. A mesma execução manteve `ARCHIVE_DAG_VERIFIED=101`.
- **Estado após esta intervenção:** 170 branches iniciais, +1 arquivo novo e 102 referências eliminadas = **69 branches restantes**. Nas duas intervenções de limpeza do dia foram eliminadas 194 referências, com redução de 260 para 69 branches Git.
- **Bloqueio operacional resolvido:** [Actions #44600351938](https://github.com/LMhdez/gaslux/actions/runs/44600351938) falhou antes de apagar qualquer referência porque o validador tinha um limite fixo antigo de 100; substituído por comparação exata e paginada de todos os nomes e SHAs com a API, validada em [#44601401759](https://github.com/LMhdez/gaslux/actions/runs/44601401759).
- **Evidência independente:** [Actions #44602575012](https://github.com/LMhdez/gaslux/actions/runs/44602575012) comprovou 101 commits de dois pais, 101 SHAs originais ainda ancestrais do arquivo, 101 referências originais ausentes, árvore do arquivo idêntica e nove testes unitários aprovados.

## Estado permanente seguro

O workflow de manutenção regressa definitivamente ao modo de **auditoria apenas de leitura**, sem credenciais Git persistentes nem permissão de escrita: não elimina branches em futuras atualizações. A branch `archive/gaslux-experiments-preserved-20261119` serve apenas de cofre de histórico, com proveniência `Source-ref` e `Source-sha` por commit; nenhum código experimental é fundido no instalador. A promoção de funcionalidades exige CI, instalação nativa, dual boot e recuperação comprovados e revisão humana.

## Reauditoria de 20:25 UTC

Pedido: reduzir branches Git, não encerrar PRs. Inventário REST inicial reconfirmado: 69 branches, 22 PRs abertas e três issues. A verificação CI permaneceu em modo de leitura. A auditoria reavalia candidatas conforme estado atual antes de qualquer eliminação. A preservação da árvore experimental e as proteções das PRs continuam obrigatórias.

## Revalidação e arquivo de 20:28 UTC

[Auditoria de leitura #44608983665](https://github.com/LMhdez/gaslux/actions/runs/44608983665) encontrou 1 referência ancestral (`feature/q4os-calamares-users-view-lab` no SHA de `main`) e 1 com histórico antigo exclusivo (`test/cachyos-166-prewrite-contracts-rebase-20261119`). Este último foi preservado no [commit de arquivo de dois pais `2b682636`](https://github.com/LMhdez/gaslux/commit/2b682636b7aacc347a507d525d2bf78ca50c1818), árvore imutável, sem importar código para o instalador. O contrato de verificação passa a exigir 102 históricos exatos. A remoção é limitada aos SHAs já ancestrais e usa `--force-with-lease`, ficando a proteção de PRs e Actions ativa.

- [Execução de limpeza #44609582671](https://github.com/LMhdez/gaslux/actions/runs/44609582671): `SUCCESS`, duas branches obsoletas eliminadas com lease após prova de ancestralidade: `test/cachyos-166-prewrite-contracts-rebase-20261119` (histórico preservado no arquivo `2b682636`) e `feature/q4os-calamares-users-view-lab` (SHA igual a `main`). `ARCHIVE_DAG_VERIFIED=102`, árvore inalterada, sem merge de código de produção; contagem de branches: **69 → 67**.

Workflow novamente limitado a `contents: read` e checkout sem credenciais. As demais referências são preservadas por proteção ou evidências insuficientes. O próximo avanço deverá integrar e testar código de branches distintas, não apagar trabalho experimental indiscriminadamente.

- [Auditoria #44609842480](https://github.com/LMhdez/gaslux/actions/runs/44609842480) identificou duas candidatas antigas Q4OS, já sem proteção da PR #226 encerrada concorrentemente: `fix/q4os-win10-qmp-socket-identity-gate-20261119` e `test/q4os-win10-proven-noprompt-reuse-20261119`. Ambos os históricos foram preservados com commits Git de dois pais e árvore idêntica no arquivo: [`d0e44b7c`](https://github.com/LMhdez/gaslux/commit/d0e44b7c939a9a3e066753a56da1057d465a8d9a), [`ae2fb894`](https://github.com/LMhdez/gaslux/commit/ae2fb894eba4418d3c2b75e8ef25e28ef5589760). O verificador agora exige **104** históricos preservados; a limpeza mantém `--force-with-lease` e proteção de PRs atuais.

- [Q4OS #226, limpeza #44610285016](https://github.com/LMhdez/gaslux/actions/runs/44610285016): `SUCCESS`, duas branches Q4OS obsoletas com PR encerrada removidas com SHA lease; histórico preservado no arquivo por commits `d0e44b7c` e `ae2fb894`. `ARCHIVE_DAG_VERIFIED=104`, árvore imutável, sem merge de produção. Contagem confirmada **67 → 65**.

Após esta execução, o workflow volta a auditoria de leitura, com `contents: read`, checkout sem credenciais persistentes e sem variável de autorização para eliminar refs. Quaisquer branches futuras são preservadas salvo nova auditoria e autorização humana.

## Consolidação adicional — 20-11-2026, 00:39–00:46 UTC

Inventário independente da API GitHub: **66 branches**, 22 PRs abertas. Nenhuma PR foi fechada ou integrada em `main`/`dev` nesta operação.

1. [Actions #44647647123](https://github.com/LMhdez/gaslux/actions/runs/44647647123): três referências sem commits exclusivos, comprovadamente ancestrais de heads de PRs abertas, eliminadas por SHA lease: `fix/mint-shutdown-witness-line-attestation-20261119` (guardada na PR #233); `fix/q4os-evidence-manifest-newline-20261119` e `fix/q4os-manifest-nofollow-20261119` (guardadas na PR #256). Contagem **66 → 63**. Cinco testes de seleção exata e verificação dos 104 históricos anteriores aprovados.
2. [Actions #44648150583](https://github.com/LMhdez/gaslux/actions/runs/44648150583): primeira tentativa de arquivo falhou em `git commit-tree` por falta de identidade Git do runner. **Não eliminou qualquer branch**; testes e verificação prévia aprovados. Corrigida identidade de autor/committer da Action.
3. [Actions #44648264608](https://github.com/LMhdez/gaslux/actions/runs/44648264608): seis branches antigas com histórico exclusivo preservadas em commits Git de dois pais, árvore de trabalho de arquivo imutável e respetivos refs eliminados com lease exato: `debug/q4os-win10-qemu-visual-evidence`, `fix/bazzite-official-iso-ovmf-gates-20261119`, `fix/cachyos-shared-cow-iso-ext4-ownership-issue3`, `fix/q4os-ovmf-dvd-format-contracts-20261119`, `fix/q4os-ovmf-hid-key-hold-20261119` e `test/popos-win10-native-child-distinst-20261119`. O HEAD final do arquivo é `e7ed13016989f3b57664aaa734ff5e52731a4092`; contagem **63 → 57**. Testes das autorizações exatas (5 + 4) e dos contratos existentes (6 + 3) aprovados. As alterações destas seis branches **não foram integradas no código de produção**.
4. Estado final desta intervenção: **66 → 57 branches (9 refs eliminados)**. Arquivo com **110 históricos** ao preservar mais seis fontes; foi reforçado o verificador de integridade para exigir exatos 110. Os workflows de manutenção são devolvidos ao modo de auditoria de leitura sem credenciais de escrita persistentes. A promoção de código experimental continua condicionada por CI, testes reais, recuperação e revisão humana.

Esta limpeza **não comprova** suporte estável a qualquer nova distribuição nem dual boot Windows/Linux. As branches com trabalhos exclusivos recentes e as bases/heads das 22 PRs permanecem intactas.

## Consolidação adicional de branches ancestrais — 20-11-2026

- [Actions #44649163564](https://github.com/LMhdez/gaslux/actions/runs/44649163564): verificação prévia recusou as quatro referências sem apagar nenhuma: a direção de ancestralidade da branch Q4OS de Summary estava invertida. Foi corrigida a escolha de origem e destino após comparação independente.
- [Actions #44649337425](https://github.com/LMhdez/gaslux/actions/runs/44649337425): `SUCCESS`, quatro branches efetivamente removidas com `--force-with-lease` e dupla verificação por SHA de origem/destino: `feature/bazzite-official-gpt-discovery-20261119` já contida em `feature/bazzite-gpt-layout-fixture-20261119`; `feature/q4os-users-transition-lab-20261119` e `test/q4os-ed25519-domain-separation-20261119` já contidas em `feature/q4os-summary-view-lab-20261119`; e `fix/q4os-cow-evidence-nofollow-20261119` já contida em `fix/q4os-require-nofollow-flag-20261119`. O último par de branches Q4OS continha exatamente o mesmo SHA. Sem fusão de código de produção, apenas eliminação de refs redundantes. **57 → 53 branches**.
- **Resultado acumulado desta intervenção:** **66 → 53 branches**, 13 referências eliminadas, 110 históricos experimentais guardados no arquivo e as fontes ancestrais adicionais mantidas nas branches sucessoras. Nenhuma PR fechada, nenhum merge para `main` ou `dev`. Workflow restabelecido em `contents: read`, checkout com `persist-credentials: false`, apenas auditoria e testes. A estabilidade do dual boot permanece por comprovar.



## Integração e remoção de branches — 20-11-2026 01:16–01:43 UTC

Estado de partida verificado: **53 branches e 22 PRs abertas**. O trabalho manteve `main` e `dev` intactas, preservou o catálogo estável, e só alterou heads das PRs em draft #256, #248 e #250 e a branch separada de manutenção. O número de PRs abertas desceu por intervenções concorrentes; **nenhuma PR foi fechada nesta ronda de limpeza**.

### Histórico integrado em branches de revisão

- [Commit Q4OS #256 `eaf0ba7d`](https://github.com/LMhdez/gaslux/commit/eaf0ba7d7f37240b0d15c294043a59e73fbe6e83): histórico da antiga `ci/q4os-evidence-manifest-coverage-20261119` guardado como segundo pai; a árvore de trabalho existente mantém as versões corrigidas e não incorpora a versão antiga com barras invertidas duplicadas. [Actions #44652954599](https://github.com/LMhdez/gaslux/actions/runs/44652954599) confirmou a remoção da branch antiga, com lease.
- [Commit CachyOS #248 `a3078779`](https://github.com/LMhdez/gaslux/commit/a3078779f809cc30b67899419d28fbbc05fe2398): histórico `fix/cachyos-grant-config-program-binding-issue3` guardado sem alterar a árvore atual nem renomear de volta `installedConfiguratorSha256`.
- [Commit Bazzite #250 `628a307a`](https://github.com/LMhdez/gaslux/commit/628a307aabd6fa9c805381846a42809e202a3e5d): históricos `feature/bazzite-advanced-custom-selection-evidence-20261119` e `fix/bazzite-blivet-observer-ruff-20261119` absorvidos, mantendo a distinção entre radio selecionado e editor Blivet-GUI efetivamente aberto. [Actions #44653300043](https://github.com/LMhdez/gaslux/actions/runs/44653300043): três referências antigas eliminadas por SHA/ancestralidade.
- [Commit Bazzite #250 `0db14e05`](https://github.com/LMhdez/gaslux/commit/0db14e05309f771adc215021ca934693a430dbc8) e [correção Ruff `0b3be2e0`](https://github.com/LMhdez/gaslux/commit/0b3be2e0061a4a2e211490098a5f861a41f7d93c): código efetivamente integrado da branch GPT: bloquear probe de instalador real abaixo dos 8 GiB RAM, verificar antes de descarregar ISO, criar pasta de evidências cedo, proibir ausência de artefacto e adicionar dois testes. [Actions #44653975154](https://github.com/LMhdez/gaslux/actions/runs/44653975154) (contratos) e [#44653975155](https://github.com/LMhdez/gaslux/actions/runs/44653975155) (GPT sintética): SUCCESS. Job de ISO real não executado nesse PR.
- [Commit Q4OS #256 `e4ee4855`](https://github.com/LMhdez/gaslux/commit/e4ee48557affcdcaf5926ea4154eab50f7d60ea2): teste Users/Calamares da branch `fix/q4os-require-nofollow-flag-20261119` incorporado; cinco regiões RGB independentes, falhas em screenshot vazia, resolução errada e symlink. Os contratos de GUI [#44654300368](https://github.com/LMhdez/gaslux/actions/runs/44654300368) e de recusa [#44654300535](https://github.com/LMhdez/gaslux/actions/runs/44654300535) passaram; execução gráfica maior [#44654300393](https://github.com/LMhdez/gaslux/actions/runs/44654300393) permanecia ativa na auditoria de 01:42 UTC e não se apresenta como instalação concluída. [Actions #44654433865](https://github.com/LMhdez/gaslux/actions/runs/44654433865) eliminou duas referências ancestrais: GPT Bazzite e Q4OS nofollow.

### Arquivo de PRs antigas não integradas

- PRs #214 (Bazzite), #228 (Pop!_OS) e #158 (Windows FAT32 USB) estavam fechadas **sem merge** quando verificadas. A tentativa [#44654969220](https://github.com/LMhdez/gaslux/actions/runs/44654969220) recusou a seleção inicial **antes de eliminar referências**: o tip Pop!_OS já era ancestral do arquivo anterior, evitando duplicação.
- [Actions #44655156732](https://github.com/LMhdez/gaslux/actions/runs/44655156732) preservou os históricos exclusivos de `feature/bazzite-legacy-iso-scout-20261118` e `test/windows10-partitioned-fat32-usb-explicit-removable` como dois commits de dois pais, árvore do arquivo inalterada, SHA exacto e lease, depois removeu os dois refs: **110 → 112 histórias arquivadas**. Não fundiu estas experiências no código de produção.
- [Actions #44655408149](https://github.com/LMhdez/gaslux/actions/runs/44655408149) validou a DAG dos **112** históricos e eliminou mais três referências já alcançáveis por keeper verificado: `feature/bazzite-owned-qcow2-storage-discovery` via PR #250, `test/popos-genuine-win10-cow-live-iso-20261119` e `test/windows10-fat32-usb-partitioned-mbr-setup` via arquivo. Sem perda de commits.

**Resultado total da ronda: 53 → 42 branches**, **11 refs eliminados**, 112 históricos experimentais no cofre. Na verificação final há 19 PRs abertas e quatro refs não diretamente protegidos: `automation/gaslux-15m-integration-audit`, `docs/distro-backend-one-shot-research-20261119`, `feature/q4os-summary-view-lab-20261119`, `test/mint-squashfs-identity-contracts-20261119`. Todos permanecem para análise de histórico/código; a proteção de branches referenciadas nas PRs é obrigatória. A issue #3 permanece aberta: não declarar dual boot estável sem Windows/Linux, updates e rollback comprovados.

A partir deste commit o workflow de manutenção regressa a **apenas leitura** (`contents: read`, checkout `persist-credentials: false`, sem autorizações de eliminação). A presença de scripts de limpeza no repositório não permite operações por futuras atualizações deste workflow.
