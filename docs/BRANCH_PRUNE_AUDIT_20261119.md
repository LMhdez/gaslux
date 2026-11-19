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
