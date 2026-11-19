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
