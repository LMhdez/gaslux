# Arquivo Git de experiências Gaslux — 19-11-2026

**Este arquivo preserva o histórico, não integra código no instalador.**
A árvore de trabalho permanece ancorada na versão `main` inicial, com este
ficheiro informativo. Cada futura consolidação acrescenta um commit Git com
dois pais: o HEAD anterior deste arquivo e o SHA integral da branch original.
A árvore desse commit é idêntica à anterior, pelo que nenhum ficheiro das
experiências é incorporado no executável ou no catálogo estável.

Para recuperar uma experiência, procurar neste arquivo por `Source-ref:`:

```bash
git log --first-parent --format='%H%n%B' archive/gaslux-experiments-preserved-20261119
# Recuperar a branch pelo SHA Source-sha apresentado no commit de arquivo:
git branch recuperacao/<tema> <sha-original>
```

Antes de eliminar uma referência original, a manutenção comprova que o seu
commit final é ancestral do HEAD deste arquivo e usa
`git push --force-with-lease` com o SHA exato da branch original.
`main`, `dev`, bases/heads de PRs abertas, Actions ativas e branches
recentes ficam excluídas.

Esta estratégia reduz referências redundantes sem descartar histórico
experimental. Não é certificação de instalação, dual boot, rollback ou
estabilidade. A integração funcional das distribuições continua sujeita
a PRs próprias, testes reais e revisão humana.

Generated-by: GPT-6
