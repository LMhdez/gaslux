# Integração do histórico da auditoria periódica — 20-11-2026

A branch antiga `automation/gaslux-15m-integration-audit` foi criada como experiência isolada de auditoria read-only. O seu workflow executava testes e reunia inventários de PRs/branches, mas a agenda `schedule` do GitHub Actions só é executada a partir do branch predefinido. Por isso, uma branch isolada não estabelece execução periódica comprovada.

Esta branch de manutenção preserva integralmente a origem `65ade7efb2232171c1d67f6e1ad006606a3ec5d8` como **segundo progenitor Git** do commit de consolidação. A árvore executável da branch de manutenção conserva os mecanismos e validadores atuais; o workflow antigo não é ativado, nem se funde código no instalador.

Recuperação: `git show 65ade7efb2232171c1d67f6e1ad006606a3ec5d8:.github/workflows/gaslux-integration-audit.yml`.

A eventual reutilização da auditoria periódica requer revisão humana, política de permissões de leitura e orçamento de CI. Esta incorporação de histórico não comprova testes de instalação, dual boot ou rollback. `main`, `dev` e as PRs abertas permanecem inalterados.
