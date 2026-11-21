# Proveniência e limites da extração documental

- Data da extração: 2026-11-21.
- Origem: PR [#258](https://github.com/LMhdez/gaslux/pull/258), commit fixado `9b434a6a2b96b7a02fded73eb2ef66753bddde5d`.
- Base: `dev` no commit `6101bfebf88b43d3c1bad1e4ec19ea4a0f0761b8`.
- Extraídos os dossiers e contratos de investigação para seis distribuições, preservando o conteúdo da origem exceto a atualização dos cinco links do Q4OS para ficheiros ainda exclusivos da PR #258.
- Este commit não transporta workflows Q4OS, automação de instalador, scripts, schemas de execução, catálogos, artefactos binários nem autorização de escrita.
- A sobreposição de `SHARED_CONTRACTS.md` com a PR [#270](https://github.com/LMhdez/gaslux/pull/270) necessita reconciliação antes de integrar a #270. A PR [#259](https://github.com/LMhdez/gaslux/pull/259) mantém a sua própria base experimental; não foi rebaseada.
- As decisões de aprovação/integração exigem revisão humana conforme `AI_POLICY.md`. Nenhum dossier demonstra dual boot, atualização, remoção ou rollback em produção.
- O conteúdo é uma fotografia de investigação: links e versões externas deverão ser revalidados antes de uso operacional.

## Excluído deliberadamente

`docs/distro-backends/{boot-maps,ui-maps,evidence}/q4os*`, `schemas/distro-ui-*.json`, `auto_tests/tools/*q4os*`, workflows, fixtures e testes da PR #258. Dependem de proveniência/CI separadas e têm sobreposição com #270.
