# Consolidação da investigação multidistribuição — 20-11-2026

Esta integração preserva a investigação independente da antiga branch `docs/distro-backend-one-shot-research-20261119` como segundo progenitor Git desta branch de revisão, sem substituir os dossiers one-shot mais recentes da PR #258.

## Proveniência e política de revisão

- Branch original: `docs/distro-backend-one-shot-research-20261119` no commit `ce5f3672033a28595a439df93b055d635e0cc98e`.
- Destino de revisão: `docs/distro-one-shot-playbooks-20261119` (PR #258).
- Os ficheiros `docs/distro-backends/{README,SHARED_CONTRACTS,MINT,ZORIN,CACHYOS,POPOS,BAZZITE,Q4OS}.md` existiam em **ambas** as branches com conteúdos diferentes. Preservam-se as versões mais recentes do destino; as versões alternativas continuam acessíveis no segundo progenitor do commit de integração, por exemplo com `git show ce5f3672033a28595a439df93b055d635e0cc98e:docs/distro-backends/POPOS.md`.
- `AGENTS.md` também divergiu e **não** foi substituído por instruções mais antigas.
- Não se declara nenhuma distribuição estável por causa desta integração documental. As evidências de ISO, boot, Windows, updates e rollback têm de ser comprovadas em VM antes de qualquer promoção.
- Não foi executada escrita em discos nem alterações a bootloaders. `main` e `dev` não são alvos deste commit.

## Revisão pendente

Os dossiers independentes são material de referência, não configuração executável nem autorização para alterar partições. Antes de atualizar procedimentos, comparar cada hipótese com o estado atual das ISOs oficiais, os contratos assinados e os ensaios QEMU/OVMF. Manter as diferenças não resolvidas em revisão humana na PR #258.
