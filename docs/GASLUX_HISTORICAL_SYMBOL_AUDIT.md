# GASLUX — Inventário de símbolos e recuperação de código (24-11-2026 UTC)

Fonte: [inventário JSON](GASLUX_HISTORICAL_SYMBOL_INVENTORY.json), [mapa por backend](GASLUX_BACKEND_REUSE_MAP.md), dev fixado em `d89f1547c50787e4640164e34bfd1863134e2908`.

## Cobertura
- 42/42 ficheiros Python/Shell nas seis PRs históricas selecionadas (#260, #224, #263, #298, #318, #320).
- 178/178 ficheiros atuais nas áreas selecionadas (`assets/live`, `auto_tests/tools`, `auto_tests/installer_observer` e caminhos de testes); a árvore contém 247 Python/Shell no total, logo 69 fora desta seleção.
- 788 declarações históricas; 3 006 atuais. 120 declarações históricas partilham nome e tipo com 324 declarações atuais (46 pares distintos nome/tipo); 668 sem coincidência nominal. Zero ficheiros históricos com blob idêntico em qualquer caminho da árvore dev completa.
- Método lexical por declaração `def/class` ou função Shell, não parser AST. Inclui auxiliares, métodos e testes; pode omitir ou classificar incorretamente declarações complexas. Contagens não significam funcionalidades em falta nem testes executados. Os nomes coincidentes não provam equivalência; não há equivalência semântica aprovada.

| Backend | Ficheiros | Declarações | Declarações test_* | Coincidência nominal |
|---|---:|---:|---:|---:|
| mint | 5 | 141 | 60 | 18 |
| zorin | 4 | 44 | 10 | 8 |
| cachyos | 11 | 190 | 84 | 20 |
| popos | 5 | 77 | 23 | 17 |
| q4os | 5 | 174 | 48 | 34 |
| bazzite | 12 | 162 | 87 | 23 |

## Caso concreto de duplicação histórica: Windows
As variantes de `auto_tests/tools/windows_x64_tcg_firstboot.py` em [#260](https://github.com/LMhdez/gaslux/blob/7ab2a431767d212566ab57b834f299f8308dbda6/auto_tests/tools/windows_x64_tcg_firstboot.py) e [#263](https://github.com/LMhdez/gaslux/blob/8b82ecdf5c5ef3e7d9d712c5d60b679bb1615f9f/auto_tests/tools/windows_x64_tcg_firstboot.py) têm blobs diferentes, mas 15 blocos textuais de funções top-level coincidentes. `main` difere; a variante Mint contém adicionalmente `workspace_has_active_mount` e `cleanup_private_workspace`. As 15 funções incluem download/validação ISO, geração unattended, argumentos QEMU, arranque e TPM. Comparação lexical exclui decorators, globals, imports, classes e dependências: não autoriza substituição ou execução. Reconciliar uma implementação comum e preservar as diferenças, com revisão independente e testes antes de qualquer integração.

## Caso de falsa equivalência
`validate_plan` de [Pop!_OS #298](https://github.com/LMhdez/gaslux/blob/fa2ffe35ae0398e2df83f6ee5aa948e0577686cb/auto_tests/tools/gaslux_popos_six_gpt_contract.py#L138) valida um plano sintético fixo e transaction_id; a [função atual](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/assets/live/libertix-installation-plan.py#L198) valida schema e regras do plano de instalação. Mesmo nome, contratos e assinaturas diferentes. Não substituir uma pela outra.

## Candidatos concretos a reutilização
### mint
PRs: #260, #263, #383, #388.
- [auto_tests/tools/compact_ovmf_target.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/auto_tests/tools/compact_ovmf_target.py)
- [assets/live/libertix-first-boot-verify.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/assets/live/libertix-first-boot-verify.py)
- [auto_tests/tools/verify_windows_guest_recovery.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/auto_tests/tools/verify_windows_guest_recovery.py)
- [assets/live/gaslux_distribution_capabilities.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/assets/live/gaslux_distribution_capabilities.py)

Existing allocation and installed-system/Windows observation validators do not replace historical Windows two-stage harness or same-COW validation. Reconcile the two historic harness variants and retain cleanup differences.

### zorin
PRs: #224, #264.
- [assets/live/libertix-first-boot-verify.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/assets/live/libertix-first-boot-verify.py)
- [auto_tests/tools/verify_windows_guest_recovery.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/auto_tests/tools/verify_windows_guest_recovery.py)

Existing first-boot/Windows validators are reusable contracts; isolated Zorin initramfs regeneration and real shared COW harness not shown equivalent.

### cachyos
PRs: #248, #263, #314, #335.
- [assets/live/gaslux_distribution_capabilities.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/assets/live/gaslux_distribution_capabilities.py)
- [auto_tests/tools/verify_windows_guest_recovery.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/auto_tests/tools/verify_windows_guest_recovery.py)
- [auto_tests/tools/gpt_fd_crosscheck_offline_compat.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/auto_tests/tools/gpt_fd_crosscheck_offline_compat.py)

Offline GPT/Windows recovery evidence does not replace native pacstrap or BCD A/B attribution. Reconcile common Windows harness before recovering distro-specific code.

### popos
PRs: #291, #298, #324, #329, #353.
- [assets/live/gaslux_popos_preflight.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/assets/live/gaslux_popos_preflight.py)
- [assets/live/libertix-installation-plan.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/assets/live/libertix-installation-plan.py)
- [auto_tests/installer_observer/qemu_local_disk_witness.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/auto_tests/installer_observer/qemu_local_disk_witness.py)

Native live diagnostics and production plan validation are distinct from synthetic six-GPT ownership, fsck and trace. Same-name validate_plan is not interchangeable.

### q4os
PRs: #299, #318, #338, #345, #351.
- [assets/live/gaslux_q4os_preflight.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/assets/live/gaslux_q4os_preflight.py)
- [auto_tests/installer_observer/host_fd_boundary.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/auto_tests/installer_observer/host_fd_boundary.py)
- [auto_tests/installer_observer/qemu_local_disk_witness.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/auto_tests/installer_observer/qemu_local_disk_witness.py)

Reuse current HOST-only measurement primitives; historical authenticated QMP session/supervisor and native Calamares remain separate scopes. Current witness never starts VM.

### bazzite
PRs: #250, #262, #280, #320, #357.
- [assets/live/gaslux_bazzite_preflight.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/assets/live/gaslux_bazzite_preflight.py)
- [assets/live/gaslux_bazzite_iso_signature.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/assets/live/gaslux_bazzite_iso_signature.py)
- [auto_tests/installer_observer/qemu_local_disk_witness.py](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/auto_tests/installer_observer/qemu_local_disk_witness.py)

Existing ISO signature gate checks caller-pinned digest/key and detached signature, not native installer or OCI/RPM/deployment provenance. Preserve separate historical research and denial.


## Próximo incremento
Validar por AST, dependências, constantes, entradas/saídas e testes diferenciais os candidatos relevantes; pesquisar os restantes caminhos/linguagens e outras PRs antes de afirmar cobertura total. Depois catalogar os findings Safety, RED/GREEN e disponibilidade dos artefactos. Não executar código histórico a partir de uma referência documental. Nenhum novo consumidor automático, workflow, autorização ou gate formal; a PR permanece Draft.

## Extensão da memória e validação estrutural — 24/11/2026

Cobertura lexical Python/Shell de dev completa na snapshot d89f1547: 247/247 ficheiros, 3 625 declarações; 122 declarações históricas com coincidência nominal (48 chaves nome/tipo), 666 sem coincidência. Ver [extensão JSON](GASLUX_HISTORICAL_SYMBOL_EXTENSION.json). As seis PRs históricas continuam o âmbito selecionado; outras linguagens e restantes PRs não foram integralmente analisadas.

[Catálogo Safety e falhas](GASLUX_HISTORICAL_FINDINGS.md): 12 findings/bloqueios, sete registos de falhas/correções, 12 runs com metadados confirmados. Estados históricos não são fecho atual nem aprovação formal.

Novo auditor AST no workflow Factory existente: blobs Python exatos, SHA Git recalculado, sem importação de módulos; comparação por AST incluindo assinatura, constantes e decorators, ignorando posições. Artefacto de descoberta limitado. Teste diferencial restrito às duas funções históricas Mint de reconhecimento de shutdown, 16 fixtures positivas/negativas, AST exatamente igual a um template revisto antes de executar a função isolada; não executa módulo, não comprova equivalência geral. CI real deste novo HEAD ainda por confirmar. A auditoria AST de blobs reais corre somente na PR #419 same-repo; testes offline no job contracts. A seleção existente recebe referências numéricas, SHA, identificadores/estados de findings, contagens e fonte por distribuição a partir dos índices trusted-main, nunca texto livre; no máximo 12 findings e 12 comparações Git. O artefacto AST não é automaticamente promovido a conhecimento validado; revisão e integração continuam necessárias. Sem nova workflow, alteração de permissões, AST de geração Qwen, publisher ou gate formal. Nenhum merge.
