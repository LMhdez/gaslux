# GASLUX — Catálogo de falhas e Safety (snapshot 24-11-2026)

[JSON](GASLUX_HISTORICAL_FINDINGS.json) · catálogo inicial, não exaustivo. Os pareceres técnicos históricos usam a conta partilhada; não são aprovações formais independentes. A resolução offline pertence exclusivamente ao SHA e âmbito revistos. Novo HEAD requer revalidação. Nenhuma autoridade operacional.

| Backend | Finding | Origem / parecer | Estado no registo |
|---|---|---|---|
| mint | F-383-01: Report path confinement and exclusive creation | [#383](https://github.com/LMhdez/gaslux/pull/383#issuecomment-7085401815) | open_at_review |
| mint | F-383-02: OVMF copy destination TOCTOU | [#383](https://github.com/LMhdez/gaslux/pull/383#issuecomment-7085401815) | open_at_review |
| popos | F-01: Pathname ownership and deletion | [#291](https://github.com/LMhdez/gaslux/pull/291#issuecomment-7066892313) | remediation_reported_reaudit_required; [#298](https://github.com/LMhdez/gaslux/pull/298#issuecomment-7077439234) |
| popos | F-02: Ambiguous synthetic QEMU trace | [#291](https://github.com/LMhdez/gaslux/pull/291#issuecomment-7066892313) | remediation_reported_reaudit_required; [#298](https://github.com/LMhdez/gaslux/pull/298#issuecomment-7077439234) |
| popos | F-03: Verification error mistaken for injected fault | [#291](https://github.com/LMhdez/gaslux/pull/291#issuecomment-7066892313) | remediation_reported_reaudit_required; [#298](https://github.com/LMhdez/gaslux/pull/298#issuecomment-7077439234) |
| popos | F-04: QCOW2 zero extents mistaken for empty child | [#291](https://github.com/LMhdez/gaslux/pull/291#issuecomment-7066892313) | remediation_reported_reaudit_required; [#298](https://github.com/LMhdez/gaslux/pull/298#issuecomment-7077439234) |
| q4os | R-01: Legacy QMP unauthenticated peer | [#299](https://github.com/LMhdez/gaslux/pull/299#issuecomment-7078059250) | resolved_offline_at_review; [#318](https://github.com/LMhdez/gaslux/pull/318#issuecomment-7078921738) |
| q4os | R-02: Injected factory bypass plus cleanup identity regression | [#299](https://github.com/LMhdez/gaslux/pull/299#issuecomment-7078059250) | remediation_reported_reaudit_required; [#318](https://github.com/LMhdez/gaslux/pull/318#issuecomment-7080249734) |
| q4os | R-03: Unbounded CLI reason disclosure | [#299](https://github.com/LMhdez/gaslux/pull/299#issuecomment-7078059250) | resolved_offline_at_review; [#318](https://github.com/LMhdez/gaslux/pull/318#issuecomment-7078921738) |
| q4os | R-02-CLEANUP-01: Foreign pidfd accepted for cleanup | [#318](https://github.com/LMhdez/gaslux/pull/318#issuecomment-7078921738) | remediation_reported_reaudit_required; [#318](https://github.com/LMhdez/gaslux/pull/318#issuecomment-7080249734) |
| bazzite | BZD-CLI-OUTPUT-BOUNDARY-01: Arbitrary output pathname replaced by stdout-only deny CLI | [#320](https://github.com/LMhdez/gaslux/pull/320#issuecomment-7080851676) | resolved_offline_at_review; [#320](https://github.com/LMhdez/gaslux/pull/320#issuecomment-7080851676) |
| bazzite | BZD-BOOTC-PREWRITE-SOURCE-01: Native binary first-write and ESP ownership not proved | [#320](https://github.com/LMhdez/gaslux/pull/320#issuecomment-7081050352) | producer_blocker |

## Falhas / correções

| Backend | RED | GREEN | Limite |
|---|---|---|---|
| mint | [44572398014](https://github.com/LMhdez/gaslux/actions/runs/44572398014) | [44704787925](https://github.com/LMhdez/gaslux/actions/runs/44704787925) | shutdown recognition CRLF; same-COW witness only |
| mint | [45064087180](https://github.com/LMhdez/gaslux/actions/runs/45064087180) | [45064724367](https://github.com/LMhdez/gaslux/actions/runs/45064724367) | qemu-img format autodetection; separate two Safety findings remain |
| q4os | [45015332942](https://github.com/LMhdez/gaslux/actions/runs/45015332942) | [45016230742](https://github.com/LMhdez/gaslux/actions/runs/45016230742) | initial QMP/FD/CLI offline remediation; later cleanup regression |
| q4os | [45029941312](https://github.com/LMhdez/gaslux/actions/runs/45029941312) | [45030505844](https://github.com/LMhdez/gaslux/actions/runs/45030505844) | pidfd cleanup identity; offline GREEN, independent re-review required |
| popos | não indexado | [45008842451](https://github.com/LMhdez/gaslux/actions/runs/45008842451) | four synthetic findings remediation; not independently accepted |
| bazzite | não indexado | [45033764291](https://github.com/LMhdez/gaslux/actions/runs/45033764291) | stdout-only CLI narrow deny-only review at historical SHA |
| bazzite | não indexado | [45036376285](https://github.com/LMhdez/gaslux/actions/runs/45036376285) | bootc source prewrite deny-only; not runtime provenance |

Metadados Actions dos 12 runs foram consultados; a relação causal é documentada pelas fontes indicadas, não uma nova execução diferencial. Para concluir o catálogo, examinar comentários e revisões das PRs restantes, incluindo findings sem identificador, follow-ups e HEADs atuais. Não importar para evidence.json.
