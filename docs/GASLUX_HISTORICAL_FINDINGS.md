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

## Extensão verificada — 25-11-2026 UTC

O catálogo contém agora 20 registos (12 anteriores + 8 novos), 23 runs e 11 relações de falha/correção ou diagnóstico. As quatro correções transversais são encaminhadas a todos os backends pelo leitor existente, mantendo o limite de 12 e excluindo narrativa. CAT-* são identificadores de catálogo atribuídos nesta intervenção, não IDs Safety originais.

| Âmbito | Finding / bloqueio | Referência | Estado histórico |
|---|---|---|---|
| shared | D-337-01: Partial positive pread incorrectly authenticated a prefix; exact byte coverage enforced, independent oracle replayed. | [#337](https://github.com/LMhdez/gaslux/pull/337#issuecomment-7080704589); [correção](https://github.com/LMhdez/gaslux/pull/337#issuecomment-7080967838) | resolved_offline_at_review |
| shared | SAFETY2-346-01: Descendant subprocess survived timeout; independent real-subprocess oracle confirmed corrected group cleanup. | [#346](https://github.com/LMhdez/gaslux/pull/346#issuecomment-7083769906); [correção](https://github.com/LMhdez/gaslux/pull/346#issuecomment-7083769906) | resolved_offline_at_review |
| shared | F-361-01: Automation restored guest before invalid-source rejection; source gate moved before guest operations. | [#361](https://github.com/LMhdez/gaslux/pull/361#issuecomment-7082353359); [correção](https://github.com/LMhdez/gaslux/pull/361#issuecomment-7082697059) | resolved_offline_at_review |
| shared | F-361-02: Deployment audit counted non-executable PowerShell imports; here-string false closer regression corrected. | [#361](https://github.com/LMhdez/gaslux/pull/361#issuecomment-7082353359); [correção](https://github.com/LMhdez/gaslux/pull/361#issuecomment-7082951550) | resolved_offline_at_review |
| cachyos | CAT-314-O-PATH: Producer reproduced O_PATH misclassified as read-only; explicit rejection and regression added. Catalog ID assigned, not original Safety identifier. | [#314](https://github.com/LMhdez/gaslux/pull/314#issuecomment-7078980928); [correção](https://github.com/LMhdez/gaslux/pull/314#issuecomment-7078980928) | remediation_reported_reaudit_required |
| cachyos | CAT-335-BCD-ATTRIBUTION: Historical BCD A/B final hashes differ despite equal changed offsets; process attribution and rollback unproven. Catalog ID assigned. | [#335](https://github.com/LMhdez/gaslux/pull/335#issuecomment-7080421852) | producer_blocker |
| zorin | CAT-333-HANDOFF-ORIGIN: Technical approval only offline deny-only; plan/ISO/VM origin and actual Ubiquity/partman execution not authenticated. Catalog ID assigned. | [#333](https://github.com/LMhdez/gaslux/pull/333#issuecomment-7080579295) | producer_blocker |
| bazzite | BZD-BOOTC-SRPM-ELF-BINDING-01: SRPM source matches upstream but signature and source-to-ELF binding unproved; alongside route threatens shared ESP. Review requested. | [#357](https://github.com/LMhdez/gaslux/pull/357#issuecomment-7081352892) | producer_blocker |

RED/GREEN: #337 [RED](https://github.com/LMhdez/gaslux/actions/runs/45033893644) → [GREEN](https://github.com/LMhdez/gaslux/actions/runs/45035718212); #346 [expected RED](https://github.com/LMhdez/gaslux/actions/runs/45037813419) → [GREEN](https://github.com/LMhdez/gaslux/actions/runs/45056131189). O primeiro workflow #346 concluiu SUCCESS porque a oracle esperava demonstrar o defeito; não é prova de correção. #361 [RED](https://github.com/LMhdez/gaslux/actions/runs/45046490577) → [GREEN](https://github.com/LMhdez/gaslux/actions/runs/45049176083). CachyOS #335 [falha VM](https://github.com/LMhdez/gaslux/actions/runs/44900941635) → [regressões offline](https://github.com/LMhdez/gaslux/actions/runs/45031774164): não é reparação da falha de BCD. Todos os metadados dos runs adicionais foram reconsultados; não reexecutámos os ensaios nem arquivámos ZIPs nesta intervenção.

O catálogo continua parcial, não contém aprovação atual, e não modifica formal evidence.json. A CI anterior #45502620847 foi confirmada: 97 testes de contratos, 242 blobs Python, 784 declarações históricas e 3338 atuais, quatro pares AST, 16/16 casos diferenciais apenas shutdown. Os jobs de produção foram SKIPPED. Novo HEAD requer CI e revisão.

## Segundo lote — 25-11-2026 UTC

27 registos, 33 runs, 13 relações. Âmbitos históricos, não autorizações atuais. CAT-* é um ID atribuído pelo catálogo. O limite do seletor permanece 12; a lista completa está no JSON.

| Âmbito | Finding | Fonte | Estado histórico |
|---|---|---|---|
| shared | F-391-01: AST validator allowed nested callback and evidence mutation; corrected read-only contract independently revalidated at exact HEAD. | [#391](https://github.com/LMhdez/gaslux/pull/391#issuecomment-7105801147) | resolved_offline_at_review |
| shared | CAT-414-TRIAGE-ACTOR: Unknown same-repository bot actor caused triage failure when configured login was empty; exact observed actor fallback, scoped Safety review and blocked-path runtime validation. Catalog ID assigned. | [#414](https://github.com/LMhdez/gaslux/pull/414#issuecomment-7142029288) | resolved_offline_at_review |
| popos | P-324-01: Same-inode/same-size mutation between digest, interpretation and export; frozen evidence snapshots with byte equality and exclusive outputs independently checked. | [#324](https://github.com/LMhdez/gaslux/pull/324#issuecomment-7079104266) | resolved_offline_at_review |
| popos | POP-GPT-FD-01: Workspace-to-FD-to-GPT origin remediation; synthetic six-GPT checkpoint contracts green, independent differential review requested. | [#329](https://github.com/LMhdez/gaslux/pull/329#issuecomment-7080463871) | remediation_reported_reaudit_required |
| popos | POP-DISTINST-ELF-SOURCE-BINDING-01: Pinned installer ELF not authenticated to candidate source/build; prewrite plan unavailable, no distinst execution. | [#353](https://github.com/LMhdez/gaslux/pull/353#issuecomment-7081262461) | producer_blocker |
| q4os | Q4OS-ISO-SIGNED-PROVENANCE-01: Official checksum and ISO readback verified per producer, independent ISO signature chain not verified; unsigned experimental catalog cannot authorize native installation. | [#351](https://github.com/LMhdez/gaslux/pull/351#issuecomment-7081160990) | producer_blocker |
| q4os | Q4OS-RUNLAB-BOUNDARY-01: Real paused QEMU diagnostic reuses measured FD/peer primitives without issuing operational session; independent review requested, no guest boot. | [#338](https://github.com/LMhdez/gaslux/pull/338#issuecomment-7080518502) | remediation_reported_reaudit_required |

Metadados de 10 runs adicionais conferidos no GitHub. Pareceres de conta partilhada não constituem aprovação formal independente. O catálogo permanece parcial, sem entrada em evidence.json. Não reexecutámos os ensaios históricos nesta extensão.
