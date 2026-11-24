# GASLUX — mapa de recuperação por backend (24-11-2026 UTC)

Complemento dos dossiers técnicos em [dev fixado](https://github.com/LMhdez/gaslux/tree/d89f1547c50787e4640164e34bfd1863134e2908/docs/distro-backends), do [manual histórico](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/docs/AGENT_HISTORICAL_PLAYBOOK.md) e do [índice VM](https://github.com/LMhdez/gaslux/blob/d89f1547c50787e4640164e34bfd1863134e2908/docs/CI_VM_EVIDENCE_INDEX.md). Não substitui esses documentos nem o registo formal. `main=d408ffa603272007d9cb0c2c896ed1789f775a80`; `dev=d89f1547c50787e4640164e34bfd1863134e2908`. Registo formal de evidências: zero entradas.

## 1. Código histórico localizável

Comparação por caminho e blob entre seis PRs e a árvore completa dev: **59 referências, 58 caminhos distintos, 13 workflows** ausentes no caminho exato em dev. Isto não prova que não exista implementação equivalente noutro caminho. O índice [JSON](GASLUX_BACKEND_REUSE_INVENTORY.json) fixa todos os SHA e blobs; consultar código e dependências antes de recuperar.

| Backend | PR / fonte | Caminhos ausentes | Próximo incremento de análise |
|---|---|---:|---|
| mint | [#260](https://github.com/LMhdez/gaslux/tree/7ab2a431767d212566ab57b834f299f8308dbda6) | 7 | Reconcile #260/#271/#274/#276/#278 with #383/#388 compact lab; recover existing Windows harness and independent validator. Resolve Safety findings and confirm native boot only after lab admission. |
| zorin | [#224](https://github.com/LMhdez/gaslux/tree/3a10dac2d85dd19849a0736d8f57558827277794) | 6 | Reuse #224 harness; reconcile #264/#277/#281 with #328/#332/#333. Keep direct-kernel and source/FD checks separate from native boot and production installation. |
| cachyos | [#263](https://github.com/LMhdez/gaslux/tree/8b82ecdf5c5ef3e7d9d712c5d60b679bb1615f9f) | 13 | Recover #248 positive witness; #263 final real job skipped. Reconcile #314/#335 BCD attribution before claiming Windows integrity or in-place recovery. |
| popos | [#298](https://github.com/LMhdez/gaslux/tree/fa2ffe35ae0398e2df83f6ee5aa948e0577686cb) | 7 | Review #291 F-01–F-04 and #298/#324/#329/#353 exact composition; distinguish absent filesystem before install from identity mismatch. No distinst or real writer admission from synthetic evidence. |
| q4os | [#318](https://github.com/LMhdez/gaslux/tree/f6a446b2c3e4ec05cefdc2d084a3024464ca912e) | 9 | Reconcile #299/#318/#338/#345/#351; preserve existing Calamares visual states, resolve Summary identity and QMP/FD boundary before native install. |
| bazzite | [#320](https://github.com/LMhdez/gaslux/tree/b6796fe3e920ca02b57041d32a2dff7d37e9c480) | 17 | Reconcile #250/#262/#280/#320/#357; reuse native route research; resolve independently authenticated ISO/OCI, exact write-set and Observer provenance before any installer execution. |

## 2. Execuções históricas e limites

Os SHA abaixo são os devolvidos pelo endpoint Actions, não necessariamente o HEAD final da PR ou o checkout efetivo; os logs são fonte adicional e arquivos não foram reverificados neste lote.

| Backend | Run / job | SHA do run | Resultado do job | Observação e nível de verificação |
|---|---|---|---|---|
| mint | [44704787925](https://github.com/LMhdez/gaslux/actions/runs/44704787925/job/136182418950) | `98d7b450a275` | SUCCESS | Windows→Mint→Windows in disposable same COW; direct kernel; native GRUB/update/rollback not proved. (prior_log_audit) |
| zorin | [44582546627](https://github.com/LMhdez/gaslux/actions/runs/44582546627/job/135766869236) | `3a10dac2d85d` | SUCCESS | Genuine installed Zorin reboots from owned GPT after initramfs regeneration. Explicit NOT TESTED: Windows dual boot/recovery, Gaslux bootloader, kernel update, uninstall. (job_log) |
| cachyos | [44653217724](https://github.com/LMhdez/gaslux/actions/runs/44653217724/job/136013396583) | `a3078779f809` | SUCCESS | Real Windows/Archiso/pacstrap/discard job success; assertion stage requires native kernel, pacman, protected hashes and Windows return after discard; sameDiskDualBootVerified, windowsInPlaceRecoveryVerified and rollbackProven false. (job_log_and_successful_assertion_stage) |
| cachyos | [45156385941](https://github.com/LMhdez/gaslux/actions/runs/45156385941/job/137631711342) | `8b82ecdf5c5e` | SKIPPED | Exact final HEAD real Windows/Archiso/pacstrap job skipped; static/synthetic job passed. Do not inherit positive guest status from #248. (job_metadata) |
| popos | [44561473570](https://github.com/LMhdez/gaslux/actions/runs/44561473570/job/135692392513) | `85c9ea30b75c` | FAILURE | Live guest refused GPT identity: fifth partition signature probe returned empty type. No installed guest or dual boot. (job_log) |
| q4os | [44641233701](https://github.com/LMhdez/gaslux/actions/runs/44641233701/job/135972508547) | `91ed606c56a6` | SUCCESS | Calamares UI transitions=8; second replica also success (job 135972509168). Installation false, Windows disk not attached, Summary not visited. ISO 1851392000 bytes. (job_log) |
| q4os | [44646209124](https://github.com/LMhdez/gaslux/actions/runs/44646209124/job/135989332346) | `d35be9643059` | FAILURE | Both replicas failed (other job 135989332883); dossier attributes failure to Summary visual validation. Root cause requires renewed log/fixture review; no installation. (job_metadata_and_dossier) |
| bazzite | [44443420174](https://github.com/LMhdez/gaslux/actions/runs/44443420174/job/135289898262) | `c7c808f6da61` | SUCCESS | Diskless locale stage successful; dossier records installer selection options visible but disabled. No installation or Blivet editor proof. (job_metadata_and_dossier) |
| bazzite | [44576081171](https://github.com/LMhdez/gaslux/actions/runs/44576081171/job/135745407366) | `ad26cb10ee2c` | FAILURE | GUEST_PROBE=FAIL; missing mandatory Custom selection evidence. No editor, install or write authorization. Run metadata SHA overrides different HEAD cited in historical dossier. (job_log) |

A CI verde de #263 não prova novo boot: o job real foi SKIPPED. O run Bazzite 44576081171 tem SHA `ad26cb10...`, diferente do HEAD histórico citado no dossier; preservar ambos com a distinção correta. Os casos Pop/Q4OS/Bazzite falhados são evidências negativas úteis, não gates cumpridos.

## 3. Propostas autónomas atuais

| Backend | PR | Estado observado | Blob do ficheiro face a dev |
|---|---|---|---|
| mint | [#393](https://github.com/LMhdez/gaslux/pull/393) | merged_dev | different: assess_mint_lifecycle present in dev; later #407 modifies same file. |
| mint | [#407](https://github.com/LMhdez/gaslux/pull/407) | merged_dev | identical: match_mint_223_iso_descriptor present; matching descriptor is not authenticated ISO. |
| zorin | [#395](https://github.com/LMhdez/gaslux/pull/395) | draft | different: Read-only helper. |
| bazzite | [#400](https://github.com/LMhdez/gaslux/pull/400) | draft | different: Read-only helper. |
| cachyos | [#411](https://github.com/LMhdez/gaslux/pull/411) | draft | different: Read-only helper; preserve Mint functions in shared file. |
| popos | [#412](https://github.com/LMhdez/gaslux/pull/412) | draft | different: Read-only helper. |
| q4os | [#413](https://github.com/LMhdez/gaslux/pull/413) | draft | different: Read-only helper. |

A presença em dev de `assess_mint_lifecycle` e `match_mint_223_iso_descriptor` foi confirmada no código. O blob da #407 é idêntico; o da #393 difere porque o ficheiro teve evolução posterior. Não repetir essas funções. Nas cinco PRs Draft, a diferença de blob não autoriza integração, nem prova falta de equivalência funcional. Confirmar HEAD, CI, proprietário, composição e Safety aplicáveis.

## 4. Continuação

Pesquisar implementações equivalentes por função/teste e blobs noutros caminhos; inspecionar dependências já verificadas; separar extração non-writer de VM real; resolver findings antes de execução. Acrescentar evidências com run/job, resultado negativo, origem, limites e revalidação. Priorizar preservação dos artefactos autorizados ainda disponíveis, sem exportar ISO/QCOW2/TPM/segredos. Não introduzir workflow duplicado nem preencher o registo formal com este inventário. Os seis dossiers existentes continuam referências canónicas. Nenhum consumidor automático novo foi implementado neste lote documental.
