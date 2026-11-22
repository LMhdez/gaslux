# HOST/FD offline import from #312 into dev

> **Estado revalidado a 22-11-2026:** [PR #319](https://github.com/LMhdez/gaslux/pull/319) foi **MERGED em dev**, commit [b57bbf97057a154beeb744bcbeef710687d520b4](https://github.com/LMhdez/gaslux/commit/b57bbf97057a154beeb744bcbeef710687d520b4), HEAD final da PR `2db6de367af530812cd242fe8061c88f2b8699f6`. O texto abaixo foi originalmente redigido **antes** do merge e descreve a extração inicial de 6 ficheiros; a PR final tinha **10** e adicionou a correção O_PATH e o diagnóstico de peer/sessão Unix local. Os gates descritos são históricos, não uma instrução para reabrir a PR integrada. O módulo HOST/FD atual em dev tem blob `6727ca454b9282079400593356516097a297b9d6`, e o módulo peer local `e176d90f487aede071b12bced9d5d3a41d93199e`. Ambos continuam **deny-only**: não autenticam guest, backing ou autoridade de escrita. Consultar [contrato peer local](OBSERVER_LOCAL_PEER_TRUST_BOUNDARY.md), [manual histórico dos agentes](AGENT_HISTORICAL_PLAYBOOK.md) e [índice CI/VM](CI_VM_EVIDENCE_INDEX.md).


## Origin and exact source
- Source PR #312 at `2ec6c97cbd72a52349e0efdcdf3a75b0d120fa64`, stacked on #294 `e7941ef3eb26c0cae1a2d7fbe1b3009eb050c5c9`.
- Two source blobs **unchanged**: `host_fd_boundary.py` `35bc7f4a37ec8821aa32c15660f83ef80e3e29b9`, `host_qemu_fd_evidence.py` `74bd1a7f1fde62f9dfb74b5374d5f423909eabe0`.
- F-01/F-02/F-03 tests from #294 `758ab4769787b9de005dbfb78688079762ed424a` are reused with the sole `ProcessSeal` import switched from the **experimental** `lab_identity` to the corrected `host_fd_boundary`. No test deletion or xfail.
- New direct-dev tests and least-privilege offline workflow; no old pinned-dev checkout or QEMU executor.

## Security model
The modules are **Linux HOST diagnostics** and never installation authorities. Source code can reopen a numbered `/proc/PID/fd` read-only and issue exactly the observational QMP commands `qmp_capabilities` and `query-block` to an existing, peer-checked local socket when *explicitly invoked*. The imported modules **do not launch QEMU** and do not import `lab_identity`, `state_machine`, `gpt_lab_provenance`, `remote_verifier`, `transport_vnc` or guest controllers. This is not an external VM attestation or independent provenance.

Local HOST observations are classified `LOCALLY_MEASURED`, externally provided claims remain `CLAIMED`, and `deviceFdAssociationProven`, `vmDiskBindingProven` remain false. F-01 rejects forged QMP trust provenance, F-02 refuses caller-supplied QCOW2 authority, and F-03 checks remote descriptor flags and process/FD identity before **and after** inspection. **FD ABA between observations remains unresolved**; the contract is deny-only. Importability alone never authorizes guest, image writes, installation or disk/Windows operations.

## Historical integration gate (before #319 merged)
Do not merge without the exact-candidate CI, diff review, and **independent Safety verdict scoped to these five files and the resulting dev composition**. The #294 earlier `ACCEPTABLE_DENY_ONLY` verdict cannot be borrowed to approve the #312 differential. All test files operate only on disposable synthetic regular files and Python subprocesses. No QEMU-system, Windows Setup, Calamares, input or physical storage is exercised. Any later addition of executable QMP controls or writer mandates separate authorization and tests.

`main`, production backends, stable catalogs, ESP/BCD/WinRE/NVRAM were outside the PR scope. The original dev base was `f44386674fff437043fee82ff6c86851d3168b78`; it is **not** the current dev HEAD. Revalidate the live code and CI for any future extension.
