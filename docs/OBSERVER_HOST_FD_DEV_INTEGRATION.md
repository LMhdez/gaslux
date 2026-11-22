# HOST/FD offline import from #312 into dev

## Origin and exact source
- Source PR #312 at `2ec6c97cbd72a52349e0efdcdf3a75b0d120fa64`, stacked on #294 `e7941ef3eb26c0cae1a2d7fbe1b3009eb050c5c9`.
- Two source blobs **unchanged**: `host_fd_boundary.py` `35bc7f4a37ec8821aa32c15660f83ef80e3e29b9`, `host_qemu_fd_evidence.py` `74bd1a7f1fde62f9dfb74b5374d5f423909eabe0`.
- F-01/F-02/F-03 tests from #294 `758ab4769787b9de005dbfb78688079762ed424a` are reused with the sole `ProcessSeal` import switched from the **experimental** `lab_identity` to the corrected `host_fd_boundary`. No test deletion or xfail.
- New direct-dev tests and least-privilege offline workflow; no old pinned-dev checkout or QEMU executor.

## Security model
The modules are **Linux HOST diagnostics** and never installation authorities. Source code can reopen a numbered `/proc/PID/fd` read-only and issue exactly the observational QMP commands `qmp_capabilities` and `query-block` to an existing, peer-checked local socket when *explicitly invoked*. The imported modules **do not launch QEMU** and do not import `lab_identity`, `state_machine`, `gpt_lab_provenance`, `remote_verifier`, `transport_vnc` or guest controllers. This is not an external VM attestation or independent provenance.

Local HOST observations are classified `LOCALLY_MEASURED`, externally provided claims remain `CLAIMED`, and `deviceFdAssociationProven`, `vmDiskBindingProven` remain false. F-01 rejects forged QMP trust provenance, F-02 refuses caller-supplied QCOW2 authority, and F-03 checks remote descriptor flags and process/FD identity before **and after** inspection. **FD ABA between observations remains unresolved**; the contract is deny-only. Importability alone never authorizes guest, image writes, installation or disk/Windows operations.

## Integration gate
Do not merge without the exact-candidate CI, diff review, and **independent Safety verdict scoped to these five files and the resulting dev composition**. The #294 earlier `ACCEPTABLE_DENY_ONLY` verdict cannot be borrowed to approve the #312 differential. All test files operate only on disposable synthetic regular files and Python subprocesses. No QEMU-system, Windows Setup, Calamares, input or physical storage is exercised. Any later addition of executable QMP controls or writer mandates separate authorization and tests.

`main`, production backends, stable catalogs, ESP/BCD/WinRE/NVRAM remain untouched. Branch from `dev` `f44386674fff437043fee82ff6c86851d3168b78`; revalidate its HEAD on every prospective merge.
