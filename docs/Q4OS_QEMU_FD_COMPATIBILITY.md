# Q4OS — laboratório independente de compatibilidade QEMU/FD

**Estado: experimental, runner descartável, guest parado, sem autorização de instalação.**

Este laboratório investiga apenas se o QEMU instalado pelo GitHub Actions aceita
descritores herdados para OVMF CODE/VARS, QCOW2 e imagem CD-ROM sintética.
Não importa, executa ou desbloqueia `q4os_win10_qmp_supervisor.run_lab()`,
`q4os_win10_qmp_boot.supervise()`, Calamares ou o Installer Observer.
As correções R-01/R-02/R-03 da PR #318 permanecem independentes.

## Superfície e isolamento

- Workflow: `.github/workflows/gaslux-q4os-qemu-fd-compatibility.yml`;
  execução exclusivamente em `push` da branch experimental #318,
  no repositório exato, sem `workflow_dispatch`, sem segredos e apenas
  `contents: read`. A execução em runner `ubuntu-24.04` instala
  `qemu-system-x86`, `qemu-utils` e `ovmf` a partir dos repositórios Ubuntu.
- O código começa por exigir `GITHUB_ACTIONS=true`, `RUNNER_ENVIRONMENT=github-hosted`,
  `GITHUB_REPOSITORY=LMhdez/gaslux`, UID não-root. Os únicos suportes são
  criados em `RUNNER_TEMP` e subdiretórios `0700`, com ficheiros `0600`.
  Não procura nem abre discos de host, /dev/kvm, ISO de Windows ou Linux, NVRAM,
  partições/ESP/BCD/WinRE ou recursos de produção.
- QEMU: `qemu-system-x86_64`, machine q35, acelerador **TCG**, 1 vCPU,
  128 MiB, `-S -nodefaults -no-reboot -display none -serial none -net none`.
  **-S mantém vCPU parada**: não há firmware executado, boot, convidado,
  instalador, nem input guest.
- Firmware CODE/VARS é copiado do pacote OVMF do runner (o manifesto prova
  SHA-256 e tamanho das cópias). QCOW2 de 64 MiB, sem backing file, é
  construído por `qemu-img` e validado quanto a formato, tamanho virtual
  e backing. A imagem CD-ROM é deliberadamente não arrancável.
- O laboratório usa `pass_fds` com descritores abertos por `O_NOFOLLOW`,
  `fstat` de UID, inode, tipo e link count. Experimenta separadamente
  `file=/proc/self/fd/N` e `-add-fd fd=N,set=K` com
  `file=/dev/fdset/K`, para pflash/CODE/VARS/QCOW2/CD-ROM. Esta
  é uma medição de compatibilidade, **não** uma autorização para replicar a
  estratégia no backend de produção.
- QMP utiliza apenas `qmp_capabilities` para negociação e
  `query-status`, `query-block`, `query-fdsets` para leitura. Verifica
  `SO_PEERCRED` (PID/UID), socket de proprietário/inode esperado,
  nascimento de processo em /proc e pidfd real. `query-status` deve devolver
  `running=false`. Não envia `send-key`, `cont`, `quit`,
  comandos guest, nem comandos de escrita. Terminação usa pidfd e `wait()`.

## Adversários e limites das provas

O mesmo programa contém recusas por FD comum ou PID divergente, ficheiro de
destino errado, renomeação depois da abertura, substituição do nome do socket,
alteração artificial de OVMF VARS, FD fechado e QEMU vivo sem socket QMP.
O inventário de `/proc/<pid>/fd` compara device/inode com os descritores
fixados; os FDs não são considerados propriedade apenas por pathname.
O processo QEMU e o respetivo grupo devem desaparecer após limpeza; não se
afirma limpeza de toda uma árvore de processos do host, nem rollback Windows.

A prova do FD set é válida **somente** para a versão exata de QEMU/OVMF e
configuração de dispositivos que constem no artefacto desta execução.
Falhas reais não devem ser convertidas em `PASS` nem atribuídas à causa
errada sem logs verificáveis. `-S` não prova compatibilidade em execução
efetiva de firmware ou atualização de bootloader.

## Evidência e recuperação

Artefacto Actions `q4os-paused-qemu-fd-compatibility` (retenção 7 dias):
`q4os-fd-evidence.json`. Inclui SHA do commit, versão QEMU, geometria,
SHA-256 e tamanho de cada ficheiro criado, inventário de inodes vistos pelo
QEMU, QMP read-only, recusa dos adversários, exit code e limpeza por pidfd,
bem como hashes antes/depois. Não inclui discos, NVRAM, credenciais, stderr
bruto nem caminhos privados. Os artefactos do laboratório são efémeros.

Ação para revisão: comparar o SHA do artefacto com o HEAD da PR #318,
confirmar sucesso do workflow no mesmo SHA, analisar se há um `PASS` real
para cada método FD e inspecionar os códigos de recusa e cleanup. Uma CI
verde **não** transforma esta experiência em prova de instalação.

Gates obrigatórios inalterados:

```text
QEMU_FD_BACKING_VERIFIED=false
productionStorageWritesAuthorized=false
q4osNativeInstallationVerified=false
sameDiskDualBootVerified=false
windowsInPlaceRollbackProven=false
releaseEligible=false
stable=false
```

Compatibilidade experimental positiva, se demonstrada, deve ser revista
independentemente pelo GASLUX-SAFETY antes de qualquer desenho para
o caminho operacional. A PR permanece Draft e não sofre merge automático.

Generated-by: GPT-6; GPL-3.0; revisão humana conforme AI_POLICY.md.

## Resultado experimental verificado — 22/11/2026

Execução de GitHub Actions [#45022713512](https://github.com/LMhdez/gaslux/actions/runs/45022713512) no SHA `4db1364df0a6995300ef017b963580c4c026d61d`: **SUCCESS**. Evidência JSON e logs da Action autenticam a execução, não a integridade criptográfica de toda a infraestrutura do GitHub. A configuração executada utilizou **QEMU 8.2.2** (pacote Ubuntu `1:8.2.2+ds-0ubuntu1.18`), q35/TCG, 1 vCPU, 128 MiB, `-S`, QMP limitado a `qmp_capabilities`, `query-status`, `query-block`, `query-fdsets`. Três casos aprovados de QEMU **parado**, sem executar firmware ou guest:

| Estratégia | QMP `running` | `query-fdsets` | Identidade e limpeza |
| --- | --- | ---: | --- |
| `/proc/self/fd/N` | `false` | 0 | PASS |
| `-add-fd` + `/dev/fdset/K` integral | `false` | 4 | PASS |
| FD-set QCOW2/CD e `/proc` pflash | `false` | 2 | PASS |

A primeira experiência do FD-set na [Action #45022108131](https://github.com/LMhdez/gaslux/actions/runs/45022108131) tinha falhado com `Permission denied` ao oferecer apenas `O_RDWR` para meios que o QEMU volta a abrir como leitura. **Correção exclusivamente no laboratório:** acrescentar um segundo descritor `O_RDONLY` (aberto de forma independente, mesmo dispositivo/inode) ao mesmo `set` de `-add-fd` para VARS e QCOW2. Esta causa é corroborada pela aprovação de todas as variantes após a correção; os códigos operacionais não foram modificados.

### Geometria e SHA-256 das cópias efémeras do teste

| Recurso | Tamanho físico | SHA-256 inicial |
| --- | ---: | --- |
| OVMF CODE | 3 653 632 bytes | `ad23261d43116abc3747d59a7837fbf578c9586a8993f4eeba064cd07eccb083` |
| OVMF VARS | 540 672 bytes | `5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e` |
| QCOW2 (64 MiB virtuais; clusters de 65 536 bytes; sem backing) | 196 616 bytes | `1b7af784841125887e688254229e282829e17245d0e47fe7280da9b68a30d9e1` |
| ISO sintética não arrancável | 4 125 bytes | `1fd4ee3e633f2596da24ec60cd7f69aa834bf8083c155a4ce6aad07310da6e49` |

O manifesto JSON contém hashes pós-encerramento por cenário, contagens de inodes coincidentes obtidas de `/proc/<pid>/fd` e resultado de `pidfd`/limpeza. Os hashes de CODE, VARS e do QCOW2 fixado permaneceram iguais; na substituição do *pathname* QCOW2, o ficheiro estranho não foi alterado e o inode original continuou preso ao FD.

**Provas adversariais da Action #45022713512:** FDs comuns/fechados e PID divergente recusados; pidfd genuíno de outro Python e pidfd obsoleto pós-encerramento recusados; symlink/substituição de socket recusada; backing QCOW2 externo identificado e recusado antes de QEMU; hash de VARS adulterado detetado; erro de spawn de executável inexistente identificado; QEMU vivo sem QMP rejeitado; todos os processos filhos diretos terminados/recolhidos sem descendentes remanescentes observados. `qmpSendKeyAcknowledged` não é autorizado nem produzido pelo laboratório. **Nenhuma escrita de produção**, boot ou recuperação Windows comprovados.

A execução final após atualização documental deve confirmar novamente HEAD/CI e manter a PR em Draft. **A reauditoria independente GASLUX-SAFETY permanece obrigatória** antes de considerar alterações ao contrato de arranque operacional; `QEMU_FD_BACKING_VERIFIED=false` mantém-se sem exceções.


## Validação incremental em 22/11/2026 — reutilização do gerador real #318

**Finding Safety R-02-CLEANUP-01:** [parecer independente #7078921738](https://github.com/LMhdez/gaslux/pull/318#issuecomment-7078921738) comprovou que `_cleanup(A, pidfd_B)` podia sinalizar B indevidamente. A regressão [RED #45029941312](https://github.com/LMhdez/gaslux/actions/runs/45029941312) reproduziu duas falhas em subprocessos Python reais. Corrigido no **supervisor** para verificar `_pidfd_target(pidfd, process.pid)` antes de cada `pidfd_send_signal` (TERM e KILL) e imediatamente após a obtenção de pidfd, antes de qualquer autoridade QMP/cleanup. O percurso sintético já não pode transformar um pidfd estrangeiro em sucesso de limpeza. Regressões executadas [GREEN offline #45030107020](https://github.com/LMhdez/gaslux/actions/runs/45030107020), e novamente após alteração do laboratório [#45030298042](https://github.com/LMhdez/gaslux/actions/runs/45030298042). Segurança ainda requer nova reauditoria independente.

**Cenário `pr_argv`:** o mesmo laboratório descartável importa `q4os_win10_qmp_supervisor._qemu_args()` da PR atual, sem mocks, e utiliza o resultado para iniciar **QEMU-system real**. Fica separado de `run_lab()`/`_await_qmp()`, que continuam bloqueados pelo gate de produção. O laboratório muda apenas os parâmetros indispensáveis à segurança da experiência: acrescenta `-S -no-reboot`, reduz para **1 vCPU / 128 MiB** e utiliza exclusivamente cópias de OVMF, QCOW2 e ISO/answer artificiais. Os argumentos nativos do supervisor para **q35, pflash CODE/VARS, AHCI, três drives IDE, QCOW2, CD-ROM e QMP socket** são realmente exercitados. Não é equivalente ao `run_lab()` completo, nem ao perfil de memória e CPU Windows operacional.

**Execução real:** [Action #45030292285](https://github.com/LMhdez/gaslux/actions/runs/45030292285) `SUCCESS`, HEAD `18defdf32e2d030f0c60160f9ece5170cf0c7b7e`. QEMU 8.2.2. A QMP respondeu a `qmp_capabilities`, `query-status` (`running=false`), `query-block` (**6 entradas**) e `query-fdsets` (**0**, por utilizar `/proc/self/fd/N`). `SO_PEERCRED` autenticou o processo QEMU; `/proc/<pid>/fd` comprovou a presença dos descritores para cinco recursos, dois FDs observados por recurso. `pidfd` estrangeiro e obsoleto recusados. O socket substituído foi rejeitado sem comandos adicionais. Cleanup recolheu o filho com exit code 0 e sem descendentes do grupo sobreviventes observados.

| Recurso experimental `pr_argv` | Tamanho | SHA-256 antes e depois |
| --- | ---: | --- |
| OVMF CODE | 3 653 632 B | `ad23261d43116abc3747d59a7837fbf578c9586a8993f4eeba064cd07eccb083` |
| OVMF VARS | 540 672 B | `5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e` |
| QCOW2 sem backing, 64 MiB virtual, clusters 65 536 B | 196 616 B inicial | `1b7af784841125887e688254229e282829e17245d0e47fe7280da9b68a30d9e1` |
| CD de instalação sintético, não arrancável | 4 125 B | `1fd4ee3e633f2596da24ec60cd7f69aa834bf8083c155a4ce6aad07310da6e49` |
| Answer CD sintético, não arrancável | 548 B | `093832a9ae1a6d4ba59a51d1cf1b0a0d1f6a33e8d8ab44f86c02cc0d7fcb8341` |

**Testes negativos:** permanecem incluídos a recusa QEMU de FD fechado, alteração externa de pathname/socket, backing externo, pidfd de terceiro, PID diferente, pidfd obsoleto, QMP ausente e falha de spawn. Casos de QMP greeting/versão/capabilities maliciosos continuam avaliados na suite QMP offline, não como servidores QEMU genuínos. Nenhum `send-key`, `cont`, OS guest ou instalador foi executado.

**Gates:** `QEMU_FD_BACKING_VERIFIED=false` (inalterado), `productionStorageWritesAuthorized=false`, `q4osNativeInstallationVerified=false`, `sameDiskDualBootVerified=false`, `windowsInPlaceRollbackProven=false`, `releaseEligible=false`, `stable=false`. Nenhuma conclusão de instalação Q4OS, boot Windows/Linux ou rollback deve resultar destas provas.
