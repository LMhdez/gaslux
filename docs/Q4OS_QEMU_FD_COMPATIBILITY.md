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
