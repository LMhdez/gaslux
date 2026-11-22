# Bazzite 45 native route investigation: pinned official sources

Experimental read-only evidence. This branch is stacked on Bazzite #262 and
does not modify #250, #262, #280, Safety or Observer, Windows or a bootloader.

## Exact upstream byte sources

Workflow bazzite-native-route-readback.yml downloads only five Markdown
sources using immutable commits and compares their Git blob SHA-1 identity
with GitHub API metadata. It emits measured SHA-256 for each document.
The Bazzite docs commit was marked GitHub-verified; the bootc docs
commit was not. A pinned Git blob does not independently attest a live
Anaconda/bootc executable or authorize host/guest activity.

Bazzite docs source:
https://github.com/ublue-os/docs.bazzite.gg/commit/1a9b77a0633443424e9c939cf4bd50718d1c79a5

bootc docs source:
https://github.com/bootc-dev/bootc/commit/0fe7b14f29f1a8e6868462a170b165611992e901

Historical Bazzite 45.20261117.1 ISO signature, OCI signature and embedded
payload readback already exist in Actions #44759529218. They are not rerun
or used as a grant of trust by this source-only job.

## Grounded conclusions

- ISO45: Bazzite documents only automatic partitioning in modern live
  installers; selecting a whole drive is warned as erasing its content.
  It documents a misleading Windows EFI format label. There is no
  demonstrated custom GPT 4-6 route or exact EFI write-set.
- ISO45 automatic Windows dual boot: officially described with pre-shrink
  in Windows, but not demonstrated safe under Gaslux transaction and
  recovery requirements.
- Legacy ISO: Bazzite documents Blivet-GUI manual partitioning. The exact
  legacy ISO42 in the Gaslux historical lab has no independent upstream
  signature and cannot be promoted by signed ISO45 evidence.
- Generic bootc to-disk: its official manual states the entire selected
  device is wiped. Not suitable for Windows-preserving dual boot.
- Generic bootc to-existing-root: upstream states it wipes /boot. Not
  suitable as a conversion of an existing system or Windows partition.
- Generic bootc to-filesystem: can install into externally mounted and
  prepared filesystems and ESP, but its compatibility with the exact
  Bazzite OCI, Btrfs layout, bootloader, updates and dual boot remains
  UNPROVEN. This is the most promising separate research route.

The offline readback returns six classifications but always keeps
installationAuthorized, partitionWriteAuthorized, gptMetadataWriteAuthorized,
windowsEspWriteAuthorized, nvramWriteAuthorized,
secureBootEnrollmentAuthorized and guestCommandChannelAuthorized FALSE.
A valid report exits 2; an altered source/unknown file exits 3.
No action is executed against any guest, QEMU, ISO, disk or NVRAM.

## Next experiment, NOT yet authorized

Ask Safety/Observer to establish independent protected read-only guest
provenance: reviewed bootc executable/version bound to the signed Bazzite
OCI, a disposable isolated QCOW2 with stable physical identity and no
Windows disk, source and destination sector evidence, unique guest
collector channel, restricted methods, bounded one-time transaction, and
immutable post-read measurements. First inspect whether this exact Bazzite
image actually supports bootc install to-filesystem and can target its
own ESP and the intended Btrfs root with no foreign EFI/NVRAM writes.
Do not run installation, Blivet mutators, formatting, bootloader updates
or privileged shell simply to find this out. A separate writer approval,
Windows VM rollback and dual-boot proof would be needed later.

Official references:
https://docs.bazzite.gg/General/Installation_Guide/install-guide/
https://docs.bazzite.gg/General/Installation_Guide/legacy-install/
https://bootc.dev/bootc/man/bootc-install-to-disk.8.html
https://bootc.dev/bootc/man/bootc-install-to-filesystem.8.html
https://bootc.dev/bootc/man/bootc-install-to-existing-root.8.html


## Atualização de evidência — 22/11/2026: OCI/RPM versus deployment

COMPROVADO APENAS NA ORIGEM: a Actions
https://github.com/LMhdez/gaslux/actions/runs/45024613641
revalidou a assinatura Cosign, a atestação GitHub/SLSA, o manifesto OCI por
digest imutável, a configuração e 256 layers/DiffIDs. O pacote real
bootc-0:1.17.1-1.fc45.x86_64 foi identificado na RPM DB da imagem
usr/lib/sysimage/rpm-ostree-base-db/rpmdb.sqlite; o SHA-256 RPM de
/usr/bin/bootc coincide com o ELF medido
f8944e5431de613133aa56bd7ac623dcf223f40ec3745a8c87b9cdcff4956e08.
Artefacto original #14755572085: ZIP SHA-256
3a9ba3d8560918333640addcc6f4e4caa901581ee568227fda9ce4e4acf1ee88.
A presença de uma página de manual bootc-install-to-filesystem não comprova
a operação runtime nem um deployment Atomic.

NOVO CONTRATO DE FRONTEIRA (DENY ONLY): o módulo
auto_tests/bazzite_deployment_provenance_boundary.py valida o JSON original
do artefacto anterior, fixado pelo seu SHA-256
03790bd39a06943d3d9abc6dcd86dfb0c88ca52508e4ee2df9a9ce5bb156a4c9,
e não promove alegações do guest/runner a provas. O workflow
.github/workflows/bazzite-deployment-provenance-readonly.yml descarrega
somente o pequeno artefacto histórico e verifica também a identidade do
run, HEAD, ID e ZIP digest registados pela API GitHub. Não executa QEMU,
bootc, Anaconda, disk writer ou bootloader. Resultado esperado:
SOURCE_ARTIFACT_MATCHED_DEPLOYMENT_UNPROVEN (exit 2, não autorização).
Relatório autoafirmado: BLOCKED_UNAUTHENTICATED_DEPLOYMENT (exit 3).
Esta repetição de bytes não revalida independentemente as assinaturas neste
novo job; herda a prova do run de origem.

BLOQUEADO: não existe testemunho autenticado de instalação nativa
Fedora Atomic, QCOW2 pós-escrita, identidade FD-QEMU/disk GUID, deployment
OSTree, binário instalado, GPT/ESP pós-instalação, BootOrder, Linux boot,
Windows boot, atualização ou rollback. Todos os flags de instalação,
partição, ESP, NVRAM, canal guest, deployment, boot e estabilidade continuam
false. A auditoria Safety Lane 2, comentário
https://github.com/LMhdez/gaslux/pull/320#issuecomment-7080109724,
classifica destino e recuperação como INSUFFICIENT_EVIDENCE.
O próximo passo de execução depende de um controlador independente
Safety/Observer, prova de ownership do QCOW2/FD e um checkpoint de
recuperação; não reinterpretar JSON ou fixtures como prova de deploy.


## BZD-QCOW2-DEPLOYMENT-READBACK-01 — 22/11/2026 UTC

**Inventário operacional verificado, sem imagem instalada:** foram consultados os
artefactos da CI de origem Bazzite #45030530822 e #45024613641
(ambos contêm apenas JSON de OCI/RPM e hashes), Safety BZD-DEST-01
#45030191718/#45030196771 (sem artefacto QCOW2) e Observer QEMU real parado
#45030813901/#45030818339 (pequenos manifestos host-only, sem exportação
de disco instalado, sem guest arrancado). Nenhum contém um QCOW2 autenticamente
associado a instalação Fedora Atomic concluída, e não existe uma transação
identificada com checkpoint, backing chain validado e guest readback
independente. Uma imagem usada no laboratório QEMU host para observar FDs
não é deployment Bazzite.

**Código experimental:** \`auto_tests/bazzite_qcow2_deployment_readback.py\`
contém \`inspect_qcow2_fd(fd)\`, que lê um descritor O_RDONLY **já aberto**
e mede o cabeçalho QCOW2, o inode e o SHA-256 dos bytes armazenados
(arquivo regular, um único hardlink, limite 16 GiB, verificação fstat inicial
e final); não recebe pathname e não abre QEMU, guest, sistemas de ficheiros,
blocos de partição nem backing. Imagens com backing, encriptação, snapshots,
feature incompatível, tamanho fora dos limites ou FD gravável são recusadas.
A leitura do cabeçalho **não** descodifica setores virtuais do QCOW2; a
geometria lógica GPT/ESP/Btrfs permanece por observar. Os testes de estrutura
utilizam apenas ficheiros mínimos de cabeçalho, **sem GPT ou OS**.

\`assess()\` compara medições locais com reivindicações, mas todas estas
últimas são \`CLAIMED\`: não faz delas fonte de confiança externa.
Mesmo no caso coerente, devolve
\`BLOCKED_NO_AUTHENTICATED_DEPLOYMENT_QCOW2\`; não há estado ACCEPT.
As negativas A–J rejeitam ou sinalizam como não provados swaps de QCOW2,
backing, GUID/sector GPT, versões RPM/bootc, OSTree, EFI, BIOS/MBR e ausência
de checkpoint. Não há \`bootc install\`, Anaconda, mount ou escritor.

**Ligação pendente (Integrador 2/Safety):** um contrato partilhado
\`assess_authenticated_destination(...)\`, ainda inexistente, deverá fornecer
prova de origem e propriedade do QCOW2, host FD/process seal/QMP,
backing graph, leitura dos setores virtuais autenticados e GPT primária/
secundária pelo parser canónico, partições e filesystems Btrfs, arquivos OSTree
e bootc/RPM lidos por um canal de bytes fiável, FAT32 ESP/EFI e checkpoint.
Só depois poderá este backend implementar um consumidor de bytes do deployment
ancorado no mesmo QCOW2. Identidade da OCI e RPM é origem estática, não
instalação, boot, manutenção ou rollback.

**Permissões inalteradas:** somente UEFI/GPT, todos os flags de instalação,
partição, canal guest, Linux/Windows boot, dual boot e rollback são \`false\`.
A existência de SHA local, claim JSON ou resultado HOST/FD \`LOCALLY_MEASURED\`
não substitui um controlador autenticado nem autoriza um writer. PR #320
permanece Draft.
