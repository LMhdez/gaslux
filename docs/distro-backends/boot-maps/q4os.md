# Q4OS 6.10 r2 — boot map operacional e exploração visual sem escrita

> **Estado em 20-11-2026:** COMPROVADOS 9 estados e 8 transições em **duas VMs oficiais distintas** com SHA de PNGs e verificação visual independente. Nenhuma instalação, conta persistida, Windows, ESP ou NVRAM do host foi alterada. A extensão não destrutiva Users → Summary decorre separadamente em [Actions #44645487403](https://github.com/LMhdez/gaslux/actions/runs/44645487403).

## 1. Meios e cadeia de confiança

| Campo | Contrato exacto |
| --- | --- |
| Distribuição | Q4OS Andromeda 6.10 r2, x64, Debian 13 Live |
| URL observada no laboratório | `https://downloads.sourceforge.net/project/q4os/stable/q4os-6.10-x64.r2.iso` |
| SHA-256 obrigatório | `1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d` |
| Tamanho | **COMPROVADO no job**: 1 851 392 000 bytes nas duas VMs; SHA exacto verificado antes do boot |
| Autenticidade | Comparação do SHA local com valor fixado no workflow original. **Não é prova de GPG detached upstream**; não autoriza promoção para catálogo |
| Fonte de arranque | [harness fixado em commit `6b6d5521`](https://github.com/LMhdez/gaslux/tree/6b6d5521dbd4c2c26712fb57cb6ae5b29e0c69bb/auto_tests/tools), executado por [workflow novo, duas VMs](https://github.com/LMhdez/gaslux/blob/docs/distro-one-shot-playbooks-20261119/.github/workflows/q4os-ui-repro-2vm.yml) |
| Falhas de integridade | Abortam antes de QEMU; ISO symlink, SHA divergente, múltiplos `vmlinuz-*`, initramfs ausente, dispositivo partilhado ou configuração Calamares inesperada recusados |

A validação de identidade **da ISO ao Linux Live** é feita em separado: [`gaslux_q4os_calamares_probe.sh`](https://github.com/LMhdez/gaslux/blob/6b6d5521dbd4c2c26712fb57cb6ae5b29e0c69bb/auto_tests/tools/gaslux_q4os_calamares_probe.sh) extrai módulos efectivos do SquashFS da ISO autenticada, e [`gaslux_q4os_calamares_policy.py`](https://github.com/LMhdez/gaslux/blob/6b6d5521dbd4c2c26712fb57cb6ae5b29e0c69bb/assets/live/gaslux_q4os_calamares_policy.py) verifica a versão `etc/q4os_version=6.10-deb13u1`, `ID=debian`, `VERSION_ID=13` e a sequência de Calamares. **COMPROVADO:** o pacote real incluído no SquashFS é `calamares 1:3.3.14-deb13.1.3` (`Status: install ok installed`), em `calamares-package-version.txt` dos dois artefactos. A sequência e os SHA dos módulos podem ser auditados nos ficheiros `calamares-inspect` da mesma ISO; nunca inferir a versão apenas da documentação upstream.

## 2. Windows → QEMU/OVMF → Q4OS Live (o que está testado e o que falta)

**Experimentado apenas em QEMU/OVMF:** a ISO é aberta em leitura, via `mount -o loop,ro,nosuid,nodev,noexec`, e é seleccionada exactamente uma entrada `live/vmlinuz-<versão>` com `live/initrd.img-<mesma versão>`. A versão de kernel só é fixada após exame da ISO. O laboratório produz um `BOOTX64.EFI` GRUB independente com `grub-mkstandalone --format=x86_64-efi`, alojado numa ESP **sintética**, dentro de uma imagem GPT descartável. O firmware tem OVMF CODE só de leitura e VARS de trabalho privada. Existe uma única ESP `GASLUX-LAB-ESP` na imagem criada pelo runner; nenhuma partição Windows é anexada.

A ISO oficial é exposta ao convidado como **virtio-blk read-only**, não CD-ROM: o projecto observou dificuldades de enumeração GRUB de CD-ROM em OVMF hosted, e este adaptador usa `search --no-floppy --file --set=source` para encontrar o kernel. A secção GRUB usa `linux ($source)/live/vmlinuz-<sufixo>` e `initrd ($source)/live/initrd.img-<sufixo>`. Os argumentos **observados no código do lab** são:

```text
boot=live components console=tty0 console=ttyS0,115200n8 systemd.log_target=console systemd.log_level=info systemd.unit=graphical.target systemd.setenv=KWIN_COMPOSE=N systemd.wants=serial-getty@ttyS0.service
```

Estes são argumentos da **experiência da ISO Q4OS 6.10 em QEMU**, não uma prova de arranque sem USB a partir do Windows. Um instalador Gaslux nativo terá de demonstrar leitura do staging Windows/NTFS, identificação de disco/offsets, firmware Windows, variáveis NVRAM e recuperação após BootNext falhado. **BIOS/MBR e Secure Boot real nesta ISO ainda estão PENDENTES de ensaio independente**, mesmo que a distribuição upstream os suporte noutros contextos.

## 3. Calamares upstream extraído da ISO

**IMPLEMENTADO no código do lab:** o auditor exige, na configuração efectiva da ISO autenticada:

- `/etc/calamares/settings.conf` e módulos `partition`, `mount`, `unpackfs`, `fstab`, `grubcfg`, `bootloader`, `users`, `packages`, `displaymanager`;
- ordem de instalação que começa em `partition → mount → unpackfs`, passando por `q4oshook2`, GRUB, `q4oshook3`, apt, initramfs, `q4oshook5` e `umount`;
- fonte SquashFS `/run/live/medium/live/filesystem.squashfs`, root `ext4`, ESP `/boot/efi`, `grubInstall=grub-install`, gestor de pacotes `apt`;
- `installEFIFallback=true` na configuração upstream, **BLOQUEADO para qualquer ESP Windows partilhada**. Escrever `EFI/BOOT/BOOTX64.EFI` pode comprometer o fallback Windows mesmo se `EFI/Microsoft/Boot/bootmgfw.efi` ficar intacto.

**Limite:** inspeccionar YAML e módulos do Calamares não executa jobs de instalação; não inferir sucesso unattended. Para explorar a interface, o ensaio selecciona uma proposta visual num QCOW2 exclusivamente sintético com checkpoint; não clica Install e compara GPT/ESP antes/depois. Os detalhes dos estados e localizadores estão em [q4os.json](../ui-maps/q4os.json).

## 4. Máquina de ecrãs e gates

A base de exploração usa resolução **1280×800** fixa, com regiões RGB SHA-256 **exactas** para Welcome, Location, Keyboard, Software, Partitions e Users, implementadas em [`gaslux_q4os_vnc_visual_gate.py`](https://github.com/LMhdez/gaslux/blob/6b6d5521dbd4c2c26712fb57cb6ae5b29e0c69bb/auto_tests/tools/gaslux_q4os_vnc_visual_gate.py). O zoom/escala reportados pela API de acessibilidade Qt e objectName dos widgets **não foram observados**. O mapa usa `null`, não inventa IDs. Cada alteração de página exige **ambos**: ROI do ecrã seguinte igual ao hash pré-verificado e ROI central diferente do ecrã anterior; mover o relógio da taskbar não satisfaz a condição.

Transições **COMPROVADAS independentemente em duas VMs**, cada uma com screenshot anterior/posterior e SHA de origem: `Desktop → Welcome → Location → Keyboard → Software → Software/Desktop selected → Partitions → Partitions synthetic proposal selected → Users (em branco)`. As coordenadas de clique provêm do **código de laboratório fixado** e as transições passaram os gates visual/ROI em ambas as VMs. As caixas adicionais de controlos só são descritas como verdadeiros bounding boxes quando visíveis nos PNGs; as caixas RGB de guarda não são automaticamente dimensões Qt do widget.

**Limite de paragem obrigatório:** depois do ecrã Users, **não introduzir utilizador/password, não premir Next para Summary, Done, Install ou confirmar erase-disk**. A selecção de rádio Erase disk é apenas um **preview**, executada exclusivamente na imagem sintetizada e controlada pela guard `gaslux_q4os_native_cow_view_guard.py` — nunca num disco com Windows. Não é uma autorização de escrita nem um método recomendado de particionamento de produção.

## 5. Reprodutibilidade e evidência por VM

- [Actions #44640026059](https://github.com/LMhdez/gaslux/actions/runs/44640026059) — execução inicial de duas VMs de Q4OS com matrix `replica: [1,2]`; **SUCCESS** nas duas réplicas, cada uma com 9 PNGs de estado, 8 transições visualmente validadas e um manifesto SHA-256.
- O workflow descarrega e confirma SHA/tamanho *antes* da VM, extrai Calamares sem executar instalação e produz `native-calamares-audit.json`, `calamares-package-version.txt`, `ui-screenshots-report.json`, `evidence.sha256`, PNGs originais e OCR por estado.
- Testes de estrutura e evidência: [`test_q4os_ui_map_contract.py`](https://github.com/LMhdez/gaslux/blob/docs/distro-one-shot-playbooks-20261119/auto_tests/tests/test_q4os_ui_map_contract.py) com [JSON Schema do mapa](https://github.com/LMhdez/gaslux/blob/docs/distro-one-shot-playbooks-20261119/schemas/distro-ui-map.schema.json) e [do manifesto](https://github.com/LMhdez/gaslux/blob/docs/distro-one-shot-playbooks-20261119/schemas/distro-ui-evidence.schema.json).

**COMPROVADO para esta etapa documental (não de instalação):** duas VMs em runners distintos, cada uma com 9 estados e 8 transições verificadas, originais PNG e SHA por estado, auditoria Calamares da ISO e artefactos ligados no mapa JSON. Verificação separada de todos os PNGs no segundo workflow: Testes de tempo decorrido por clique, IDs Qt, Summary, contas e finalização nativa permanecem **PENDENTES** até autorização específica de uma nova exploração segura que não execute `Install`.

## 6. Falhas previstas e recuperação do laboratório

| Falha | Reacção |
| --- | --- |
| ISO hash, origem ou versionamento divergente | STOP pré-VM, nenhuma instalação ou promoção |
| Múltiplo kernel, initrd ausente ou ecrã inesperado | STOP, guardar captura/serial, descartar COW |
| Screenshot ROI falha ou não muda entre dois estados | STOP, não clicar novamente cegamente; rever imagem e versão |
| QEMU encerra por timeout de 720 s; VNC tem limite por comando de 20 s | Registar limites *configurados*, sem inventar durações observadas; cancelar/descartar guest |
| GPT/ESP do backing sintético mudou | Falha da guard, descartar COW; **não** tratar snapshot como rollback Windows |
| Calamares oferece formatação da ESP ou qualquer partição Windows | BLOQUEADO antes de qualquer escrita; impedir escolha em produção |
| Ausência de API/accessibility IDs | `null` no mapa; investigar Qt Accessibility/AT-SPI de modo passivo e read-only numa VM futura |

As alterações de produção continuam proibidas. A evidência de arranque Live e de navegação não é prova de instalação, primeiro arranque instalado, actualizações ou recuperação in-place.

## 7. Evidência experimental nova e verificável — 20-11-2026

| Requisito | Prova real |
| --- | --- |
| Fonte oficial autenticada pelo hash fixado | [Actions #44641233701](https://github.com/LMhdez/gaslux/actions/runs/44641233701), SHA-256 `1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d`, tamanho exato **1 851 392 000 bytes** nos dois runners |
| Calamares realmente presente na ISO | `Package: calamares`, `Version: 1:3.3.14-deb13.1.3` nas duas extracções `var/lib/dpkg/status` e nos ficheiros de configuração nativos |
| VM 1 QEMU/OVMF | [Capturas, OCR, serial, módulos, hashes e manifesto #14587306682](https://github.com/LMhdez/gaslux/actions/runs/44641233701/artifacts/14587306682) — 9 estados, 8 transições |
| VM 2 QEMU/OVMF | [Capturas, OCR, serial, módulos, hashes e manifesto #14586773677](https://github.com/LMhdez/gaslux/actions/runs/44641233701/artifacts/14586773677) — 9 estados, 8 transições |
| Validação independente dos dois conjuntos | [Actions #44643805955](https://github.com/LMhdez/gaslux/actions/runs/44643805955) **SUCCESS**, [artefacto #14587637863](https://github.com/LMhdez/gaslux/actions/runs/44643805955/artifacts/14587637863); valida SHA de cada PNG original, recarrega os gates RGB por ecrã e confirma o par de VMs |
| Bounding boxes OCR | O artefacto independente contém `two-vm-ocr-control-bboxes.json` com **449 palavras no primeiro conjunto e 457 no segundo**, cada uma com caixa e confiança OCR, ligadas ao hash do screenshot. São *OCR words*, **não** os `objectName` Qt |
| Compatibilidade da UI | **1280×800** nas duas VMs; escala do desktop e object IDs Qt/AT-SPI **não medidos** (`null`) |
| Paragem segura | `calamares-users-unfilled`, sem introdução de conta ou execução de jobs de instalação; estudo de `Summary` pertence a um ensaio separado |

**Texto observado no Welcome:** a VM indica que não satisfaz alguns requisitos recomendados e que não está ligada à Internet; apesar disso, a interface avança por Welcome, Location, Keyboard, Software, Partitions e Users. Isto **não** autoriza uma instalação.

**Campos efectivamente vistos no ecrã Users:** nome completo, nome de login, hostname, palavra-passe, repetição de palavra-passe, login automático e reutilização de palavra-passe de administrador. O [mapa JSON](../ui-maps/q4os.json) identifica o estado e associa as capturas reais; a detecção pelo OCR não garante identificação de `QObject::objectName` nem API unattended.

**Não reivindicado:** passagem de Users para Summary na primeira experiência, qualquer operação destrutiva Calamares, instalação Linux, dual boot Windows/Q4OS, actualização de GRUB/kernel, rollback Windows ou estabilidade.
