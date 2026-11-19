# Q4OS 6.10 r2 — boot map operacional e exploração visual sem escrita

> **Estado em 19-11-2026:** EXPERIMENTO EM EXECUÇÃO. A existência de código não é uma prova de transição; o resultado por VM e os hashes PNG são publicados em [q4os-manifest.json](../evidence/q4os-manifest.json) só após o job passar. Nenhuma escrita de instalação, conta, Windows, ESP ou NVRAM do host é autorizada.

## 1. Meios e cadeia de confiança

| Campo | Contrato exacto |
| --- | --- |
| Distribuição | Q4OS Andromeda 6.10 r2, x64, Debian 13 Live |
| URL observada no laboratório | \`https://downloads.sourceforge.net/project/q4os/stable/q4os-6.10-x64.r2.iso\` |
| SHA-256 obrigatório | \`1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d\` |
| Tamanho | **PENDENTE de medição pelo novo job**; o workflow exige 1,5 GB < tamanho < 3 GB, além do hash exacto |
| Autenticidade | Comparação do SHA local com valor fixado no workflow original. **Não é prova de GPG detached upstream**; não autoriza promoção para catálogo |
| Fonte de arranque | [harness fixado em commit \`6b6d5521\`](https://github.com/LMhdez/gaslux/tree/6b6d5521dbd4c2c26712fb57cb6ae5b29e0c69bb/auto_tests/tools), executado por [workflow novo, duas VMs](https://github.com/LMhdez/gaslux/blob/docs/distro-one-shot-playbooks-20261119/.github/workflows/q4os-ui-repro-2vm.yml) |
| Falhas de integridade | Abortam antes de QEMU; ISO symlink, SHA divergente, múltiplos \`vmlinuz-*\`, initramfs ausente, dispositivo partilhado ou configuração Calamares inesperada recusados |

A validação de identidade **da ISO ao Linux Live** é feita em separado: [\`gaslux_q4os_calamares_probe.sh\`](https://github.com/LMhdez/gaslux/blob/6b6d5521dbd4c2c26712fb57cb6ae5b29e0c69bb/auto_tests/tools/gaslux_q4os_calamares_probe.sh) extrai módulos efectivos do SquashFS da ISO autenticada, e [\`gaslux_q4os_calamares_policy.py\`](https://github.com/LMhdez/gaslux/blob/6b6d5521dbd4c2c26712fb57cb6ae5b29e0c69bb/assets/live/gaslux_q4os_calamares_policy.py) verifica a versão \`etc/q4os_version=6.10-deb13u1\`, \`ID=debian\`, \`VERSION_ID=13\` e a sequência de Calamares. A versão exacta do **pacote binário** Calamares deve constar de \`calamares-package-version.txt\` após o novo ensaio; não a presumir.

## 2. Windows → QEMU/OVMF → Q4OS Live (o que está testado e o que falta)

**Experimentado apenas em QEMU/OVMF:** a ISO é aberta em leitura, via \`mount -o loop,ro,nosuid,nodev,noexec\`, e é seleccionada exactamente uma entrada \`live/vmlinuz-<versão>\` com \`live/initrd.img-<mesma versão>\`. A versão de kernel só é fixada após exame da ISO. O laboratório produz um \`BOOTX64.EFI\` GRUB independente com \`grub-mkstandalone --format=x86_64-efi\`, alojado numa ESP **sintética**, dentro de uma imagem GPT descartável. O firmware tem OVMF CODE só de leitura e VARS de trabalho privada. Existe uma única ESP \`GASLUX-LAB-ESP\` na imagem criada pelo runner; nenhuma partição Windows é anexada.

A ISO oficial é exposta ao convidado como **virtio-blk read-only**, não CD-ROM: o projecto observou dificuldades de enumeração GRUB de CD-ROM em OVMF hosted, e este adaptador usa \`search --no-floppy --file --set=source\` para encontrar o kernel. A secção GRUB usa \`linux (\$source)/live/vmlinuz-<sufixo>\` e \`initrd (\$source)/live/initrd.img-<sufixo>\`. Os argumentos **observados no código do lab** são:

\`\`\`text
boot=live components console=tty0 console=ttyS0,115200n8 systemd.log_target=console systemd.log_level=info systemd.unit=graphical.target systemd.setenv=KWIN_COMPOSE=N systemd.wants=serial-getty@ttyS0.service
\`\`\`

Estes são argumentos da **experiência da ISO Q4OS 6.10 em QEMU**, não uma prova de arranque sem USB a partir do Windows. Um instalador Gaslux nativo terá de demonstrar leitura do staging Windows/NTFS, identificação de disco/offsets, firmware Windows, variáveis NVRAM e recuperação após BootNext falhado. **BIOS/MBR e Secure Boot real nesta ISO ainda estão PENDENTES de ensaio independente**, mesmo que a distribuição upstream os suporte noutros contextos.

## 3. Calamares upstream extraído da ISO

**IMPLEMENTADO no código do lab:** o auditor exige, na configuração efectiva da ISO autenticada:

- \`/etc/calamares/settings.conf\` e módulos \`partition\`, \`mount\`, \`unpackfs\`, \`fstab\`, \`grubcfg\`, \`bootloader\`, \`users\`, \`packages\`, \`displaymanager\`;
- ordem de instalação que começa em \`partition → mount → unpackfs\`, passando por \`q4oshook2\`, GRUB, \`q4oshook3\`, apt, initramfs, \`q4oshook5\` e \`umount\`;
- fonte SquashFS \`/run/live/medium/live/filesystem.squashfs\`, root \`ext4\`, ESP \`/boot/efi\`, \`grubInstall=grub-install\`, gestor de pacotes \`apt\`;
- \`installEFIFallback=true\` na configuração upstream, **BLOQUEADO para qualquer ESP Windows partilhada**. Escrever \`EFI/BOOT/BOOTX64.EFI\` pode comprometer o fallback Windows mesmo se \`EFI/Microsoft/Boot/bootmgfw.efi\` ficar intacto.

**Limite:** inspeccionar YAML e módulos do Calamares não executa jobs de instalação; não inferir sucesso unattended. Para explorar a interface, o ensaio selecciona uma proposta visual num QCOW2 exclusivamente sintético com checkpoint; não clica Install e compara GPT/ESP antes/depois. Os detalhes dos estados e localizadores estão em [q4os.json](../ui-maps/q4os.json).

## 4. Máquina de ecrãs e gates

A base de exploração usa resolução **1280×800** fixa, com regiões RGB SHA-256 **exactas** para Welcome, Location, Keyboard, Software, Partitions e Users, implementadas em [\`gaslux_q4os_vnc_visual_gate.py\`](https://github.com/LMhdez/gaslux/blob/6b6d5521dbd4c2c26712fb57cb6ae5b29e0c69bb/auto_tests/tools/gaslux_q4os_vnc_visual_gate.py). O zoom/escala reportados pela API de acessibilidade Qt e objectName dos widgets **não foram observados**. O mapa usa \`null\`, não inventa IDs. Cada alteração de página exige **ambos**: ROI do ecrã seguinte igual ao hash pré-verificado e ROI central diferente do ecrã anterior; mover o relógio da taskbar não satisfaz a condição.

Transições planeadas, sempre condicionadas por screenshot SHA de origem: \`Desktop → Welcome → Location → Keyboard → Software → Software/Desktop selected → Partitions → Partitions synthetic proposal selected → Users (em branco)\`. As coordenadas e caixas do mapa são provenientes do **código fixado do laboratório** e só se tornam transições **COMPROVADAS** quando as duas VMs devolverem PNG original, SHA-256, gate visual, relatório JSON e artefactos por job.

**Limite de paragem obrigatório:** depois do ecrã Users, **não introduzir utilizador/password, não premir Next para Summary, Done, Install ou confirmar erase-disk**. A selecção de rádio Erase disk é apenas um **preview**, executada exclusivamente na imagem sintetizada e controlada pela guard \`gaslux_q4os_native_cow_view_guard.py\` — nunca num disco com Windows. Não é uma autorização de escrita nem um método recomendado de particionamento de produção.

## 5. Reprodutibilidade e evidência por VM

- [Actions #44640026059](https://github.com/LMhdez/gaslux/actions/runs/44640026059) — execução inicial de duas VMs de Q4OS com matrix \`replica: [1,2]\`; consultar o resultado por job, não inferir sucesso de workflow iniciado.
- O workflow descarrega e confirma SHA/tamanho *antes* da VM, extrai Calamares sem executar instalação e produz \`native-calamares-audit.json\`, \`calamares-package-version.txt\`, \`ui-screenshots-report.json\`, \`evidence.sha256\`, PNGs originais e OCR por estado.
- Testes de estrutura e evidência: [\`test_q4os_ui_map_contract.py\`](https://github.com/LMhdez/gaslux/blob/docs/distro-one-shot-playbooks-20261119/auto_tests/tests/test_q4os_ui_map_contract.py) com [JSON Schema do mapa](https://github.com/LMhdez/gaslux/blob/docs/distro-one-shot-playbooks-20261119/schemas/distro-ui-map.schema.json) e [do manifesto](https://github.com/LMhdez/gaslux/blob/docs/distro-one-shot-playbooks-20261119/schemas/distro-ui-evidence.schema.json).

**Critério de sucesso desta missão documental, não de instalação:** duas VMs em runners distintos, cada uma com 9 estados e 8 transições verificadas, originais PNG e SHA por estado, auditoria Calamares da ISO, artefactos e mapa JSON que não se declara COMPROVADO antes de ambos. Testes de tempo decorrido por clique, IDs Qt, Summary, contas e finalização nativa permanecem **PENDENTES** até autorização específica de uma nova exploração segura que não execute \`Install\`.

## 6. Falhas previstas e recuperação do laboratório

| Falha | Reacção |
| --- | --- |
| ISO hash, origem ou versionamento divergente | STOP pré-VM, nenhuma instalação ou promoção |
| Múltiplo kernel, initrd ausente ou ecrã inesperado | STOP, guardar captura/serial, descartar COW |
| Screenshot ROI falha ou não muda entre dois estados | STOP, não clicar novamente cegamente; rever imagem e versão |
| QEMU encerra por timeout de 720 s; VNC tem limite por comando de 20 s | Registar limites *configurados*, sem inventar durações observadas; cancelar/descartar guest |
| GPT/ESP do backing sintético mudou | Falha da guard, descartar COW; **não** tratar snapshot como rollback Windows |
| Calamares oferece formatação da ESP ou qualquer partição Windows | BLOQUEADO antes de qualquer escrita; impedir escolha em produção |
| Ausência de API/accessibility IDs | \`null\` no mapa; investigar Qt Accessibility/AT-SPI de modo passivo e read-only numa VM futura |

As alterações de produção continuam proibidas. A evidência de arranque Live e de navegação não é prova de instalação, primeiro arranque instalado, actualizações ou recuperação in-place.
