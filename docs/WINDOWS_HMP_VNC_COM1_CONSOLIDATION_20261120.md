# Windows QEMU: consolidação experimental de HMP, COM1 e RFB

Data: 20-11-2026. **Laboratório apenas; não promove nenhum backend a estável.**

## Proveniência

- PR de destino: https://github.com/LMhdez/gaslux/pull/217 (COM1, HMP, detecção de repetição de DVD, primeiro arranque condicionado)
- PR de origem: https://github.com/LMhdez/gaslux/pull/216 (RFB Unix privado, captura HMP de framebuffer, regras de propriedade)
- SHA de origem de #216: `3718b8a7951f7e9e7318cd5b7f9d89d5e8c5250f`
- A #216 tinha já incorporado as correções de fragmentação HMP da #217. O código RFB é agora trazido para a #217 sem substituir os controlos COM1/one-shot.

## Alterações isoladas

1. `auto_tests/tools/windows_x64_tcg_firstboot.py`: transportes distintos HMP e RFB, validação estrita do socket UNIX e do diretório 0700 no runner GitHub, handshake RFB 3.8 local, exatamente um par Return down/up, screendumps HMP opcionais em diretório próprio, flags `--vnc-dvd-enter` e `--diagnostic-screens`.
2. O transporte RFB exige KVM descartável, a ISO Microsoft original e proíbe simultaneamente as experiências `--one-shot-install-only`, `--two-stage-install-only`, `--derived-no-prompt`, `--boot-probe-only` e `--fixture-only`. Sem flag, permanece o comportamento anterior HMP.
3. `auto_tests/test_windows_x64_iso_boot_key.py`: testes importados da #216 para propriedade de sockets, negociação RFB e emissão de exatamente um Return; testes adicionais de rejeição CLI, transporte inválido e captura HMP não autorizada.
4. `.github/workflows/windows-x64-ovmf-usb-input-smoke.yml`: teste QEMU/KVM OVMF com GRUB sintético para distinguir ACK HMP de input efetivo; sem Windows e sem disco-alvo. Substitui o teste HMP antigo reconhecidamente inconclusivo.

## Segurança e âmbito das provas

Este laboratório opera apenas em runner GitHub-hosted e com ficheiros QCOW2 descartáveis. Não é executado por `main` ou pelo assistente Windows de produção. Um GRUB sintético que recebe Return **não** demonstra que o Windows Setup ou o Linux arrancaram. Os checks COM1 analisam serial e scripts; não provam, isoladamente, instalação, primeiro arranque do Windows, dual boot, WinRE/BCD recuperados, actualizações nem rollback.

Não ativar catálogo estável com base nesta alteração. Antes de encerrar a #216 ou eliminar a sua branch, confirmar CI do HEAD consolidado, transferir eventuais diferenças úteis ainda não contempladas, preservar a história Git e confirmar as dependências de PRs abertas.

Generated-by: GPT-6
