# SHARED_CONTRACTS — contratos transacionais dos backends Gaslux

**Consulta:** 2026-11-19. **Referência normativa existente:** [docs/ARCHITECTURE.md](../ARCHITECTURE.md), [schemas/](../../schemas/) e implementação de dev. Este documento é explicativo; mudanças ao esquema ou máquina de estados exigem sincronização e testes de paridade.

## 1. Fronteiras de autoridade

1. Windows WPF/C# escolhe distribuição, disco, tamanho e conta; executa o preflight e obtém catálogo RSA-validado.
2. PowerShell Windows valida de novo e, **após preparar recuperação**, pode executar exclusivamente a operação descrita no plano tipado.
3. Live boot é um handoff de confiança restrita: valida integralmente ISO/plano/estado, identidade física, geometria e Secure Boot antes de qualquer escrita.
4. Backend da distribuição instala o **sistema real** no destino aprovado, sem autonomia para escolher outros discos, formatar a ESP Windows ou sobrescrever bootloaders alheios.
5. Linux instalado publica prova de primeiro arranque; Windows revalida a prova e o próprio arranque. A reversão e a remoção exigem prova independente.

**IMPLEMENTADO:** Installation/InstallationPlanFactory.cs, Installation/InstallationPlanValidator.cs, Installation/InstallationExecutionLedger.cs, Installation/InstallationStateMachine.cs, Scripts/modules/Libertix.InstallationPlan.psm1, Scripts/libertix-storage-preflight.ps1, Scripts/libertix-recovery-guard.ps1, assets/live/libertix-installation-plan.py, assets/live/libertix-installation-state.py, assets/live/libertix-rollback-common.sh. **Não inferir** que estes módulos aceitam automaticamente Pop/Arch/Atomic.

## 2. Artefactos e cadeia criptográfica

- O contrato estável tem release-config.json -> geração de catálogo -> assinatura RSA -> validação no executável -> hash SHA-256/tamanho esperado -> verificação da **identidade interna** da ISO. Dados do disco não obtêm autoridade a partir de um checksum de ficheiro isolado.
- Registar: URI canónica, versão, edição, arquitetura, tamanho exato, SHA-256, origem de confiança/assinatura upstream (incluindo key fingerprint), ISO9660 volume descriptor, kernel/initrd/live payload, identidades e de onde vieram esses valores. **Nunca preencher campos desconhecidos por dedução**.
- Recolher a proveniência oficial por release. Verificar GPG detached quando publicado, cadeia de confiança da chave e identidade do artefacto; não confiar num SHA servido pela mesma CDN comprometível sem prova separada.
- Não utilizar override de filepool de laboratório ou flags de teste em builds distribuídos. Não modificar LIBERTIX_SIGNING_PRIVATE_KEY, chaves firmware ou metadados assinados nesta investigação.
- **IMPLEMENTADO em dev:** PR [#12](https://github.com/LMhdez/gaslux/pull/12) acrescentou contratos de catálogo v2 com capacidades atrás de gating; release-config.json main ainda usa schemaVersion=1, Mint/Zorin apenas. Confirmar estado/branch antes de usar.
- **BLOQUEADO:** ISO incompatível, multi-SquashFS ambígua, identidade os-release errada, tamanho/hash não coincidentes, assinatura inválida, ISO versionada diferente, release desconhecida.

## 3. Preflight Windows e identidade física

Preflight não é uma confirmação de UI; é a demonstração de que cada pré-condição continua válida **imediatamente antes** de escrever.

| Campo | Captura Windows | Revalidação Linux/rollback | Falha obrigatória |
|---|---|---|---|
| Firmware/tabela | BIOS/MBR ou UEFI/GPT efetivos | firmware carregado, disco e partições observados | par inválido, modo alterado, configuração não testada |
| Disco físico | número Windows **mais** identificador persistente, capacidade, setor lógico/físico, assinatura/GUID | identidade por caminhos estáveis e dados físicos, sem assumir /dev/sda | alias ambíguo, série duplicada, capacidade diferente |
| Geometria | start/size em bytes, ordem/overlap, sistema de ficheiros, Windows/WinRE/OEM | offsets originais, tabela GPT CRC/protective MBR ou cadeias MBR/EBR suportadas | qualquer partição alheia mudada |
| Encriptação | BitLocker/Device Encryption, proteção/lock state | antes/depois e recuperação | volume bloqueado ou proteção sem política aprovada |
| Windows boot | BCD, Windows Boot Manager, WinRE, ESP/MBR/PBR/NVRAM | snapshots/hash e arranques reais | ficheiro, entrada ou prioridade não autorizada |
| Espaço | shrink NTFS válido e livre, alinhamento, quatro entradas MBR / lógica | extent autorizado, conteúdo inicial, sistema de ficheiros | layout ambíguo, sobreposição, EBR não auditada |
| Recuperação | local restaurável fora da zona a modificar, baseline e ferramentas | prova de acesso e consistência ao retomar | baseline ausente ou não verificável |

MBR: validar partição ativa, assinatura de disco, códigos de boot MBR/PBR, quatro slots primários e partição estendida; cadeias EBR exigem prova de segurança e recuperação independente; não criar quinta primária. Setor lógico real determina endereço máximo. GPT: preservar protective MBR, GUIDs, cópias da tabela, ESP e Recovery. Nunca converter MBR para GPT ou trocar modo firmware.

## 4. Plano tipado e imutabilidade

**IMPLEMENTADO:** schemas/installation-plan.schema.json, schemas/installation-state.schema.json, Installation/InstallationPlan.cs, Installation/InstallationPlanSerializer.cs, Scripts/modules/Libertix.InstallationPlan.psm1, assets/live/libertix-installation-plan.py. Revalidar portable schema + invariantes semânticas antes de materializar operações.

- Plano identifica transação, distribuição/artefactos, disco, setor e geometria exatos, única extensão própria, capacidade/allocação, account/locale/keyboard/timezone, estratégia de boot, baseline de recuperação e hashes.
- Plano é publicado atomicamente antes da mutação. Só campos de resolução runtime expressamente autorizados por ARCHITECTURE.md podem mudar (identidade observada do staging e fallback de boot UEFI validado). Uma evolução do contrato deve ter migração e validadores equivalentes em C#/PowerShell/Python.
- Handoff entre Windows/Live: ficheiros staged, flush/hash, substituição atómica, cópia de estado durável Windows. Assinatura/autenticação **para novos backends** deve ligar nonce, transação, boot arguments, ISO, identidade de guest, disco, partição e programa autorizado. Não aceitar só texto vindo de COM1 nem marcador autoatribuído.
- Conta, senha e tokens têm ciclo de vida curto e permissão restrita. Não armazenar plaintext em logs ou provas públicas.

## 5. Máquina de estados / ownership / idempotência

**IMPLEMENTADO:** Installation/InstallationExecutionLedger.cs, Installation/InstallationStateMachine.cs, Scripts/modules/Libertix.InstallationState.psm1, assets/live/libertix-installation-state.py, assets/live/libertix-rollback-common.sh. Ordem dos passos é uma interface ABI trans-runtime: não editar num backend isolado.

- Para cada escrita, associar transação, etapa, proprietário, recurso, geometria/identificador antes, pós-condição, compensação e prova após reinício.
- Estado durável é monotónico: pending -> started -> completed ou compensation started/completed conforme schema vigente; não saltar passos nem declarar conclusão por existência de log.
- Retomar após falha começa por revalidar plano, geometria, autoridade e checkpoints. Uma operação repetível só é repetida quando idempotência é demonstrável.
- Estrangeiros nunca são "limpeza": não apagar partições sem owner, instalações anteriores, EFI/Microsoft, entradas firmware não próprias, ficheiros de outros sistemas ou artefactos com transação diferente.
- Disponibilidade de rede/energia é incerta; preparar log e checkpoint em volume persistente antes da etapa arriscada.

## 6. Estratégias de arranque e manutenção

**BIOS/MBR:** preservar MBR/PBR e BCD, percurso GRUB4DOS/GRUB da implementação original quando confirmado. Não assumir free primary slot ou alterar active flag sem recuperação. **UEFI/GPT:** conservar os ficheiros EFI da Microsoft, ESP e sua capacidade livre; criar apenas directórios próprios, validar BootNext/BootOrder e NVRAM com snapshot, garantir arranque Windows por caminho independente e restaurar prioridades após instalação/rollback.

- GRUB, systemd-boot, Limine, rEFInd e shim não são equivalentes. Cada backend declara binários, ficheiros e hooks **versionados** e prova que atualizações de kernel/loader mantêm Linux e Windows acessíveis.
- Secure Boot é uma decisão de firmware da máquina; um shim assinado para Mint/Zorin não autoriza Archiso, Pop ou Atomic. Se operação requer inscrição MOK, trocar DB/KEK/PK, desativar Secure Boot ou dispensar validação, **BLOQUEADO**.
- ISO sem USB: distinguir chainload de EFI validado, GRUB loopback ISO e kernel+initrd diretos; validar descoberta da ISO e possibilidade de encontrar o squashfs após pivot. Não publicar parâmetros não observados numa ISO exata. Falha de primeiro boot deve regressar a Windows sem criar cadeia persistente defeituosa.
- [docs/UEFI_BOOTNEXT_BOOTORDER.md](../UEFI_BOOTNEXT_BOOTORDER.md) é referência para fallback UEFI atual; não duplicar sem confirmar.

## 7. Recuperação e verificação independente

Antes de qualquer escrita: manifestos base, EFI/BCD/WinRE/NVRAM ou MBR/PBR/active flag, geometria, BitLocker, ficheiros witnesses, plano/ledger e caminho de recuperação Windows. Testar leitura dos dados de recuperação e capacidade de restaurar. Após uma falha:

1. Interromper escritores e desmontar volumes próprios; verificar que o dispositivo ainda é exatamente o alvo.
2. Compensar apenas recursos criados pela transação corrente e estados compensáveis, confirmando cada pós-condição.
3. Restaurar boot e geometria original apenas quando a extensão/código correspondem ao baseline autorizado.
4. Arrancar Windows real, medir novamente BCD/WinRE, ESP/EFI, NVRAM ou MBR/PBR, BitLocker e testemunhos de dados.
5. Se qualquer pós-condição não puder ser provada, marcar recuperação incompleta, exigir intervenção humana e **não** reportar sucesso.

Falhas a injetar em VM: hash ISO, certificado, assinatura, perda de rede, limite de espaço, corte de energia, processo morto em cada etapa, UUID errado, disco trocado, ESP parcialmente alterada, BootNext rejeitado, kernel update interrompido, rollback interrompido. Snapshot COW apenas protege o laboratório; não substitui lógica de recuperação instalada no produto.

## 8. Matriz de ensaios / evidências

| Nível | Mínimo verificável | Não demonstra |
|---|---|---|
| N0 — contratos | schema parity, lint, testes unitários, PowerShell, C#, mock de erro | boot ou disco |
| N1 — meio | assinatura/hash/tamanho, identidade ISO, arquivos de boot identificados | live boot |
| N2 — live | QEMU/SeaBIOS ou OVMF com kernel/ISO oficial e transcript confiável | Linux instalado |
| N3 — Linux | instalador **nativo** completo, root+kernel+loader instalado, reboot sem ISO, conta/locale e updates | coexistência Windows |
| N4 — Windows dual boot | Windows 10 BIOS/MBR, 10 UEFI/GPT, 11 UEFI/GPT conforme suporte, disco único/segundo disco, boot dos dois SO | rollback |
| N5 — recuperação | injeção de falhas, desinstalação e restauração completa com Windows real, hashes e geometria | garantia hardware real |
| N6 — release | todas variantes declaradas, Secure Boot específico, kernel update, reboot, review humano, backups físicos autorizados | extrapolação para layouts não testados |

**Testes não destrutivos sugeridos:** ver README do repositório e auto_tests/README.md para invocações atuais de pytest, Ruff, ShellCheck, Pester e build .NET; workflows executam somente no branch/commit em que existem. Não executar qualquer workflow de escrita sem auditar workflow_dispatch, autorização, identidade COW e snapshots. As próprias GitHub Actions podem lançar QEMU **destrutivo apenas sobre imagens VM descartáveis** — fora do âmbito desta PR.

## 9. Revisão / fonte de verdade

Referências verificadas em 2026-11-19: [ARCHITECTURE](../ARCHITECTURE.md), [PR #7](https://github.com/LMhdez/gaslux/pull/7), [PR #12](https://github.com/LMhdez/gaslux/pull/12), [PR #62](https://github.com/LMhdez/gaslux/pull/62), [issue #3](https://github.com/LMhdez/gaslux/issues/3). Revalidar caminhos e sintaxe das ações no branch concreto. Este documento não modifica schemas, catálogo ou permissões.
