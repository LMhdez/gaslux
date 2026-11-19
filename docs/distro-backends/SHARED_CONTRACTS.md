# Contratos partilhados — Gaslux

> Revisão documental: 2026-11-19. Autoridade: [ARCHITECTURE.md](https://github.com/LMhdez/gaslux/blob/dev/docs/ARCHITECTURE.md), [AGENTS.md](https://github.com/LMhdez/gaslux/blob/dev/AGENTS.md), [AI_POLICY.md](https://github.com/LMhdez/gaslux/blob/dev/AI_POLICY.md). O presente documento especifica critérios para implementação; não certifica implementações ou testes ausentes.

## Semântica de evidência
- **DOCUMENTADO**: orientação de fonte primária indicada por URL e, quando aplicável, versão.
- **IMPLEMENTADO**: código identificado por caminho/ref; sem implicar execução correcta.
- **COMPROVADO**: resultado real, commit exacto, execução Actions e artefacto verificável; indicar especificamente o que foi provado.
- **PENDENTE**: falta prova ou investigação; nunca preencher parâmetros, hashes ou comandos por conjectura.
- **BLOQUEADO**: preflight deve negar antes de qualquer modificação.
Um CI verde de fixture não é prova de instalação nem de Windows recuperado.

## 1. Preflight e fronteira de autorização
[IMPLEMENTADO — arquitectura] Windows WPF/C# e PowerShell produzem plano; o Linux revalida-o. Validar modo firmware real, tabela real, identidade física (serial/WWN/GPT disk GUID ou assinatura MBR, sempre cruzados), tamanho e sector lógico/físico, geometria em bytes, offsets de todas as partições, tipo e sistema de ficheiros, espaço reservado e shrink NTFS efectivamente suportado. Em vários discos, seleccionar por identidade estável e negar ambiguidades. Capturar Windows Boot Manager, BCD, WinRE, ESP, Recovery/OEM, BitLocker/Device Encryption, estado de hibernação, partição activa BIOS, NVRAM BootOrder/BootNext UEFI, política Secure Boot e chaves de confiança sem alterá-las. Não inferir permissão de escrita do simples facto de uma partição estar vazia.

## 2. Integridade e cadeia de confiança
[IMPLEMENTADO — arquitectura] O catálogo e releases são assinados; resolver uma distribuição por versão exata, tamanho exacto, SHA-256 validado, identidade interna e capacidades permitidas. Para ISO e handoff, ligar todos os artefactos ao transaction ID, hash e disco autorizado. Não substituir uma assinatura upstream por um SHA publicado numa PR. Se a cadeia da assinatura upstream não foi verificada, registar PENDENTE. Sem override da assinatura em produção. Assinar o plano / autenticar o handoff conforme o protocolo que o projecto venha a definir e testar; não declarar que qualquer checksum isolado constitui autenticação.

## 3. Plano tipado, máquina de estados e ownership
[IMPLEMENTADO — arquitectura] [InstallationPlanFactory](https://github.com/LMhdez/gaslux/blob/dev/Installation/InstallationPlanFactory.cs) é a referência nominal do contrato Windows (confirmar localização na revisão). [InstallationExecutionLedger](https://github.com/LMhdez/gaslux/blob/dev/Installation/InstallationExecutionLedger.cs), `Installation/InstallationStateMachine.cs`, `Scripts/modules/Libertix.InstallationState.psm1` e `assets/live/libertix-installation-state.py` mantêm a ordem de transições. O schema em `schemas/` é a autoridade para documentos persistidos. Nenhuma etapa pode ser saltada para declarar sucesso. Revalidar antes/depois de cada escrita e após reboot. Gravar checkpoint durável em duas fronteiras de confiança apropriadas; publicar atomicamente, fazer flush e conferir hash. A posse de uma partição não se infere de label, /dev/sdX ou letra Windows: exige ligação à identidade e geometria fixadas no plano e ao evento de criação transaccional.

## 4. Escritas e rollback
[BLOQUEADO sem prova] Mutação apenas de intervalos autorizados, sobre VM descartável expressamente autorizada, com snapshot/backing imutável, recuperação armada e limites definidos. Proibir apagar/mover/formatar Windows, OEM, Recovery, ESP ou artefactos alheios. Em BIOS/MBR validar os quatro slots, extensão/EBR, assinatura e sector real; não reescrever cadeia EBR sem prova. Em UEFI/GPT proteger ESP existente e Windows EFI, partições GPT reservadas, GUIDs, BootOrder e BootNext; nunca assumir que BootNext reverte sozinho. Verificar compensação de cada etapa completada e comparar geometria, dados/boot críticos, Windows arranca, WinRE/BCD e estado de encriptação com baseline. Remover apenas artefactos cuja ownership seja demonstrada. Falha ou divergência implica estado NÃO RECUPERADO, nunca sucesso baseado em log.

## 5. Boot e handoff
[IMPLEMENTADO — arquitectura] Windows prepara staging e próximo boot; ambiente Live verifica plano e hardware antes de instalar; sistema instalado produz evidência ligada ao plano; Windows valida o regresso. O firmware adapter BIOS e o UEFI têm responsabilidades diferentes; não compartilhar comandos de instalação de bootloader entre distribuições por analogia. Uma estratégia de loopback ISO só é autorizável depois de validar módulos do bootloader, drivers do initramfs, descoberta da ISO e disponibilidade do sistema de ficheiros em teste real da versão exacta. Secure Boot desligado não valida assinatura de cadeia final; Secure Boot ligado requer autoridade aceite e ausência de enrollment manual.

## 6. Falhas obrigatórias
Testar: hash/assinatura falsa, identidade ISO trocada, ISO truncada, perda de rede, falta de espaço, interrupção em cada fronteira, SIGKILL/power-cut, disco permutado ou UUID divergente, GPT alterada, EBR ambíguo, BitLocker activo, NVRAM sem capacidade, EFI ocupada, falha de pacote/bootloader, alteração de kernel e energia cortada durante update. Cada falha tem de terminar sem escrita ou com rollback comprovado.

## 7. Níveis de teste, sem equivalências indevidas
1. Contratos estáticos/fixtures/lint (não escrevem discos).
2. Inspecção de ISO assinada e Live boot (não é instalação).
3. Instalação nativa no disco VM identificado e primeiro arranque sem ISO.
4. Windows real + Linux instalado no mesmo disco/segundo disco, ambos a arrancar.
5. Actualização de kernel e loader, arranque dos dois sistemas.
6. Desinstalação e rollback após falhas, com provas de Windows, WinRE, BCD e geometria.
7. Hardware físico apenas mediante autorização, backups e restauro comprovado.
Prova de execução = commit + workflow/run + artefactos de guest + hashes + relatório de verificações independente. A existência de PR não satisfaz nenhum nível.

## 8. CI e documentação de revisão
[DOCUMENTADO — CONTRIBUTING] Validadores candidatos: `dotnet test`, testes Pester em `PowerShell.Tests/`, `pytest`, `ruff check`, `ruff format --check`, ShellCheck e compilação WPF em runner Windows. Executar os comandos definidos nos workflows do HEAD; não presumir que a máquina local contém PowerShell/.NET/QEMU. Não correr testes que possam escrever disco nesta missão. A integração de CI tem de preservar regressões Mint/Zorin e bloquear catálogo estável para backends experimentais.

## 9. Plano de evidência por transição
| Transição | Evidência exigida | Recuperação se falhar |
|---|---|---|
| Preflight → download | identidade hardware, encriptação, WinRE/BCD e snapshot de geometria | nenhuma escrita permitida |
| Download → staging | catálogo assinado, ISO hash/tamanho, identidade interna | descartar só download possuído |
| Staging → boot Live | intervalos possuídos, estado/boot anterior e handoff autenticado | restaurar estado firmware/BCD e remover staging possuído |
| Live → target | GUID/offset/UUID verificados e checkpoint anterior | remover apenas target possuído e validar Windows |
| Target → bootloader | Windows EFI/BCD intactos, backup transaccional e hash | restaurar exclusivamente alterações possuídas, testar Windows |
| Bootloader → first boot | boot autónomo de Linux instalado, kernel/root/account | rollback se falhar, sem chamar Live boot de sucesso |
| First boot → Windows | Windows real com WinRE/BCD/ESP preservados | reactivar recuperação e estado incompleto |
| Update/uninstall → done | arranques de ambos pós-update ou Windows pós-removal; geometria comparada | NÃO RECUPERADO sem provas finais |

## 10. Regras para executores one-shot
Ao primeiro dado contraditório, STOP antes de escrita; indicar campo, valor esperado, valor real, fase e artefacto de prova. Cada backend deve fornecer adapters específicos para verificação da ISO, handoff, instalação nativa, configuração, bootloader, actualizações, first boot, remoção. Não alterar `release-config.json`, `schemas/`, `Installation/`, `Scripts/`, `assets/live/` numa PR documental. Antes de qualquer PR funcional, confirmar HEAD/PRs dependentes e resultados reais mais recentes. A revisão humana continua obrigatória.
