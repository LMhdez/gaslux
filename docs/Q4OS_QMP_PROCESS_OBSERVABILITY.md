# Q4OS — supervisão QEMU/QMP sem autorizações

Estado: **experimental / no-writer / draft**. Dependência da PR #266.
O Installer Observer #259 mantém controlo exclusivo sobre a observação do Calamares.
Nenhum clique VNC, Calamares, Windows Setup ou QEMU-system foi executado nesta PR.

## Evidência histórica

- Action #44894608753: QMP socket unavailable após prazo; causa não determinada.
- Action #44895504961: QEMU/OVMF/QMP sobre suportes sintéticos, sem Windows.
- Action #44818428023: primeiro logon Windows comprovado, falha posterior Safety.
- O workflow de disparo único da branch experimental continua sem push e com job if: false.

## Protocolo de supervisão

1. Validar inputs privados antes de iniciar qualquer processo.
2. Abrir QEMU por subprocess.Popen direto e Linux pidfd para identificar o filho.
3. Validar tipo, proprietário e inode do socket; ligar e conferir SO_PEERCRED
   do peer com o PID/UID do processo criado.
4. Exigir QMP greeting, versão, capabilities e query-status running.
5. Passar canal QMP já autenticado e guard ao supervisor DVD original.
6. Preservar no máximo uma única tecla DVD, sem outras tentativas.
7. Comprovar cleanup por pidfd e wait, sem kill a PID de shell.
8. Emitir JSON exclusivamente de campos allowlisted. Nunca incluir logs
   brutos, argumentos, ISO, discos, passwords, NVRAM ou caminhos privados.

## Diagnósticos

| reasonCode | Condição demonstrada |
| --- | --- |
| QEMU_SPAWN_FAILED | Falha de Popen |
| QEMU_EARLY_EXIT | Processo saiu antes de QMP |
| QEMU_QMP_SOCKET_TIMEOUT | Processo ativo, socket indisponível no prazo |
| QEMU_QMP_SOCKET_INVALID | Socket inválido, symlink, owner, inode ou peer incorreto |
| QEMU_QMP_CONNECTION_REFUSED | Ligação recusada com processo ainda ativo |
| QEMU_QMP_HANDSHAKE_FAILED | Greeting, versão ou capabilities inválidos |
| QEMU_QMP_NOT_RUNNING | query-status devolveu estado diferente de running |
| QEMU_PROCESS_CLEANUP_FAILED | Falta de prova do encerramento do processo próprio |
| QEMU_STARTUP_UNCLASSIFIED | Evidência insuficiente para outra categoria |

errorDetailCode é obtido do classificador preexistente de QEMU somente em
early exit. Sem assinatura conhecida, permanece QEMU_EARLY_EXIT_UNCLASSIFIED.
A ausência de socket não prova falha KVM, memória ou dispositivo.

O JSON contém flags de spawn e PID observado (sem divulgar número), exit code,
sinal, estado do socket, handshake, recusa, resultado de cleanup e gates false.

## CI e limites

A CI de diagnóstico usa processos e sockets simulados, Python compileall, Ruff,
pytest, YAML, JSON Schema e Safety fixado. Não executa QEMU-system.
O workflow anterior que inclui QEMU sintético está ignorado nesta branch;
o workflow Windows continua unicamente manual e não foi acionado.
O disparo histórico não foi rearmado.

Riscos Calamares existentes, incluindo installEFIFallback=true, preservação
de Windows ESP, BCD, WinRE, primeiro boot, atualizações e rollback, não são
autorizados nem resolvidos nesta PR.

Gates: productionStorageWritesAuthorized=false;
q4osNativeInstallationVerified=false; sameDiskDualBootVerified=false;
windowsInPlaceRollbackProven=false; releaseEligible=false; stable=false.

GPL-3.0, AI_POLICY.md, revisão humana obrigatória. Generated-by: GPT-6.
