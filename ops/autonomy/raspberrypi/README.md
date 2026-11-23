# GASLUX — agendador de recuperação no Raspberry Pi

**Estado:** proposta na [PR #389](https://github.com/LMhdez/gaslux/pull/389). **Não está instalado no Raspberry Pi, não está ativo e exige parecer independente GASLUX-SAFETY.**

O GitHub documenta que eventos `schedule` podem atrasar ou perder-se. Esta solução usa o relógio local do **Raspberry Pi** via `systemd --user`, sem Cloudflare, conta externa, novo workflow GitHub ou alojamento novo.

## Âmbito estrito
- Cada 15 minutos o timer executa um programa Python 3 da biblioteca padrão.
- Consulta `GET /repos/LMhdez/gaslux/actions/workflows/gaslux-agent-lifecycle-research.yml/runs?branch=main&per_page=30`.
- Apenas execuções reais `schedule` ou `workflow_dispatch` em `main` contam como heartbeat; `push`, `pull_request` e `workflow_run` são excluídos.
- Se a execução mais recente terminou **SUCCESS** há pelo menos **45 minutos**, pode pedir `workflow_dispatch` **exclusivamente** do Lifecycle read-only, com `mint_live_boot=false`. Nunca executa os agentes de criação de PR, integração, instalador Guest ou writer.
- Se não há histórico verificável, se a execução está ativa, terminou com erro, a API falha ou há corrida/conteúdo inválido, o script recusa a operação.
- O Raspberry Pi usa bloqueio `flock` no diretório runtime privado, execução systemd `Type=oneshot`, timeout de 45s, recursos limitados, sem root, sem subprocessos nem comandos externos; o estado e os motivos de recusa ficam no `journalctl`.
- A proteção contra duplicação é best-effort e **não garante exclusão distribuída** perante o cron nativo do GitHub. Por isso, continua **read-only**. Não conceder permissão de merge nem código de instalação a este watchdog.

## Instalação (apenas depois de aprovação Safety e integração em main)

No próprio Pi, com um utilizador **não-root** que tenha `systemd --user`, Python 3 e acesso HTTPS a `api.github.com`:

```bash
git clone --depth 1 https://github.com/LMhdez/gaslux.git
cd gaslux
sh ops/autonomy/raspberrypi/install-user.sh
systemctl --user list-timers gaslux-fallback.timer
journalctl --user -u gaslux-fallback.service -n 30 --no-pager
```

A instalação cria `~/.config/gaslux/raspberrypi-scheduler.json` com `{"enabled":false,"dry_run":true}`, guardado com modo `0600`, e instala somente unidades de **utilizador**. O timer fica programado, mas as ações ficam **PAUSED**. A execução do serviço não usa `sudo`.

Se precisares que funcione quando a sessão SSH termina, ativa o *linger* para **esse utilizador** (esta é uma ação de sistema que requer autorização local):

```bash
sudo loginctl enable-linger "$(whoami)"
systemctl --user status gaslux-fallback.timer
```

O timer usa `Persistent=true` para recuperar uma execução após Pi desligado e `AccuracySec=30s`; estes valores não garantem execução em tempo real. O Raspberry Pi tem de permanecer ligado, com relógio acertado e acesso à internet.

## Ensaio seguro — sem token

Edita `~/.config/gaslux/raspberrypi-scheduler.json` para:

```json
{"enabled": true, "dry_run": true}
```

Guarda em modo `0600`. Para uma observação imediata:

```bash
systemctl --user start gaslux-fallback.service
journalctl --user -u gaslux-fallback.service -n 30 --no-pager
```

Esperado: `RECENT`, `RUN_IN_PROGRESS`, `WOULD_DISPATCH`, `NO_ATTESTED_RUN` ou `FAILED_HALT`. **Nenhum pedido de arranque é enviado no ensaio.** O serviço recusa ficheiros de configuração com symlink/hardlink, modo inseguro ou campos inesperados.

## Ativação limitada, depois do ensaio e do parecer Safety

1. Cria **no GitHub** um *fine-grained Personal Access Token* limitado **apenas** ao repositório `LMhdez/gaslux`, com permissão **Actions: Read and write**, porque o endpoint `workflow_dispatch` exige essa permissão; não conceder `Contents: Write`, `Administration`, outros repositórios nem instalação/desinstalação de sistemas. Define validade curta e plano de rotação.
2. Guarda o token **localmente no Pi** em `~/.config/gaslux/github-actions-token`, com `0600`, sem symlink/hardlink. **Nunca colocar token no GitHub, comentários, logs, screenshots, chat, argumentos CLI nem histórico da shell.** Podes criar/editar o ficheiro num editor local com `umask 077`.
3. Altera a configuração local para `{"enabled":true,"dry_run":false}` e verifica `chmod 600 ~/.config/gaslux/raspberrypi-scheduler.json ~/.config/gaslux/github-actions-token`.
4. Verifica uma execução `DISPATCH_REQUESTED` no journal e uma execução `workflow_dispatch` do Lifecycle no GitHub, seguida de um `RECENT` sem duplicação. O token não é lido quando não é necessário fazer um dispatch.
5. Regista os IDs, SHA, horários UTC, Safety e razão de recuperação na [Issue #390](https://github.com/LMhdez/gaslux/issues/390).

## Paragem de emergência
- Imediata: `systemctl --user disable --now gaslux-fallback.timer`. Cancela também qualquer job GitHub já ativo na página Actions.
- Persistente: muda `enabled` para `false` no JSON. O watchdog fica inerte mesmo que o timer seja reiniciado.
- O travão próprio dos agentes `GASLUX_AUTONOMY_PAUSED=true` na PR #389 é **separado** deste timer e só atua após integração em main.

## Prova antes de integração
```bash
python3 -B -m unittest discover -s ops/autonomy/raspberrypi -p test_raspberrypi_scheduler.py -v
```
Os testes correm offline, sem GitHub token e sem Pi, incluindo recusas, identidade dos runs, race local, destinos privados, hardlinks, symlinks, run falso e nunca autorizar publicação/merge.

**Limite de autoridade:** `RPI_TIMER_SCHEDULE_ONLY / LIFECYCLE_HOST_READONLY / NO_GUEST_INSTALL / NO_PHYSICAL_DISK_WRITE / NO_MERGE / NO_RELEASE`.

**Acesso remoto:** este repositório e o conector GitHub não dão acesso SSH ao Raspberry Pi. O Pi não foi identificado, inventariado nem configurado pelo Supervisor.
