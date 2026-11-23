# GASLUX — Raspberry Pi como trigger completo dos quatro agentes

**Estado:** implementação na [PR #389](https://github.com/LMhdez/gaslux/pull/389); aguarda Safety, integração e instalação no Pi. Não existe acesso SSH ao Pi nesta sessão. **Nenhuma alteração Cloudflare é necessária.**

O Pi é **somente o relógio externo**. Executa os MESMOS workflows já definidos em `main`, com os mesmos inputs e privilégios GitHub; as verificações de Safety, modelos, autenticação de código, seleção de tarefas e política de merge continuam a ser as dos workflows existentes. Não executa código LLM nem instala OS no próprio Pi.

## Paridade de eventos com o cron GitHub da PR #389 (UTC)

| Workflow GitHub existente | Intervalo Raspberry Pi | Inputs do `workflow_dispatch` |
| --- | --- | --- |
| `gaslux-agent-clock.yml` | :03, :18, :33, :48 | `role=auto` |
| `gaslux-agent-feature-factory.yml` | :06, :21, :36, :51 | Sem inputs |
| `gaslux-agent-integrator.yml` | :10, :25, :40, :55 | Sem inputs |
| `gaslux-agent-lifecycle-research.yml` | :16, :46 | `mint_live_boot=false` |
| **Mesmo Lifecycle — Mint oficial diário** | 03:31 | **`mint_live_boot=true`** |

O serviço `systemd --user` acorda **uma vez por minuto**, verifica se há instantes previstos ainda não cobertos e envia `workflow_dispatch` usando a API oficial GitHub. Os próprios workflows decidem o que executar, tal como com `schedule`. A PR corrige também a condição `github.event.schedule` do Mint diário para as 03:31, mantendo paridade entre os dois gatilhos.

## Única condição de supressão: não duplicar trabalho

- Se houver execução **queued, in_progress, pending, waiting ou requested** desse workflow em `main`, não inicia outra.
- Se GitHub já entregou um disparo do mesmo instante **e da mesma função/inputs comprovados**, não repete. A identidade é validada pelo `display_title` da API GitHub, calculado pelo `run-name` de cada workflow em `main`; um Lifecycle normal `research` ou manual `mint_live_boot=false` **nunca** cobre o Mint diário `mint-daily`, e um Clock manual `role=mint` não cobre `role=auto`. Runs sem identificação semântica não são tratados como prova de execução do slot. Esta verificação corrige o finding **F-389-01**.
- Guarda em disco privado (`~/.config/gaslux/last-dispatched-slots.json`) os instantes pedidos; um reboot ou listagem GitHub temporariamente desatualizada não repete a mesma execução. Também espera a visibilidade do último POST.
- **Falhas dos jobs NÃO suspendem o relógio.** O ciclo seguinte volta a chamar o mesmo workflow normalmente. Se Pi ou Internet estiverem temporariamente em baixo, ao regressar tenta o último ciclo em falta por workflow, incluindo Mint diário.
- A prevenção de duplicados entre servidores **não é atomicamente garantida**: o cron nativo do GitHub pode começar durante a janela entre consulta e POST do Pi. A exclusão perfeita exigiria um bloqueio partilhado com GitHub, não suportado por um simples trigger. Não há limitação artificial de agentes ou modos no Pi.

Isto dá **equivalência de capacidade**, mas não promete disponibilidade absoluta: o Pi tem de ter eletricidade, ligação à Internet, hora UTC sincronizada, token GitHub válido e acesso ao serviço GitHub; `workflow_dispatch` é uma API remota, não entrega garantida sem falhas. O timer com `Persistent=true`, estado atómico e tentativas nos minutos seguintes melhora a recuperação quando estas condições regressam.

## Instalação no Pi (após gates Safety e integração)

Com um utilizador normal, não-root, em Raspberry Pi OS/Debian com `python3`, `git` e `systemd --user`:

```bash
git clone --depth 1 https://github.com/LMhdez/gaslux.git
cd gaslux
sh ops/autonomy/raspberrypi/install-user.sh
systemctl --user list-timers gaslux-fallback.timer
journalctl --user -u gaslux-fallback.service -n 30 --no-pager
```

Instala somente script e unidades de **utilizador**, recusando sobrescrever ficheiros existentes ou symlinks. O ficheiro `~/.config/gaslux/raspberrypi-scheduler.json` fica inicialmente `{"enabled":false,"dry_run":true}`, `0600`. A ativação é uma operação local explícita, não uma limitação permanente da solução.

Para o timer persistir após logout e durante o arranque do Pi, o administrador do Pi pode autorizar:

```bash
sudo loginctl enable-linger "$(whoami)"
```

### Canary local

Configurar `{"enabled":true,"dry_run":true}` no JSON privado, e executar:

```bash
systemctl --user start gaslux-fallback.service
journalctl --user -u gaslux-fallback.service -n 30 --no-pager
```

Verificar `WOULD_DISPATCH`, `ALREADY_RUNNING`, `ALREADY_TRIGGERED`, `WAITING_FOR_VISIBILITY` e `OK`. Em dry run, **nenhum POST** é enviado.

### Ativação do trigger (depois de aprovação Safety)

Criar no GitHub um *fine-grained personal access token*, apenas para `LMhdez/gaslux`, com **Actions: Read and write**. Esta permissão é necessária para criar eventos `workflow_dispatch` para os quatro workflows. Não conceder `Contents: Write`, `Administration` ou acesso a outros repositórios. O token permite **arrancar workflows que, por sua vez, possuem as próprias autoridades de escrita**; proteger o Pi e este token como credenciais privilegiadas de automação.

Guardar o token **apenas no Pi** em `~/.config/gaslux/github-actions-token` como ficheiro privado regular `0600`, sem symlink/hardlink; nunca publicar no GitHub, na conversa, no histórico da shell ou em logs. As consultas API também usam autenticação para não esgotarem os 60 pedidos/hora permitidos a clientes anónimos.

Após testar, alterar o JSON privado para `{"enabled":true,"dry_run":false}`, verificar permissões `0600` e reiniciar/testar o serviço. Confirmar em GitHub Actions o evento `workflow_dispatch`, SHA `main`, jobs normais e a ausência de uma segunda execução enquanto a primeira ainda corre.

**Paragem imediata:** `systemctl --user disable --now gaslux-fallback.timer`. Para cancelar jobs já entregues, usar GitHub Actions. A variável de Safety `GASLUX_AUTONOMY_PAUSED=true` continua a ser respeitada pelos workflows após integração da PR.

## Testes CI

```bash
python3 -B -m unittest discover -s ops/autonomy/raspberrypi -p test_raspberrypi_scheduler.py -v
sh -n ops/autonomy/raspberrypi/install-user.sh
systemd-analyze calendar '*-*-* *:*:00 UTC'
systemd-analyze verify ops/autonomy/raspberrypi/gaslux-fallback.service ops/autonomy/raspberrypi/gaslux-fallback.timer
```

Escopo: `TRIGGER_PARITY_ALL_FOUR / DAILY_MINT_INCLUDED / NO_CONCURRENT_DUPLICATES / SAME_EXISTING_WORKFLOW_SAFETY / NO_PI_DEVICE_CONNECTED`.

Documentação: [GitHub Actions schedule](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule), [GitHub workflow_dispatch REST](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event), [systemd.timer](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html).
