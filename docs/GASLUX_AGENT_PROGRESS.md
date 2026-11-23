# GASLUX — Observabilidade e controlo dos agentes GitHub

**Estado:** proposta em Draft, requer CI, análise Safety e integração explícita em `main`. Não instalada nem ativa em produção enquanto a PR não for integrada.

## Objetivo
A cada execução do workflow agendado `Gaslux autonomous GitHub agents`, um job **read-only** `autonomy_progress` consulta os quatro fluxos automáticos existentes e publica um **GitHub Actions Step Summary** e um artefacto `gaslux-autonomous-progress` (`agent-checkpoints.json`). Atualiza-se sem custos de LLM e sem escrita de GitHub no job.

### Acesso ao painel
`GitHub → LMhdez/gaslux → Actions → Gaslux autonomous GitHub agents → execução mais recente → autonomy_progress`. A página da execução mostra o resumo; os artefactos incluem o JSON de checkpoints. Frequência típica: cron de 15 minutos, sujeito à disponibilidade de agendamento do GitHub. O relatório reflete os *últimos runs observados*, não uma subscrição em tempo real.

### Checkpoints verificáveis
| Fluxo | Checkpoints (ordem) |
|---|---|
| Agente teclado (Mint/Zorin) | seleção → modelo → Safety → compilação/testes Windows → publicação Draft |
| Propostas seis distros | seleção → modelo → Safety → publicação Draft |
| Integrador `dev` | seleção → aceitação Windows → integrador com commit exato |
| Pesquisa de ciclo de vida | testes contratos por distribuição → boot live Mint quando agendado |

O job só considera `passed` quando os **jobs Actions reais** correspondentes terminaram com `conclusion=success`. `skipped`, `idle`, `unobserved`, `running` e `blocked` não equivalem a trabalho acabado. Cada barra **mede checkpoints desse run**, não funcionalidades nem progresso de release. Falhas são contadas nas oito execuções operacionais mais recentes de cada fluxo, e cada pipeline inclui link para a execução e SHA do código. Uma falha de API não vira sucesso: o painel falha fechado e não concede autoridade.

### Aceitação real do produto
O painel lê **dados JSON** de `docs/autonomy/goal.json` e `docs/autonomy/evidence.json` em `dev`. Exibe o número de slots de evidência exigidos (**136 atualmente**), o número de registos declarados e **zero atestados externos nesta ferramenta**. Mesmo um registo formalmente correto **não** é prova de instalação, dual boot, desinstalação ou recuperação Windows sem inspeção independente. `release_eligible=false` é invariável no painel. O `goal_supervisor.py` mantém a avaliação separada.

### Travão de emergência
Criar ou editar em `Settings → Secrets and variables → Actions → Variables` a variável de repositório:

- **Nome:** `GASLUX_AUTONOMY_PAUSED`
- **Valor:** `true`

Com este valor, os **novos** jobs de seleção/modelo e integração dos fluxos de agentes param; a publicação de Draft PR e o merge confiável em `dev` também verificam a flag dentro do código, antes das operações. O job de telemetria mantém-se ativo e mostra `PAUSED`. Os jobs de contrato de PR/push não escrevem código.

**Limitação operacional:** a variável não revoga instantaneamente tokens de execuções que já começaram. Em emergência, cancelar os runs em andamento na página Actions, bloquear merge e, se necessário, desativar os workflows temporariamente. Só repor a variável para `false` depois de examinar o motivo da pausa.

### Barreiras de segurança existentes mantidas
- Apenas código confiável de `main` consulta a API e apresenta o painel; ficheiros de `dev` são analisados como dados JSON.
- O dashboard só tem `contents: read` e `actions: read`, checkout sem credenciais persistentes, e não usa scripts/modelos de `dev`.
- Os modelos não recebem tokens de publicação; só os publishers/integradores de confiança têm permissões especiais, com limites de escopo e checks existentes.
- As alterações desta PR não concedem permissão de instalação no Guest, discos físicos, `main`/stable, recuperação Windows ou novos backends no catálogo.
- Não há alegação de que a API de GitHub tenha verificado integralmente os artefactos/merges ou de que uma percentagem represente qualidade do produto.

### Critérios de aceitação Safety
1. A CI executa testes adversariais do reporter: falhas, idle/skipped, corridas, jobs matriciais, SHA malformado, evidência duplicada e resposta parcial.
2. Pausa `true` impede nova seleção e bloqueia **antes de cada publicação/merge confiável**, incluindo corridas entre jobs; pausar não transforma em sucesso um run interrompido.
3. O reporter nunca interpreta `CI success`, `Draft PR`, claim JSON ou `qemu-img create` como `INSTALLED_GUEST`, `DUAL_BOOT`, `WINDOWS_RECOVERY` ou release.
4. Verificar caminho de execução por workflow, permissões dos jobs e estado dos runs reais. Após revisão independente, integrar em `main` apenas a instrumentação e a pausa, sem alterar a cadeia `dev` de instaladores.

### Expansão posterior, separadamente revista
Uma fase futura poderá juntar contadores por distribução (tarefas abertas, PRs Draft, PRs aprovadas, blobs integrados), tempos e custo de CPU/inferência por task, `run_attempt`, orçamento máximo de retries, no-progress alerts e evidência direta por gate Windows/Linux. Esses números devem ter origem determinística, identificador de missão, SHA, URL e recusa Safety, nunca texto livre de LLM.
