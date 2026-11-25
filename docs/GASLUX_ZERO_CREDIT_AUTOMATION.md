# Gaslux — monitor de progresso sem créditos de IA

## Objetivo

Executar uma verificação read-only de GitHub a cada 30 minutos (GitHub Actions)
e publicar o resultado na página de execução e como artefacto JSON/Markdown.
Sem Copilot, modelos, chaves OpenAI API, contas de terceiros, PAT ou chamadas a IA.

**O monitor não é um agente de programação.** Os chats do ChatGPT Plus não podem
ser invocados diretamente por GitHub Actions como uma API ilimitada. Este
workflow não cria PRs, não dá permissões de escrita, não faz merge, não executa
instalações e não atesta recuperação de Windows ou Linux.

## Ativação

- A proposta é uma PR com revisão; **não é ativada por criar a PR**.
- schedule e workflow_dispatch só funcionam depois de o ficheiro do
  workflow existir na branch padrão main (restrição do GitHub).
- Depois do merge em main, em Actions → Gaslux zero-credit progress monitor
  podes executar Run workflow para obter o primeiro relatório.
- O monitor usa GITHUB_TOKEN temporário, com contents:read,
  actions:read e pull-requests:read; não requer segredo criado manualmente.
- O relatório atual fica no resumo da execução e num artefacto retido por 3 dias.

## O que mede

- HEADs dev e main;
- PRs abertas/draft e bases diretas em dev;
- merges recentes em dev;
- amostra limitada de estados das Actions;
- uma fila heurística de PRs para investigação **manual**.

A fila não é um veredito de prontidão. Verificar diffs, testes realmente
executados (incluindo passos SKIPPED), evidências de QEMU/Windows e segurança
antes de qualquer integração.

## Validação local

    python3 -m unittest discover -s auto_tests/tests -p 'test_gaslux_zero_credit_monitor.py' -v

## O que permanece manual ou requer um motor de IA

O Supervisor e Prompt Engineer do ChatGPT podem usar o relatório como contexto.
Não existe mecanismo suportado para GitHub Actions enviar prompts ilimitados ao
ChatGPT Plus e obter respostas via API sem consumo associado.

Uma eventual etapa autónoma com LLM **fica desativada** até existir uma solução
explicitamente autorizada e compatível com orçamento adicional de 0 €.
