# Observer GPT — controlador protegido e ledger one-shot (contrato OFFLINE v1)

**Estado: NÃO OPERACIONAL.** Esta proposta não é um controlador de execução nem uma autoridade de evidência. Não ativa QEMU, guest input, instalação, escritor de disco ou workflows operacionais. A CI executa exclusivamente validação estática com ficheiros descartáveis.

## Proveniência e reutilização obrigatória

- [PR #275](https://github.com/LMhdez/gaslux/pull/275) no commit `1a6446b408c78386e720f8d2b1f2063c1d3f7db1`: `auto_tests/tools/observer_gpt_qemu_one_shot.py` já implementa `validate_trigger` e `validate_git` com SHA de preparação e autorização exatos, HEAD/HEAD^, evento e diff exclusivo. **Não duplicar nem substituir** esse verificador. O valor `unused_external_grant=True` continua só uma afirmação do chamador; não prova consumo atómico independente.
- `docs/INSTALLER_OBSERVER_GPT_PROTECTED_CONTROLLER.template.yml` da #275 permanece fora de `.github/workflows` e contém `if: false`. O antigo workflow branch-controlled foi desativado na #275, mas outras branches (incluindo #273) não foram revogadas globalmente.
- [PR #267](https://github.com/LMhdez/gaslux/pull/267), SHA `0be04192acd542646a5b6cd952e01620379edf5d`: contratos Safety de GPT, identidade e recusa de writers. Não é atestação guest independente.
- [PR #280](https://github.com/LMhdez/gaslux/pull/280), SHA `e3783408a109c737cf7095943b47ca878ba012a0`: parecer Safety `CONTRACT_ACCEPTABLE_DENY_ONLY` / `BLOCKED_TRUST_ROOT`.
- Esta PR acrescenta apenas um schema de pedidos e um modelo SQLite em diretório local descartável. O modelo não expõe endpoint operacional nem converte fixtures em credenciais.

## Duas autoridades separadas

| | A — Autoridade de execução | B — Autoridade de evidência |
|---|---|---|
| Responsabilidade | Decidir se uma experiência **exatamente identificada** pode ser iniciada, após revisão humana externa, e consumir a concessão **antes** de qualquer execução | Verificar independentemente o que ocorreu na VM: launch QEMU, identidade de ISO/payload, handles/fds, setores GPT, CRC, traces guest e integridade da cadeia de medição |
| Administração futura | Branch `main` protegida + controller revisto + reviewers independentes + ledger durável com ACL externas ao runner e à branch | Coletores/verificador separados do executor e de A, com cadeia autenticada até à sessão guest |
| Entradas confiáveis | SHA completos de preparação, autorização, controlador e código auditado fixados em origem protegida **não fornecida pela branch solicitante**; decisão humana verificável; expiração e revogação externas | Bytes originais, origem/proveniência, vínculos de VM/collector e medição verificada por raiz externa; consumo dos contratos Safety #267 |
| Limite | Concessão APPROVED ou CONSUMED **não atesta** guest ou DBus | Medição válida **não concede** permissão de execução, input ou escrita |

Identidade do requerente e aprovador tem de ser distinta; não aceitar self-approval. Aprovação AI assistida, `humanApproved=true`, comentário PR, evento GitHub, variável de ambiente, OIDC ou HMAC gerado pelo próprio runner não constituem autoridade independente. Os SHA da branch requerente são alegações até confirmados por origem externa e Git exato protegido. Só o controlador revisto pode consultar esses dados; nunca executar scripts da branch requerente antes da validação.

## Contrato offline v1

Schema: `schemas/observer-one-shot-grant-v1.schema.json`, Draft 2020-12, `additionalProperties=false`. Campos obrigatórios: UUID v4 único `grantId`, versão, repositório, experimento, ref, SHA-1 completos (40 caracteres) de preparação, autorização, controlador protegido e código auditado, requester, approver externo, referência de revisão humana, escopo READ_ONLY_DIAGNOSTIC, emissão e expiração. O schema **não** autentica os hashes nem o autor da concessão.

Estados: `REQUESTED -> REVIEW_PENDING -> APPROVED -> CONSUMED`; `REQUESTED`, `REVIEW_PENDING` ou `APPROVED` podem transitar para `REVOKED`, `REFUSED` e, após prazo, `EXPIRED`. Os quatro estados terminais são irreversíveis. `APPROVED` exige `TrustedDecisionFixture` coincidente com todos os pins e revisão. Esta classe é uma **simulação** da futura resposta externa, não uma assinatura nem uma identidade autenticada.

`OfflineLedger` usa SQLite local, transações `BEGIN IMMEDIATE`, `synchronous=FULL`, journal DELETE e uma tabela de decisões sequenciais. A alteração para CONSUMED e o registo de decisão são confirmados no mesmo COMMIT, **antes** do retorno da chamada. Um segundo consumidor encontra CONSUMED e é recusado; falha após consumo não restitui concessão. Rejeições sobre grants conhecidos ficam registadas. UUID repetido é recusado e auditado. Os testes de concorrência e reinício usam ficheiros descartáveis, sem equivalência com serviço externo.

**Limites:** SQLite sob controlo do runner não é raiz de confiança; não impede adulteração do ficheiro, restauração de snapshot, rollback do relógio, acesso concorrente noutro host, HA, falsificação de reviewer ou TOCTOU em diretórios adversariais. Rejeição básica de symlinks/hardlinks não torna a BD segura contra ataque de filesystem. `RunObservationFixture` contém observações **alegadas**: para execução real será obrigatório reutilizar `validate_git` da #275 no controlador protegido, e repetir a medição do checkout e da árvore a executar. Não inferir atestação por valores JSON.

## Fluxo operacional futuro — NÃO implementado

1. Um operador humano independente aprova uma experiência e SHA exatos em infraestrutura administrativa externa à branch experimental.
2. O controlador protegido obtém SHA/revisões **de fonte externa autenticada**; faz checkout do código de validação protegido e nunca corre código não confiável antes do preflight.
3. Reutiliza `validate_trigger` e `validate_git` da #275, exigindo HEAD e HEAD^ exatos, um único commit de autorização e diff estritamente permitido. Histórico intermédio com alteração de workflow/preflight é recusado, mesmo que o último commit só acrescente JSON.
4. Consulta expiração/revogação. Um serviço externo com compare-and-swap e registo durável consome o grant uma só vez **antes** de iniciar guest; indisponibilidade, timeout ou consumo incerto impõem DENY sem retry automático. Não permitir reexecução, recriação de branch, force-push, input, writer nem instalação.
5. Após eventual aprovação adicional de execução real, a autoridade B independente terá de verificar dados observados na VM; não assumir que A a substitui. Nenhuma destas integrações existe nesta PR.

## Matriz de ameaças e testes

| Falha ou ataque | Recusa modelada |
|---|---|
| Commit intermédio altera workflow/preflight | Históricos Git temporários reproduzem HEAD^ divergente do commit de preparação autorizado; DENY. Validação formal do diff pertence à #275 |
| Aprovação falsificada ou sem revisão humana; requester igual a reviewer | Snapshot confiável sintético ausente/divergente; esquema e identidade rejeitam |
| SHA de preparação/autorização/controlador/código alterado | Igualdade exata obrigatória; DENY |
| Dois consumos, disputa de oito threads, reuse do mesmo grant | Um só CONSUMED; restantes DENIED, evento durável |
| Interrupção abrupta após COMMIT | Novo processo lê CONSUMED e não reabre |
| Concessão expirada ou revogada; branch recriada; rerun | DENY; estado terminal |
| Autoridade externa indisponível | DENY, sem substituto local |
| Pedido de instalação, escrita ou canal guest | DENY; escopo READ_ONLY_DIAGNOSTIC apenas |
| Atacante controla BD, relógio, runner, source branch ou falsas medições | NÃO RESOLVIDO por este modelo; execução operacional bloqueada |

## Requisitos de infraestrutura verificados em 21/11/2026

| Requisito | Constatação | Bloqueio |
|---|---|---|
| Proteção de `main` | Branch API devolveu `protected=false`; API branch-protection 403 para esta instalação; rulesets enumerados vazios | **Não comprovada / não usar para execução** |
| Environment com revisores obrigatórios | API de Environments inacessível através do conector; template apenas menciona `gaslux-gpt-qemu-human-reviewed` | Não verificado |
| Separação requester/approver, self-approval desativado | Não existe prova de configuração de identidade independente | Não verificado |
| Ledger externo e durabilidade/ACL | Não foi identificado serviço operacional; existe apenas SQLite descartável de teste | Em falta |
| Revogação independente | Sem endpoint confiável comprovado | Em falta |
| Atestação guest independente | Ausente nos contratos atualmente auditados | BLOCKED_TRUST_ROOT |

Indicadores de capacidade **imutavelmente falsos no modelo**:

```json
{
  "protectedControllerOperational": false,
  "externalLedgerOperational": false,
  "guestAttestationVerified": false,
  "qemuExecutionAuthorized": false,
  "guestCommandChannelAuthorized": false,
  "diskWritesAuthorized": false,
  "productionInstallationAuthorized": false
}
```

**Revisão exigida:** humano responsável, GASLUX-SAFETY e GASLUX-OBSERVER; confirmar GPL-3.0, DCO e `AI_POLICY.md`. Não fazer merge, não executar QEMU, não confiar no fixture como atestado.
