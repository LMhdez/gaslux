# Gaslux — histórico técnico e manual operacional dos agentes

> Revisão: 2026-11-22 UTC. **Este documento é um índice histórico e um procedimento de trabalho, não um certificado de estabilidade.** As referências de PR, HEAD, CI e integração mudam rapidamente; consultar novamente o GitHub antes de agir. A política executável e de segurança continua em [AGENTS.md](../AGENTS.md), [AI_POLICY.md](../AI_POLICY.md), [ARCHITECTURE.md](ARCHITECTURE.md), [CONTRIBUTING.md](../CONTRIBUTING.md) e nos schemas.

## Manter permanentemente atualizado

**O instantâneo de 22-11-2026 é histórico e não é o estado vivo do Gaslux.** Antes de cada missão, consultar novamente `dev`/`main`, PRs abertas/fechadas/merged, branches, issues, commits, workflows e execuções no HEAD exato. Sempre que surgir evidência nova, mudança de código/capacidade, finding, merge ou fecho, corrigir as referências afetadas **na mesma intervenção**, preservando a cronologia original e acrescentando a data UTC e os SHAs/URLs das provas.

Responsáveis: Orquestrador/Prompt Engineer corrige instruções e dependências antigas; Backend mantém o seu dossier e provas de instalação/boot; Safety regista findings e regressões; Observer mantém os limites de proveniência HOST/guest; Integrador atualiza relações entre PRs, integração real em `dev`, fechos e o [índice de testes VM](CI_VM_EVIDENCE_INDEX.md). Não manter PRs já merged como pendentes nem reabrir tarefas históricas demonstradas.

**Critério de conclusão:** se uma decisão alterou o estado documentado, atualizar e verificar o documento antes de declarar sucesso; quando não se alterou nenhuma conclusão, uma revalidação não exige reescrita artificial. Se faltar capacidade ou acesso, indicar o ficheiro desatualizado e o bloqueio concreto. Não inventar uma atualização automática agendada: este dever é executado pelos agentes em cada evento relevante. Ver [AGENTS.md](../AGENTS.md) e [AI_POLICY.md](../AI_POLICY.md).

## CORE-361-DEV-INTEGRATION-01 — integração verificada em 22-11-2026 UTC

- A [PR #363](https://github.com/LMhdez/gaslux/pull/363) foi **squash-merged** em `dev` como `09fba3df79302577338d81bd4fbdde9e20913a24`, seguida da correção documental `119b35a4fbc6e74e72171ac4794e37123cfe1b7f`. Pesquisa local-coder read-only não equivale a agente publicador autónomo.
- A [PR #361](https://github.com/LMhdez/gaslux/pull/361) foi **merged** (método `merge`, sem squash/rebase/force-push) em `dev` como [`6129f9cc4b92617d35a4bb5ba47b69c201bbd43a`](https://github.com/LMhdez/gaslux/commit/6129f9cc4b92617d35a4bb5ba47b69c201bbd43a), com pais exatos `119b35a4fbc6e74e72171ac4794e37123cfe1b7f` e HEAD Safety `302f4f02e2968428bfd4c2e4bbf1d8e15582c0a7`. O merge foi executado pela PR com precondição de HEAD e sem override explícito; `main` não foi alterado nesta missão.
- **Composição por blobs Git:** **12/12** caminhos aprovados da #361 idênticos ao seu HEAD e **9/9** caminhos da #363 preservados byte a byte relativamente ao `dev` imediatamente anterior. Zero interseções entre conjuntos alterados; documentação posterior da #363 preservada.
- **Safety:** [parecer #7082951550](https://github.com/LMhdez/gaslux/pull/361#issuecomment-7082951550) = `SAFETY_APPROVED_NON_WRITER`, F-361-01/F-361-02 **CLOSED**. [Supervisor #7082985320](https://github.com/LMhdez/gaslux/pull/361#issuecomment-7082985320) delegou integração `dev`. Cinco checks do [HEAD aprovado](https://github.com/LMhdez/gaslux/actions/runs/45049176083) passaram. Branch-protection REST: HTTP 403 `Resource not accessible by integration`, rulesets listados `[]`; tais respostas não comprovam ausência de proteções, mas o endpoint de merge GitHub padrão aceitou a operação. Não foram fabricados reviews ou sign-offs DCO.
- **CI pós-merge aplicável em `6129f9cc`: 6/6 SUCCESS:** [GPT identity](https://github.com/LMhdez/gaslux/actions/runs/45051151896), [media](https://github.com/LMhdez/gaslux/actions/runs/45051151914), [multidistro](https://github.com/LMhdez/gaslux/actions/runs/45051152082), [GPT FD Safety](https://github.com/LMhdez/gaslux/actions/runs/45051151973), [CachyOS contract](https://github.com/LMhdez/gaslux/actions/runs/45051151959) e [Windows recovery](https://github.com/LMhdez/gaslux/actions/runs/45051151886). O workflow Core específico não dispara em `push dev`; o build WPF, o auditor e os testes de proveniência passaram no HEAD exato Safety e a equivalência dos 12 blobs foi confirmada, **não** foi reexecutada essa suite na árvore de merge completa.
- **Limites:** apenas `CONTRACT/STATIC` e evidência read-only, sem boot Mint, Windows 10 guest, dual boot ou uninstall/rollback demonstrados. Laboratório Windows 10 UEFI/GPT com snapshot `clean2`, disco virtual exclusivo, quota e restauro continua não admitido (`E2E_BLOCKED_ENVIRONMENT`). `no_physical_disk_writes=true`; nenhuma promoção `main`/stable. Mudanças posteriores independentes em `dev` não alteram os dois pais nem a árvore do merge registado.

## 1. Como interpretar a história

As PRs documentam hipóteses, código, testes e revisões em pontos diferentes de uma cadeia. **PR fechada não significa integrada**, PR merged para uma branch experimental não significa integrada em dev, CI verde não significa guest boot e boot Linux não significa dual boot Windows recuperável. Verificar sempre os campos state, merged, base.ref, head.sha, merge_commit_sha, checks e artefactos do HEAD exato.

Classificar cada afirmação separadamente:

- **FONTE:** questão, PR, commit, ficheiro, ISO ou documentação oficialmente identificados.
- **IMPLEMENTADO:** código presente num SHA; ainda não implica execução.
- **VALIDADO_OFFLINE:** testes, fixtures, schemas, lint e simulação.
- **VM_REAL:** processo QEMU/OVMF/KVM efetivamente iniciado, guest observado, evidência ligada ao disco e à execução.
- **INSTALADO:** root da distribuição realmente instalado e arrancado sem depender do ambiente live; indicar disco e firmware.
- **DUAL_BOOT:** Linux e Windows reais arrancaram no layout exigido; hash de ficheiros não demonstra autor de uma escrita.
- **RECUPERADO:** rollback/remoção com Windows, boot, partições, BCD/WinRE, ESP/MBR, encriptação e ownership comprovados.
- **ESTÁVEL:** apenas para a configuração que satisfaz toda a matriz de release. Nunca inferir de uma célula de CI.

São níveis de evidência, não um contador de percentagem.

## 2. Linha histórica documentada (16–22/11/2026)

| Período | Evidência e conclusão limitada | Consequência para novos prompts |
| --- | --- | --- |
| 16/11 — descoberta | [#1](https://github.com/LMhdez/gaslux/pull/1) e [#2](https://github.com/LMhdez/gaslux/pull/2): descoberta Archiso, stage-target protegido e verificação read-only; não constituíam backend bootável nem integração Windows. | Não voltar a tratar identificação de ISO como instalação. |
| 16/11 — handoff | [#10](https://github.com/LMhdez/gaslux/pull/10): handoff Ed25519 com binding de nonce, identidade de disco, ISO, parâmetros e Windows ESP; QEMU/sintéticos, mas sem emissor Windows/EFI confiável de produção. | Reutilizar o contrato assinado sem declarar trust root completa. |
| 16/11 — primeiro Linux instalado | [#36](https://github.com/LMhdez/gaslux/pull/36), [Actions 43954231860](https://github.com/LMhdez/gaslux/actions/runs/43954231860): descrição de pacstrap real e primeiro boot CachyOS headless em QCOW2 próprio, com segundo QEMU sem ISO. | Prova apenas da VM isolada, não da coexistência Windows nem de desktop completo. |
| 16–17/11 — updates/falhas | [#42](https://github.com/LMhdez/gaslux/pull/42) acrescentou ensaios de pacote/GRUB, overlays QCOW2 e corte SIGKILL; [issue #3](https://github.com/LMhdez/gaslux/issues/3) e [#71](https://github.com/LMhdez/gaslux/issues/71) exigem dual boot Windows, updates e recuperação. | Testes de atualização isolada não resolvem os gates Windows. |
| 16–17/11 — arquitetura multidistro | [#7](https://github.com/LMhdez/gaslux/pull/7) integrou AGENTS e plano multidistro; main conserva a família Mint/Zorin e os adaptadores BIOS/MBR, UEFI/GPT existentes. | Não reconstruir firmware/rollback do zero; cada família mantém backend próprio. |
| 17–20/11 — integração incremental | [#175](https://github.com/LMhdez/gaslux/pull/175) integrou contratos prewrite Mint/Zorin, validação ISO e gate Bazzite read-only, incluindo o workflow de login live Mint; não promoveu Bazzite. | Inspecionar dev antes de replicar funcionalidade de PR antiga. |
| 18–21/11 — Windows e COW | [#192](https://github.com/LMhdez/gaslux/pull/192), [#205](https://github.com/LMhdez/gaslux/pull/205) e [#263](https://github.com/LMhdez/gaslux/pull/263): experiências Windows 10, Archiso e target partilhado, com consents e fronteiras de writable overlays. | Uma gravação em COW descartável não prova rollback in-place do Windows. |
| 19–22/11 — Mint forense | [#204](https://github.com/LMhdez/gaslux/pull/204), [#233](https://github.com/LMhdez/gaslux/pull/233), [#260](https://github.com/LMhdez/gaslux/pull/260), [#271](https://github.com/LMhdez/gaslux/pull/271), [#274](https://github.com/LMhdez/gaslux/pull/274), [#276](https://github.com/LMhdez/gaslux/pull/276), [#278](https://github.com/LMhdez/gaslux/pull/278): testemunho de shutdown, checkpoints A/B, integridade de braços e inventários ESP/Recovery. | Não atribuir alterações ESP/Recovery a Mint ou Windows apenas por divergência SHA; pedir A/B independente e evidência por ficheiro. |
| 19–22/11 — outras distros | Zorin [#264](https://github.com/LMhdez/gaslux/pull/264), Pop [#232](https://github.com/LMhdez/gaslux/pull/232)/[#298](https://github.com/LMhdez/gaslux/pull/298)/[#324](https://github.com/LMhdez/gaslux/pull/324), Q4OS [#256](https://github.com/LMhdez/gaslux/pull/256)/[#299](https://github.com/LMhdez/gaslux/pull/299)/[#318](https://github.com/LMhdez/gaslux/pull/318), Bazzite [#250](https://github.com/LMhdez/gaslux/pull/250)/[#262](https://github.com/LMhdez/gaslux/pull/262)/[#320](https://github.com/LMhdez/gaslux/pull/320). | Não assumir que todas as experiências chegam à mesma fase, nem transplantar bootloader, rootfs ou instalador entre famílias. |
| 20–22/11 — Observer | Cadeias [#259](https://github.com/LMhdez/gaslux/pull/259), [#270](https://github.com/LMhdez/gaslux/pull/270), [#292](https://github.com/LMhdez/gaslux/pull/292), [#294](https://github.com/LMhdez/gaslux/pull/294), [#312](https://github.com/LMhdez/gaslux/pull/312), [#319](https://github.com/LMhdez/gaslux/pull/319), [#321](https://github.com/LMhdez/gaslux/pull/321): evidência local FD/QMP/transport e separação de imports. | Atestação do peer Unix/processo local ≠ autenticação do guest, do backing ou autoridade para agir. |
| 22/11 — integração segura | Em dev foram integradas extrações delimitadas: [#302](https://github.com/LMhdez/gaslux/pull/302) SQLite offline, [#307](https://github.com/LMhdez/gaslux/pull/307) leitor GPT FD, [#308](https://github.com/LMhdez/gaslux/pull/308) NTFS mount fail-closed, [#309](https://github.com/LMhdez/gaslux/pull/309) schemas Q4OS, [#316](https://github.com/LMhdez/gaslux/pull/316) screenshot offline, [#322](https://github.com/LMhdez/gaslux/pull/322) GPT S-01 e [#319](https://github.com/LMhdez/gaslux/pull/319) HOST/FD deny-only. | Preservar blobs, testes e histórico; fechar apenas trabalho comprovadamente substituído; o merge do diagnóstico não habilita o instalador. |
| 22/11 — delegação | [#303](https://github.com/LMhdez/gaslux/pull/303) e commits posteriores de AGENTS/AI_POLICY explicitaram integração delegada e testes VM isolados no Actions. | Sem pedido humano por cada merge/teste elegível; respeitar gates reais, release e hardware físico separados. |

Esta cronologia descreve **o que as fontes afirmam ter demonstrado**; não substitui a inspeção do log/artefactos antes de usar um resultado como prova atual. Em especial, [issue #3](https://github.com/LMhdez/gaslux/issues/3) é um gate **CachyOS**, não uma issue de aceitação universal para Mint/Zorin. [Issue #254](https://github.com/LMhdez/gaslux/issues/254) é o gate Bazzite.

## 3. Ordem de consulta para todos os agentes

1. **Estado vivo:** comparar dev/main, PRs abertas e fechadas, HEAD/base, dependências, commits relevantes, checks Actions e issues; não copiar HEADs de um relatório antigo.
2. **Contrato de produto:** ler ARCHITECTURE, AGENTS, AI_POLICY, CONTRIBUTING, MULTIDISTRO_PLAN, RELEASES e schemas antes de alterar produção; para uma distro, ler o dossier em [distro-backends](distro-backends/README.md).
3. **História específica:** procurar a PR mais antiga com a capacidade requerida, as correções posteriores e eventuais commits já integrados em dev. Comparar blobs e caminhos, não apenas nomes de PR.
4. **Âmbito de evidência:** confirmar se a Action correu em push/PR/merge sintético, checkout SHA real, passos e artefactos. Workflow não é execução; verde não é prova de guest/boot se o passo foi SKIPPED ou mock.
5. **Próximo incremento mínimo:** selecionar uma causa verificável, teste RED, correção delimitada, teste GREEN, ação CI existente, revisão Safety proporcional e integração/limpeza se elegível.
6. **Relatório:** separar executado, simulado, observado, bloqueado e não testado. Cada claim material deve indicar SHA, workflow/run e limite.

## 4. Contrato para o orquestrador / prompt engineer

Um bom prompt Gaslux especifica: agente e identidade LMHDEZ; missão única; fonte/PR/HEAD **como referência a reconfirmar**; branch existente a reutilizar; alterações permitidas; teste que comprova a hipótese; CI/VM adequada; autoridade de escrita confinada; critérios de STOP; destino de integração; resultado verificável com links e SHAs.

**Evitar os anti-padrões históricos:**

- Enviar o Integrador sempre para as três PRs recentes enquanto as cadeias antigas ficam abertas.
- Pedir inventário geral repetidamente, ou propor nova PR/branch de integração para cada correção.
- Pedir confirmação humana cerimonial quando a delegação em dev e os gates aplicáveis já autorizam o merge.
- Tratar indisponibilidade de um workflow, imagem Windows, artifact ou KVM como autorização para simular um PASS.
- Mandar executar um QEMU já executado sem uma lacuna de evidência concreta; ou proibir indiscriminadamente VMs isoladas que já são permitidas.
- Declarar uma causa de escrita ESP/Recovery a partir de duas somas SHA sem observar o escritor.
- Solicitar nova auditoria integral quando só dois ficheiros mudaram e existe parecer anterior válido para o resto.

**Estrutura de prompt recomendada:** MISSÃO → ESTADO A REVALIDAR → HERANÇA/PRs A REUTILIZAR → DIFERENCIAL → RED/GREEN → ACTIONS/VM → SAFETY → MERGE/FECHO/RECUPERAÇÃO → RELATÓRIO. Não inserir metas arbitrárias de commits ou PRs.

## 5. Contrato para o Integrador

- **Fila mais antiga primeiro**, salvo defeito crítico novo: investigar #42, #56, #168, #180, #192, #204, #205, #217 e as suas cadeias, sem assumir que continuam abertas. Registar trabalho exclusivo, sobreposições, branch base e sucessores.
- **Unificar antes de duplicar:** escolher uma branch/PR existente da família; preservar testes, assinaturas e provas de origem. Usar extração mínima direta para dev quando o stack inteiro é experimental. Não copiar códigos de writer/guest operacional inadvertidamente.
- **Autorização delegada:** merges de PRs tecnicamente aptas para dev não exigem nova aprovação humana por PR **a menos que** branch protection, regras reais, política ou risco reservado o imponham. A revisão técnica independente de Safety deve ser proporcional ao risco; jamais forjar GitHub APPROVE, DCO ou checks.
- **Merge real:** fixar HEAD, comparar com dev, confirmar required checks e findings, executar merge com expected SHA, conferir novo commit e CI pós-merge. Se CI crítica falhar, parar os merges seguintes.
- **Depois do merge:** fechar PRs cuja substituição esteja comprovada e manter referências/SHAs; tentar apagar apenas branches ancestrais e sem dependentes com ferramenta autenticada e autorização. A inexistência de operação delete-ref no conector é um bloqueio de capacidade, não motivo para novo inventário semanal.
- **Métricas:** PRs abertas/fechadas/merged, branches totais/eliminadas, dev HEAD antes/depois, CI pós-merge. Não contar um comentário ou uma análise como redução.

## 6. Contrato para Safety

- Auditar o **diferencial e a fronteira de autoridade**. Para cada finding: adversário, pré-condição, código/linha, prova RED, correção necessária, prova GREEN, efeito sobre Windows e parecer restrito ao HEAD.
- Verificar GPT primária/secundária, CRC, LBAs reservados, setor 512/4096, identidade FD e TOCTOU; NTFS/BitLocker, ESP/EFI/BCD/WinRE, MBR/EBR, boot/NVRAM, ownership e checkpoints.
- Revisitar exemplos históricos: [#286](https://github.com/LMhdez/gaslux/pull/286)/[#307](https://github.com/LMhdez/gaslux/pull/307) (path vs FD), [#315](https://github.com/LMhdez/gaslux/pull/315)/[#322](https://github.com/LMhdez/gaslux/pull/322) (snapshot GPT), [#319](https://github.com/LMhdez/gaslux/pull/319) (O_PATH e identidade local), [#298](https://github.com/LMhdez/gaslux/pull/298)/[#324](https://github.com/LMhdez/gaslux/pull/324) (subprocessos/pathnames de mesma UID).
- Dados A/B: preservar baseline físico do QCOW2, backing, OVMF VARS e TPM por braço; inventariar ESP/Recovery por ficheiro. SHA divergente não atribui causalidade ao guest/host.
- Uma VM Actions descartável pode escrever **nos seus discos virtuais possuídos** com opt-in do workflow e verificação de isolamento; isso não equivale a autorização de writer Gaslux em Windows real.
- Pareceres possíveis: ACCEPTABLE_DENY_ONLY, CHANGES_REQUIRED, BLOCKED_EVIDENCE, ACCEPTABLE_FOR_SCOPED_INTEGRATION; descrever exatamente o âmbito, nunca estabilidade genérica.

## 7. Contrato para o Observer

- Separar plano de controlo, transporte, testemunho e origem: claim QMP, socket Unix/peer local, PID/início/FD do processo, descritor de imagem, backing/overlay, bytes GPT, guest boot, observação de UI e autoridade de comando.
- **CLAIMED ≠ LOCALLY_MEASURED ≠ guest attested**. SO_PEERCRED, /proc/PID/fd, O_PATH, leitura QMP, digest de imagem e ID de sessão não autenticam automaticamente o guest nem a associação entre QMP block device e disco real.
- Preservar separação entre import offline em dev e controlador experimental em branches. A integração de [#319](https://github.com/LMhdez/gaslux/pull/319) não transforma Observer em instalador.
- Para sinais host, fixar identity e ciclo de vida do processo/FD; recusar O_PATH, O_RDWR, symlinks/hardlinks, troca/ABA e fdinfo incompleto. Para guest, exigir canal/trust root independente antes de avançar de observação para capacidade.
- UI Q4OS: parar antes de Install; screenshots/OCR e ZIP histórico não provam clique seguro, instalação ou dual boot. Artefactos sintéticos e reais são classes diferentes.
- Nenhuma leitura/proveniência concederá automaticamente capacidades de guest input, writes, instalação, BootNext ou release.

### CachyOS — aditamento de proveniência ESP/RAW em 22-11-2026

A [PR #314](https://github.com/LMhdez/gaslux/pull/314), empilhada em #279, atingiu o HEAD `a341bd059916a151fa49fb58435a69945e005d5a` com [Action #45020744228](https://github.com/LMhdez/gaslux/actions/runs/45020744228) **SUCCESS (85 testes offline)**. O diferencial de sete commits adicionou contrato de captura por FD RAW sintético, ESP GPT/FAT32 e consistência de claims QEMU, não medição autenticada de QEMU histórico. O parecer ETW-01 `APPROVED_OFFLINE_DENY_ONLY` mantém-se limitado ao HEAD anterior. Um controlo explícito contra Linux `O_PATH` e regressão foram adicionados depois, até `f5efccd50507248ca447fa5883900d951289c551`; [Action #45021184614](https://github.com/LMhdez/gaslux/actions/runs/45021184614) **SUCCESS no HEAD final**: 86/86 regressões offline, Ruff e compileall. A [reauditoria diferencial Safety](https://github.com/LMhdez/gaslux/pull/314#issuecomment-7078980928) permanece pendente antes de integração; nada disto prova origem QCOW2 histórica ou guest.

O Orquestrador não deve pedir outro parser FAT32/ETW, repetir ETW-01 ou promover resultados de RAW sintético a proveniência Windows. Próxima prova útil: checkpoint QCOW2 privado/assinado, identidade/geração QEMU, FD e backing, QMP `query-block` e vínculo independente `blk`→disco Windows, ainda deny-only; depois controles A1/A2 antes de B1/B2. Não confundir QEMU host-only com boot Windows.

## 8. Contrato para cada backend

| Backend | Código/cadeia histórica a investigar | Próxima prova útil, sem repetir o já feito |
| --- | --- | --- |
| Mint | #175, #204/#233/#260, #271/#274/#276/#278 | Explicar/contrastar A/B Windows e Mint; integridade ESP/Recovery/BCD/WinRE e rollback, preservando regressões BIOS/UEFI. |
| Zorin | #175, #224/#264/#277/#281 | Instalação nativa em layout Windows real de VM, TOCTOU GPT, ambos os boots, updates e recuperação. |
| CachyOS | #1/#2/#10/#36/#42, #56/#180/#205/#248/#263/#279/#314 | Pacstrap/Archiso/firstboot reaproveitados; falta provar Windows partilhado, GRUB/EFI updates, transação e rollback de #3/#71. |
| Pop!_OS | #232, #291/#293/#296/#298, #323/#324 | Trust do binário distinst, seis GPT, ESP partilhada/separada, systemd-boot e paths de subprocessos antes do teste instalado; BIOS/GRUB apenas se provado. |
| Q4OS | #231, #256/#266/#299/#318, #258/#270/#317 | ISO/Calamares nativo, QMP observável e provenance; nunca confundir instalação em pasta Windows com root nativa; UI não é execução. |
| Bazzite | #175, #250/#262/#280/#320, [issue #254](https://github.com/LMhdez/gaslux/issues/254) | UEFI/GPT apenas; autenticar ISO + OCI/bootc, determinar write-set/ESP; trust root e rollback não demonstrados. BIOS/MBR bloqueado. |

Os números acima são pistas históricas. Uma PR pode já estar fechada, substituída ou integrada; **consultar o estado atual antes de decidir**. A família Debian/Ubuntu de Mint/Zorin é baseline de regressão, não um backend genérico copiável para Archiso, System76 ou Fedora Atomic.

## 9. Regras para ensaios VM no GitHub Actions

A autorização está em [AI_POLICY](../AI_POLICY.md) e [AGENTS](../AGENTS.md): permitir testes com QEMU-system/KVM (se disponível), SeaBIOS/OVMF, ISO real verificada, guest instalado, escrita no **ficheiro de disco virtual privado**, reboot, update, corte de energia e rollback, sem aprovação humana por cada execução. O próprio workflow deve conter opt-in de execução guest destrutiva; falhar sem isolamento, media/proveniência ou snapshot adequado. Nunca anexar dispositivos de bloco host, discos físicos ou partilhas exteriores como alvo RW. Segredos e token Actions são fronteiras independentes.

Não inventar novos workflows se o existente já cobre o caso. Consultar [índice de VM e CI](CI_VM_EVIDENCE_INDEX.md), inclusive workflows nas **branches de PR**, e revalidar exatidão dos comandos e do job. Distinguir LIVE, VM INSTALLED, WINDOWS GUEST, DUAL BOOT, UPDATE, RECOVERY e OFFLINE. Job SKIPPED ou contrato estático não comprova arranque real.

## 10. Relatório mínimo e critérios de fecho

Publicar como GASLUX AGENT REPORT: agent_id/role, conta LMHDEZ, data UTC, branch/base, HEAD antes/depois, origem dos blobs, ficheiros, testes e comandos com nível de evidência, Actions/artefactos, findings, gates de autoridade, PRs merges/fechos, branches eliminadas e próximos bloqueios. Não utilizar outra conta nem afirmar ações não realizadas.

**Critério de execução:** entregar código validado e/ou um merge/fecho/limpeza efetivos quando houver operação apta e autorizada; ou declarar o menor bloqueio técnico comprovável e passar à próxima tarefa elegível. Nunca alegar que o produto inteiro é estável por uma extração offline ou um guest boot isolado.


## Atualização de reconciliação Observer — 22/11/2026

A [PR #294](https://github.com/LMhdez/gaslux/pull/294) foi **encerrada sem merge** às 12:32 UTC, depois da comparação técnica detalhada com a #319 (merge `b57bbf97057a154beeb744bcbeef710687d520b4`) e a #312 (merge `e382cad6760ad71df03bebf463f435f682a07508`). A [prova de cobertura](https://github.com/LMhdez/gaslux/pull/294#issuecomment-7079175900) confirma as 16 funções de teste HOST/FD históricas, os sete testes F-01/F-02/F-03, as importações isoladas e regressões O_PATH no dev. O JSON sintético histórico manteve o blob `f2fd492aa7fb40c60510b2fa0c106eb808ac99a0`. A branch original da #294 e a workflow antiga (SHA `e7941ef3eb26c0cae1a2d7fbe1b3009eb050c5c9`) permanecem recuperáveis; não foram eliminadas. A #325 prossegue como experiência QEMU distinta, com deny-only, sem autorizar guest, disco, rollback ou instalação. A #259 e o controller experimental não foram integrados pela reconciliação.


## Referências de segurança

- [Plano de arquitetura/rollback](ARCHITECTURE.md) e [matriz multidistro](MULTIDISTRO_PLAN.md).
- [Critérios CachyOS #3](https://github.com/LMhdez/gaslux/issues/3), [Windows 11 #71](https://github.com/LMhdez/gaslux/issues/71), [Bazzite #254](https://github.com/LMhdez/gaslux/issues/254).
- [Guias técnicos por backend](distro-backends/README.md), [contratos partilhados](distro-backends/SHARED_CONTRACTS.md).
