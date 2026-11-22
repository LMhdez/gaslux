# Zorin 18.1 — SOURCE-01: corpos Ubiquity e fronteira da primeira escrita

**22-11-2026 (UTC).** Revisão técnica read-only. Classe de decisão
`ROUTE_B / UBIQUITY_PRECOMMIT_PLAN_UNAVAILABLE` (PR #339).
**Não executar** Ubiquity, partman, shell scripts, GRUB ou ferramentas de disco.

## Origem, verificada sem substituir identidades

- `dev` observado: `8e68a475d6397ba8fef2e0f9f83758545e202a5f`.
- [PR #264](https://github.com/LMhdez/gaslux/pull/264) e
  [Actions #44891962800](https://github.com/LMhdez/gaslux/actions/runs/44891962800).
  ZIP original (artefacto 14702053502), **SHA-256 efetivamente recalculado
  localmente**: `641bf31056addd3e54126d3e636ea524d12d0a4ac16e4188510aef8ae1f08da9`.
- O ZIP contém **exatamente três JSON**: discovery, denied target e
  `zorin-native-ubiquity-code-map.json`. Este último tem 121 941 bytes e
  SHA-256 recalculado `47f42ce781af0eb39bc19f6c3bf4f2fb20569c5467a8f17d8e6d84b273a08f24`.
- ISO fixada: Zorin OS 18.1 Core, 3 909 091 328 bytes,
  SHA-256 `44649b97bd307fc4c8529205d098ebbf98575a1e1ba2ee7d7005b697af1721d5`;
  checksum confirmado também na [documentação oficial de integridade da
  Zorin](https://help.zorin.com/docs/getting-started/check-the-integrity-of-your-copy-of-zorin-os/).
  **Não confundir a autenticação histórica do mapa com uma nova autenticação
  integral dos bytes da ISO nesta execução.**
- Instalação Ubiquity da ISO: `24.04.5+zorin2`;
  `usr/bin/ubiquity` SHA
  `5819ac97c623085d08e55c08afc12e7d70be98795e603b27807bea165fad0b1b`.

## Reprodução exata da lacuna

O ZIP original, analisado por `auto_tests/tools/zorin_ubiquity_source_coverage.py`,
**não contém o corpo de qualquer módulo**. Os seguintes seis módulos apresentam
fingerprint de **ficheiro regular/owner validado anteriormente**, mas apenas
metadata `path/size/sha256`, nunca o texto do programa:

| Módulo | SHA-256 histórico do corpo (não reextraído do ZIP) |
| --- | --- |
| `usr/bin/ubiquity` | `5819ac97c623085d08e55c08afc12e7d70be98795e603b27807bea165fad0b1b` |
| `usr/lib/ubiquity/plugins/ubi-partman.py` | `295e4785bb9477f00c3df565a4698635631d36c5c74f40b87d302578c3a6e50f` |
| `usr/lib/ubiquity/ubiquity/parted_server.py` | `5e20b10341852549ffcc5620fd0eeb35600fba0a7e84d1b306027ad8b82b7952` |
| `usr/lib/ubiquity/ubiquity/components/partman_commit.py` | `3de7e27675e1875848c4abc50b40742c5f3c68e92d7b23f54001839851527322` |
| `usr/lib/ubiquity/ubiquity/components/grubinstaller.py` | `4f2b1e80d5401abf9164f534044162483f6d37df730dff7842ec1d651fad5579` |
| `usr/share/ubiquity/plugininstall.py` | `bf3d60094d1ab2609b6260a61b675581a5efb79f7044a0c0383f3733e52e3b20` |

**Ficheiros ausentes da autenticação histórica como regulares:**
`lib/partman/lib/commit.sh` e `lib/partman/lib/resize.sh`.
Fazem parte dos **dez candidatos não atestados** em `lib/partman/lib/`.
Sem a ISO não se pode determinar legitimamente se são ficheiros ausentes,
symlinks ou não regulares; um caminho listado não constitui fonte autenticada.

A reprodução é verificável: obter o ZIP original da Actions e aplicar
`open_pinned_archive()` e `report_gap()`. O relatório resultante deve
reconhecer todos os oito corpos como `BODY_NOT_AVAILABLE`, preservar os
hashes históricos dos seis regulares e `knownSha256=null` para os dois
não autenticados, sem promover um dry-run.

## Inspeção estritamente direcionada da ISO (condicionada à disponibilidade)

O segundo job de
[`.github/workflows/zorin-ubiquity-source-coverage.yml`](../.github/workflows/zorin-ubiquity-source-coverage.yml)
tenta utilizar **apenas** a ISO de URL e digest fixados em
`windows_zorin_synthetic_cow_root.py`. Antes de ler qualquer membro,
valida tamanho e **SHA-256 integral**, ambiente isolado GitHub-hosted,
montagem ISO9660 `ro,nosuid,nodev,noexec`, raiz SquashFS não-symlink e
caminhos exatos da allowlist. Reutiliza `require_regular_member` e
`read_member` da PR #264: nenhum executável ou script extraído é iniciado.
Compara os seis SHA originais e mede novos hashes apenas para membros
adicionais **comprovadamente regulares** na ISO fixada. Não publica os corpos,
apenas metadados e callsites AST estáticos. Se falhar a obtenção da ISO ou a
identidade, a inspeção **não** ocorre; a conclusão continua ROUTE B.

A procura está limitada aos **oito caminhos acima**, não reinventa nem
repete a enumeração dos 58 ficheiros. Não abre dispositivos físicos, não
monta partições Windows e não arranca QEMU.

## Fronteiras A–G e efeitos

A — `usr/bin/ubiquity`: corpo identificado por SHA, **ordem de enumeração
de discos ainda não comprovada**.

B/C — `ubi-partman.py`, `parted_server.py`: mapeamento estático de
seleção do alvo e lógica partman. Possíveis subprocessos/chamadas externas
antes de `partman_commit` não são autorizados. Diferenciar write em memória
de commit persistente exige análise causal dos corpos e das bibliotecas
externas, não apenas correspondência de tokens.

D — **Primeira mutação persistente exata: não demonstrável com o ZIP original.**
O corpo de `lib/partman/lib/resize.sh` não foi atestado; qualquer resize
ou partman externo pode alterar filesystem/partições antes de um commit
assumido por conveniência.

E/F — `partman_commit.py`, `lib/partman/lib/commit.sh`: nome e referências
de commit não provam que esta seja a primeira escrita; formatação
`mkfs`, `wipefs`, alterações GPT e outras dependências externas não têm
ordem completa autenticada.

G — `grubinstaller.py`, `plugininstall.py`: referências a GRUB e EFI,
sem garantias de `EFI/Microsoft`, variáveis NVRAM ou BootOrder/BootNext.

O grafo produzido pelo scanner a partir de corpos eventualmente extraídos
é de `STATIC_AST_CALLSITE_NOT_A_TRACE`; símbolos Python, shell dinâmico,
subprocessos e módulos externos não constituem um grafo de execução completo.
**Nunca marcar `firstPersistentMutationLocated=true`, nem uma API dry-run
ou de ação pré-commit verificada a partir desse resultado.**

## Alternativa existente e próximos gates

A [decisão #339](ZORIN_UBIQUITY_PRECOMMIT_DECISION.md) compara o backend
Gaslux Debian/Ubuntu: `libertix-install-main.sh` faz preflight e extrai
SquashFS para destino, `configure-target-main.sh` configura utilizador,
locale, initramfs e GRUB, `libertix-uefi-adapter.sh` gere artefactos
identificados e `libertix-rollback-common.sh` tenta recuperação.
Essa sequência **não demonstra** instalação nativa completa, arranque
Windows/Zorin após updates nem rollback real. Não reimplementar Mint e
não tratar cópia da rootfs live como prova de instalação nativa.

A futura análise Safety deverá observar o *primeiro efeito persistente*
sob uma política HOST/FD autenticada, com origens físicas verificáveis,
bloqueio de quaisquer escritas antes dos gates, recuperação funcional
restaurável e testes em VM descartável. **Até lá, DENY_NO_WRITER.**
