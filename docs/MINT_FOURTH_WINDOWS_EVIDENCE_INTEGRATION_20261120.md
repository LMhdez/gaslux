# Integração de provas Mint/Windows — 20-11-2026

Proveniência:
- PR #204 `test/mint-win10-fourth-bcd-winre-evidence-20261118` @ `11b44063dd14e8c88f962043520e26d9dde14841`.
- PR #233 `fix/mint-shutdown-witness-kernel-powerdown-20261119` @ `7521e91f819c4c00b6acaf7502693181604a1d44` antes desta integração.

O validador mais recente da #233 preserva os padrões de encerramento de sistema completos e ancorados em linhas; os padrões permissivos antigos **não** são reintroduzidos.

Foram importadas e adaptadas as verificações da quarta prova Windows da #204: digest SHA-256 do relatório, ficheiros regulares limitados, log/sidecar ligados ao JSON, arranque único do Windows Boot Manager, marcadores independentes e únicos de ESP/BCD/WinRE/GPT, recusa de falhas e de alegações de dual boot ou rollback não provados. Acrescentam-se testes de adulteração, ausência, repetição e ligação de artefactos.

Compatibilidade: a prova do quarto arranque é **obrigatória quando for alegada** no relatório; perfis históricos sem a alegação não são promovidos e devolvem `windowsEspBcdWinreFourthBootVerified: false`. Artefactos de quarto arranque presentes mas não vinculados ao relatório são recusados. Isto evita apresentar provas antigas como uma instalação nativa concluída.

Esta integração **não** demonstra arranque real Mint/Windows, segurança de escrita no disco, instalação, atualizações ou rollback; esses critérios permanecem pendentes. A experiência de descarte COW/guestfs da #204 continua nessa PR para revisão separada; a branch não é eliminada sem essa decisão.
