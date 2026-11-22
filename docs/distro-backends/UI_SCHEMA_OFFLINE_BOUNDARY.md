# Contratos estáticos de evidência UI Q4OS — sem autoridade operacional

Origem: [PR #258](https://github.com/LMhdez/gaslux/pull/258) e
[PR #270](https://github.com/LMhdez/gaslux/pull/270), versão de schemas
fixada em `ea4bc70a3aac0e618372cc8cc12bb2f54e09c56f`. Os oito dossiers e a proveniência documental
já entraram em `dev` através da [PR #282](https://github.com/LMhdez/gaslux/pull/282);
não são duplicados.

Esta extração inclui **apenas** dois JSON Schemas históricos e testes negativos
offline. O esquema de mapa documenta observações de Q4OS em VMs descartáveis e
exige `windowsDiskAttached=false`, `nativeCalamaresInstallExecuted=false` e
`windowsDiskModified=false`. Um schema válido não autentica automaticamente
o ficheiro ou o ambiente que o preenche.

**Não incluído:** mapas de coordenadas, arquivos históricos/screenshot fixtures,
controlo de VNC, `controller_lease`, `input`, transportes, comandos QMP,
workflows de QEMU/Windows, ISO, catálogos, estratégias de instalação,
alterações de discos ou provas de rollback.

O nome de workflow histórico que aparece nos schemas é apenas uma referência
de proveniência; não é instalado nem ativado por esta integração. Estes schemas
não podem ser usados como prova de instalação nativa, input autorizado,
dual boot, primeiro arranque ou recuperação Windows. Proveniência dos
artefactos, assinaturas, permissões e autorização de escrita permanecem
gates separados. A linha #259 e correções Observer posteriores conservam
os seus próprios mecanismos fail-closed; nenhum é substituído aqui.

Testar apenas: `python -m pytest -q auto_tests/tests/test_distro_ui_schema_offline.py`.
Generated-by: GPT-6.
