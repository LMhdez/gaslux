# Consolidação HMP e VNC — 20-11-2026

Origem: draft PR #217 `fix/windows-hmp-native-com1-regressions-20261118` @ `8c88c4d91f16dbf5a196adc54408ac0400d34610`.

Destino: draft PR #216 `fix/windows-vnc-owned-unix-consolidation-20261118` @ `6553db1dcd68656e32a291d3214469c1fdf233f1` antes da integração.

A versão anterior aceitava uma só chamada `recv()` para banner e outra para confirmação HMP. O protocolo usa um stream de bytes, pelo que um fragmento pode produzir um falso sucesso. A correção da #217 exige leitura limitada a 128 KiB até ao prompt terminal completo, recusa de desconexão e de erros do monitor. São importados quatro testes sobre fragmentação, erro, desconexão e falso prompt no texto.

A implementação VNC local, a verificação de propriedade do socket e as restrições a ambientes GitHub-hosted permanecem. O workflow tem permissões de leitura e testes sem disco, incluindo QEMU HMP real sem ISO, Windows ou disco.

Estas provas confirmam apenas ACK do comando HMP; não confirmam entrega ao firmware, arranque Windows/Linux, atualizações ou rollback. Os trabalhos distintos de COM1 e one-shot da #217 permanecem nessa origem; não fechar a PR nem apagar a branch com base nesta integração parcial.
