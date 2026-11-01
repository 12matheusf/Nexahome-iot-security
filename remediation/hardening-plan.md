# Plano de hardening — NexaSense versão comercial

Conceitual: nada aqui exige queimar eFuses durante a atividade. Referências: ESP-IDF Security, ETSI EN 303 645, NIST IR 8259A, MITRE EMB3D.

| Prio | Medida | Achados | Referência | Observação |
|---|---|---|---|---|
| P0 | MQTT sobre TLS (8883), validação de certificado, mTLS por dispositivo | F02 | ETSI 5.5 | Certificado único por unidade na produção |
| P0 | Credenciais únicas por dispositivo; remover senhas padrão e segredos do binário | F01, F07 | ETSI 5.1 | Provisionar na fábrica, armazenar em NVS cifrada |
| P0 | OTA por HTTPS + imagem assinada + verificação obrigatória | F03 | ETSI 5.3, NIST 8259A | Anti-rollback; manter partição anterior |
| P1 | Secure Boot v2 | F03, F05 | ESP-IDF | Chave de assinatura em HSM; gestão de chaves definida antes de queimar eFuse |
| P1 | Flash Encryption (modo release) | F01, F05 | ESP-IDF | Cuidado: operação irreversível; testar em unidades de desenvolvimento |
| P1 | Desabilitar JTAG por eFuse e restringir modo de download UART | F05, F06 | ESP-IDF, EMB3D | |
| P1 | ACL no broker, `allow_anonymous=false`, um tópico por dispositivo | F04 | NIST 8259A | |
| P2 | Console/shell desativados, nível de log mínimo, sem caminhos de build | F06 | OWASP ISTG | Remover/proteger pads de debug na PCB |
| P2 | Remover interface /debug de produção | F07 | ETSI 5.6 (reduzir superfície) | |
| P2 | Recuperação de falha de OTA (A/B + rollback) e telemetria de estado de segurança | F03 | NIST 8259A | |
| P3 | Processo: threat model (EMB3D), revisão de segurança por release, política de divulgação de vulnerabilidades e suporte de atualização | todos | ETSI 5.2, 5.3 | |

## Lição do caso real (CVE-2019-15894)
Secure Boot sozinho pode ser contornado por *fault injection* com acesso físico; a Espressif orienta combinar com Flash Encryption e usar chips/ESP-IDF atualizados. Em produto real: defesa em profundidade, não um controle único.

## Status de validação no laboratório
| Medida | Validada? | Como |
|---|---|---|
| TLS no MQTT | Sim | `hardened/evidence/mqtt_tls_hardened.pcap`: sem senha/telemetria em claro |
| Login por dispositivo + sem anônimo | Sim | testes T1/T2 em `hardened/evidence/hardened_results.txt` |
| ACL por tópico | Sim | teste T5 (publicação em tópico alheio bloqueada) |
| OTA assinada | Parcial (modelo) | `firmware/signing/signing-demo-output.txt`; verificação simulada em Python |
| Secure Boot / Flash Encryption / JTAG off | Não (conceitual) | exigem eFuses irreversíveis; não foram gravadas |
