# Achados (findings)

> **Dois conjuntos:** `R01–R04` têm evidência REAL (firmware oficial do Tasmota executado em ESP32 emulado). `F01–F07` pertencem ao cenário didático NexaSense (firmware e dispositivo SIMULADOS; ver README).

> Escala: Impacto e Probabilidade ∈ {Baixa/Baixo, Média, Alta}; Risco = matriz 3×3 (ver abaixo).

| Prob \ Impacto | Baixo | Médio | Alto |
|---|---|---|---|
| **Alta** | Médio | Alto | Alto |
| **Média** | Baixo | Médio | Alto |
| **Baixa** | Baixo | Baixo | Médio |

## Tabela resumida

| ID | Achado | Evidência | Impacto | Prob. | Risco | Recomendação |
|---|---|---|---|---|---|---|
| F01 | Segredos em texto claro no firmware, NVS e partição config | firmware/analysis-output.txt: wifi.sta.pass, api.token, mqtt password e admin:admin legíveis com strings; entropia 0,007 bits/byte (imagem não cifrada) | Alto | Média | Alto | Flash Encryption; credenciais por dispositivo provisionadas na produção; nada de segredo no binário |
| F02 | MQTT sem TLS e credenciais em claro no CONNECT | network/evidence/pcap_analysis.txt: CONNECT com usuário nexasense e senha Mqtt#Lab123 visíveis; telemetria JSON em claro | Alto | Média | Alto | MQTT sobre TLS (8883) com validação de certificado; mTLS por dispositivo |
| F03 | Atualização OTA via HTTP, sem assinatura e sem validação de certificado | strings: 'ota: update url=http://...', 'signature verification SKIPPED', 'TLS cert verification disabled'; config verify_signature=false | Alto | Média | Alto | HTTPS com pinning + imagem assinada + Secure Boot v2 + rollback protegido |
| F04 | Broker aceita assinante anônimo e sem ACL (configuração do laboratório) | network/evidence/anonymous_subscriber.txt: 4 mensagens de telemetria lidas sem credencial | Médio | Alta | Alto | allow_anonymous=false; ACL por clientid; um tópico por dispositivo |
| F05 | Secure Boot e Flash Encryption desativados; JTAG habilitado | bootloader: 'secure boot: disabled', 'flash encryption: disabled'; 'efuse: JTAG_DISABLE=0' | Alto | Baixa | Médio | Habilitar Secure Boot v2 + Flash Encryption (modo release) e desabilitar JTAG via eFuse na versão comercial |
| F06 | UART0 com shell de diagnóstico e log de boot verboso | hardware/evidence/uart_boot_SIMULATED.log (simulado a partir de strings reais do firmware): senha MQTT impressa no boot, prompt de shell | Médio | Média | Médio | Desativar console/shell em produção, reduzir nível de log, remover pads ou protegê-los |
| F07 | Página /debug HTTP com credencial padrão admin:admin (indício) | string 'web: http://192.168.56.20/debug admin:admin' no firmware. NÃO validado dinamicamente no laboratório | Alto | Média | Alto (a confirmar) | Remover a interface de produção; sem senhas padrão (credencial única por dispositivo) |

## Cadeia evidência → mitigação

### F01 — Segredos em texto claro no firmware, NVS e partição config
- **Evidência:** firmware/analysis-output.txt: wifi.sta.pass, api.token, mqtt password e admin:admin legíveis com strings; entropia 0,007 bits/byte (imagem não cifrada)
- **Fragilidade:** Credenciais embarcadas e Flash Encryption desativada
- **Ameaça possível:** Atacante com acesso físico ou à imagem OTA extrai credenciais
- **Impacto / Probabilidade / Risco:** Alto / Média / **Alto**
- **Mitigação:** Flash Encryption; credenciais por dispositivo provisionadas na produção; nada de segredo no binário
- **Referências:** ETSI 5.1/5.4; NIST 8259A (proteção de dados); EMB3D (extração de firmware)

### F02 — MQTT sem TLS e credenciais em claro no CONNECT
- **Evidência:** network/evidence/pcap_analysis.txt: CONNECT com usuário nexasense e senha Mqtt#Lab123 visíveis; telemetria JSON em claro
- **Fragilidade:** Porta 1883 sem criptografia
- **Ameaça possível:** Sniffing / MITM na mesma rede
- **Impacto / Probabilidade / Risco:** Alto / Média / **Alto**
- **Mitigação:** MQTT sobre TLS (8883) com validação de certificado; mTLS por dispositivo
- **Referências:** ETSI 5.5; NIST 8259A (proteção de dados); OWASP ISTG (rede)

### F03 — Atualização OTA via HTTP, sem assinatura e sem validação de certificado
- **Evidência:** strings: 'ota: update url=http://...', 'signature verification SKIPPED', 'TLS cert verification disabled'; config verify_signature=false
- **Fragilidade:** Integridade do firmware não verificada
- **Ameaça possível:** Imagem maliciosa entregue por MITM ou servidor comprometido
- **Impacto / Probabilidade / Risco:** Alto / Média / **Alto**
- **Mitigação:** HTTPS com pinning + imagem assinada + Secure Boot v2 + rollback protegido
- **Referências:** ETSI 5.3; NIST 8259A (atualização de software); ESP-IDF Secure Boot

### F04 — Broker aceita assinante anônimo e sem ACL (configuração do laboratório)
- **Evidência:** network/evidence/anonymous_subscriber.txt: 4 mensagens de telemetria lidas sem credencial
- **Fragilidade:** Sem autenticação e sem controle de acesso por tópico
- **Ameaça possível:** Leitura (e potencial publicação) em tópicos de qualquer dispositivo
- **Impacto / Probabilidade / Risco:** Médio / Alta / **Alto**
- **Mitigação:** allow_anonymous=false; ACL por clientid; um tópico por dispositivo
- **Referências:** NIST 8259A (controle de acesso); ETSI 5.1, 5.5

### F05 — Secure Boot e Flash Encryption desativados; JTAG habilitado
- **Evidência:** bootloader: 'secure boot: disabled', 'flash encryption: disabled'; 'efuse: JTAG_DISABLE=0'
- **Fragilidade:** Sem raiz de confiança nem proteção da flash
- **Ameaça possível:** Dump/regravação da flash e depuração via JTAG por quem tem a placa
- **Impacto / Probabilidade / Risco:** Alto / Baixa / **Médio**
- **Mitigação:** Habilitar Secure Boot v2 + Flash Encryption (modo release) e desabilitar JTAG via eFuse na versão comercial
- **Referências:** ESP-IDF Security; EMB3D; caso CVE-2019-15894

### F06 — UART0 com shell de diagnóstico e log de boot verboso
- **Evidência:** hardware/evidence/uart_boot_SIMULATED.log (simulado a partir de strings reais do firmware): senha MQTT impressa no boot, prompt de shell
- **Fragilidade:** Console de debug ativo em produção
- **Ameaça possível:** Acesso físico ao UART revela segredos e permite comandos
- **Impacto / Probabilidade / Risco:** Médio / Média / **Médio**
- **Mitigação:** Desativar console/shell em produção, reduzir nível de log, remover pads ou protegê-los
- **Referências:** OWASP ISTG (interfaces físicas); EMB3D (interfaces privilegiadas expostas)

### F07 — Página /debug HTTP com credencial padrão admin:admin (indício)
- **Evidência:** string 'web: http://192.168.56.20/debug admin:admin' no firmware. NÃO validado dinamicamente no laboratório
- **Fragilidade:** Credencial padrão universal
- **Ameaça possível:** Acesso à interface de depuração pela rede
- **Impacto / Probabilidade / Risco:** Alto / Média / **Alto (a confirmar)**
- **Mitigação:** Remover a interface de produção; sem senhas padrão (credencial única por dispositivo)
- **Referências:** ETSI 5.1 (sem senhas padrão universais)


---

## Achados com evidência real (Tasmota32 em ESP32 emulado)

| ID | Achado | Evidência | Impacto | Prob. | Risco | Recomendação |
|---|---|---|---|---|---|---|
| R01 | Imagem de aplicação sem assinatura (sem bloco Secure Boot v2) | firmware/real/real-analysis-output.txt: 36 bytes após os segmentos (padding+hash); imagem assinada teria +4096 bytes | Alto | Baixa | Médio | Habilitar Secure Boot v2 e assinar as imagens no build de produção |
| R02 | Flash não cifrada: conteúdo legível na imagem | firmware/real/flash-analysis-output.txt: entropia 6,98 bits/byte; ~11 mil strings legíveis (URLs, nomes de parâmetros, formulários) | Médio | Média | Médio | Flash Encryption (release) e NVS cifrada. Observação: a imagem de fábrica analisada não contém segredos reais |
| R03 | URLs de OTA padrão em HTTP (strings do firmware) | strings: http://ota.tasmota.com/tasmota32/release/tasmota32.bin e ...-safeboot.bin | Alto | Baixa | Médio (a confirmar) | OTA por HTTPS com validação de certificado e imagem assinada |
| R04 | Boot na UART expõe versão exata, hardware e estado de configuração, sem autenticação | hardware/evidence/uart_boot_REAL_QEMU_tasmota.log: 'Tasmota Version 16.0.0 … (2026-10-16)', 'ESP32-D0WDQ6', 'CFG: Use defaults', 'WifiManager active for 3 minutes' | Baixo | Média | Baixo | Reduzir log em produção e proteger/remover os pads de UART |

**Não é achado:** o `panic` ao iniciar o Wi-Fi na captura da UART é limitação do QEMU (periférico Wi-Fi não emulado). **Não avaliável no emulador:** estado real das eFuses (Secure Boot, Flash Encryption, JTAG).
