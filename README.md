# NexaHome — Avaliação de segurança do NexaSense (IoT / ESP32)

**Autor:** Matheus Ferreira Vieira · RA 99693

> **Aviso de transparência (leia primeiro):** nenhum firmware ou placa foi fornecido para a atividade. Por isso há **três camadas de evidência**, identificadas por rótulo:
> 1. **Didática/simulada** — firmware `nexasense_lab_fw.bin` gerado por `lab/build_lab_firmware.py`, dispositivo e broker em Python, log `uart_boot_SIMULATED.log`; credenciais fictícias. Demonstra a metodologia, a captura de tráfego e as mitigações (achados `F01–F07`).
> 2. **Firmware real em ESP32 emulado (reproduzido e conferido com binwalk/strings na VM Kali, ver `firmware/real/kali_crosscheck.txt`)** — release oficial do Tasmota32 executada no QEMU da Espressif (`lab/run_qemu_tasmota.sh`), com análise da flash e log de UART verdadeiros, mas **sem placa física** (achados `R01–R04`; `hardware/evidence/uart_boot_REAL_QEMU_tasmota.log`).
> 3. **Placa física (opcional)** — só se você tiver uma ESP32: siga `GUIA_ESP32.md` e substitua/complemente as evidências acima.
> Não apresente as camadas 1 e 2 como medição de hardware real.

> **Execução com hardware real:** ver `GUIA_ESP32.md` (dump da flash, eFuses, UART, captura do tráfego da placa) e o firmware em `firmware/educational/nexasense_proto/`.

## 1. Objetivo
Avaliar o protótipo NexaSense antes do piloto: mapear superfície de ataque, analisar firmware, interfaces físicas e comunicações, classificar riscos e propor hardening.

## 2. Dispositivo, escopo e limites
ESP32 (4 MB de flash), sensor SHT31 (I²C), Wi-Fi, MQTT, OTA e interface de debug. **Escopo:** apenas o dispositivo/firmware de laboratório e rede local (loopback). **Fora de escopo:** dispositivos de terceiros, serviços externos, internet, queima de eFuses, descompilação avançada.

## 3. Arquitetura
Ver `architecture/architecture-diagram.png` (fonte `architecture.dot`). Fluxo: Sensor → MCU/Flash/UART/JTAG → Firmware → Wi-Fi → MQTT/OTA/HTTP → Broker → Plataforma.

## 4. Ferramentas
Python 3, `hashlib`, `strings`/regex, Scapy (captura/pcap), `amqtt` (broker), `paho-mqtt` (cliente), Graphviz. Com hardware real: `esptool`, adaptador USB-serial, `screen/minicom`, Wireshark.

## 5. Organização das evidências
| Pasta | Conteúdo |
|---|---|
| `architecture/` | diagrama |
| `firmware/` | imagem original (RO), `hashes.txt`, `analysis-output.txt`, `analysis-notes.md` |
| `hardware/` | `interface-map.md`, `evidence/` |
| `network/` | `protocol-analysis.md`, `evidence/` (pcap, saída) |
| `findings/` | `findings.md` / `findings.json` |
| `remediation/` | `hardening-plan.md` |
| `lab/` | scripts de reprodução |

## 6. Resumos
- **Firmware:** SHA-256 `acaa7151…cbef4`; 5 partições; imagem não cifrada (entropia 0,007); Secure Boot e Flash Encryption desativados; segredos, endpoints, OTA sem assinatura em texto claro.
- **Hardware:** UART0 com shell/log verboso, JTAG habilitado, flash sem criptografia → exposição relevante considerando atacante com acesso físico.
- **Protocolos:** MQTT/1883 sem TLS; credenciais visíveis no CONNECT; broker de laboratório aceita assinante anônimo.

## 7. Demonstração controlada
`python3 lab/run_network_lab.py`: as credenciais MQTT são **extraídas do firmware** e a telemetria é lida de um assinante **sem credenciais**; o pcap mostra a senha em claro. Evidências: `network/evidence/` (inclui `print_execucao_windows_01-11-2026.png`, execução em Windows com Npcap 1.90).

## 7b. Validação das mitigações (hardened) e firmware real
- **Hardened (`python3 lab/run_hardened_lab.py`):** broker com TLS (8883), login por dispositivo (Argon2) e ACL por tópico. 7 testes: anônimo recusado, senha errada recusada, MQTT em claro recusado, publicação legítima entregue, publicação em tópico de outro dispositivo bloqueada, **captura sem senha/telemetria em claro**, tráfego TLS confirmado. Evidências: `hardened/evidence/`.
- **Assinatura de firmware (`python3 lab/firmware_signing_demo.py`):** Ed25519; imagem com 1 bit alterado ou endpoint trocado é rejeitada no modo hardened e aceita no modo inseguro. Evidência: `firmware/signing/signing-demo-output.txt`. *O "dispositivo" é um modelo em Python do comportamento de verificação, não um ESP32 real.*
- **Firmware real público (`python3 lab/analyze_real_firmware.py`):** o mesmo método aplicado ao `tasmota32.bin` oficial (release pública do projeto Tasmota, ESP32, ESP-IDF 5.5.5). Para reproduzir, baixe `https://github.com/arendst/Tasmota/releases/latest/download/tasmota32.bin` para `firmware/real/tasmota32_release.bin` (o hash muda a cada release; o do relatório está registrado em `firmware/real/real-analysis-output.txt`). Evidência: `firmware/real/real-analysis-output.txt`.

## 8. Principais achados
| ID | Achado | Risco |
|---|---|---|
| F01 | Segredos em claro no firmware/NVS | Alto |
| F02 | MQTT sem TLS, senha em claro | Alto |
| F03 | OTA sem assinatura/TLS | Alto |
| F04 | Broker anônimo, sem ACL (lab) | Alto |
| F05 | Secure Boot/Flash Enc. off, JTAG on | Médio |
| F06 | UART com shell/log verboso | Médio |
| F07 | /debug admin:admin (indício, não validado) | Alto (a confirmar) |

## 9. Recomendações
Ver `remediation/hardening-plan.md` (TLS+mTLS, credenciais por dispositivo, OTA assinada, Secure Boot v2, Flash Encryption, JTAG off, ACL, console off).

## 10. Reprodução (ambiente autorizado)
```bash
git clone <repo> && cd nexahome-iot-security
sudo ./lab/run_all.sh
```
Não publique credenciais reais. Os valores deste repositório são fictícios.

## 11. Vídeo
Link: `<COLE AQUI O LINK NÃO LISTADO>` — roteiro em `video-roteiro.md`.
