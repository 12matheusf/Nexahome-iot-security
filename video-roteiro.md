# Roteiro do vídeo (≤ 4:00)

| Tempo | Tela | Fala (resumo) |
|---|---|---|
| 0:00–0:20 | Placa/ESP32 (ou diagrama) + README | “Sou analista de segurança IoT; avaliei o NexaSense da NexaHome, apenas em ambiente autorizado.” |
| 0:20–0:50 | `architecture-diagram.png` | Componentes, fluxo e as 3 superfícies: física, firmware, rede. |
| 0:50–1:30 | Terminal: `python3 lab/analyze_firmware.py` | Hash SHA-256, cópia de trabalho, partições, entropia baixa; strings com segredos/OTA. |
| 1:30–2:05 | `hardware/interface-map.md` + `uart_boot_REAL_QEMU_tasmota.log` (ou `uart_boot_REAL.log` se tiver placa) | UART/JTAG: o que permitem e por que o contexto importa. Dizer que o firmware é real, mas o ESP32 é emulado (QEMU); o panic do Wi-Fi é limitação do emulador. |
| 2:05–2:50 | Terminal: `python3 lab/run_network_lab.py` + `analyze_pcap.py` | **Demonstração:** credenciais extraídas do firmware; senha visível no pcap; assinante anônimo lê telemetria. |
| 2:50–3:05 | `findings.md` (tabela) | Principais riscos F01–F03 e classificação impacto×probabilidade. |
| 3:05–3:30 | Terminal: `run_hardened_lab.py` | **Antes × depois:** 7/7 testes; capturar no Wireshark a porta 8883 cifrada vs. 1883 em claro. |
| 3:30–3:50 | `hardening-plan.md` + caso CVE-2019-15894 | Medidas validadas e conceituais; lição do caso real. |
| 3:50–4:00 | Fechamento | “Metodologia: evidência → risco → mitigação.” |

Dica: grave a tela (OBS) e narre; se usar placa física, mostre-a no início. Publique como *não listado* e cole o link no README e no relatório. **Declare no vídeo que o laboratório é simulado, se for o caso.**
