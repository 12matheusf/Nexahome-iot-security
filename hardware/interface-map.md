# Mapa de interfaces físicas

> Origem dos dados: strings do firmware educacional + documentação do ESP32. **Pendente (se tiver a placa):** fotos, medição do pinout e captura real da UART em `hardware/evidence/`.

| Interface | Pinos / parâmetros | O que permite | Proteção observada | Risco se permanecer em produto | Classificação |
|---|---|---|---|---|---|
| UART0 | TX=GPIO1, RX=GPIO3, 115200 8N1 | Ler log de boot; acessar shell de diagnóstico; modo de download do ROM | Nenhuma (console ativo, sem senha) | Vazamento de segredos (F06) e execução de comandos por quem tem acesso físico | **Exposição relevante** (contexto: atacante com a placa) |
| JTAG | MTDI=12, MTCK=13, MTMS=14, MTDO=15; `JTAG_DISABLE=0` | Depurar, ler/escrever memória, pausar CPU | eFuse não queimado | Leitura de RAM/flash e controle do dispositivo | **Exposição relevante** |
| SPI flash | Barramento interno MCU↔flash | Dump da imagem (clip no chip) | Flash Encryption desativada | Extração completa de firmware e segredos (F01, F05) | **Exposição relevante** |
| I²C | SHT31 @0x44 | Falar com o sensor | N/A (barramento interno) | Baixo: falsificar leituras exigiria acesso físico invasivo | Baixa relevância |
| Pontos de teste / USB-serial | A confirmar na placa | — | — | — | Verificar na placa real |

**Nota metodológica:** interface acessível ≠ vulnerabilidade. Aqui a classificação decorre da *combinação* interface + ausência de proteção (eFuse/Flash Encryption/console) + impacto (credenciais compartilhadas que dão acesso ao broker).
