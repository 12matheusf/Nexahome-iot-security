# Notas de análise do firmware

Script: `python3 lab/analyze_firmware.py` → `firmware/analysis-output.txt` (saída completa) e `firmware/hashes.txt`.

## Preservação (Etapa 2)
- Original: `firmware/nexasense_lab_fw.bin` (4.194.304 bytes), marcado somente-leitura.
- SHA-256: `acaa7151e2a60c3117a7b15ce7d72893127f7fe94fd9bf0a7723f985803cbef4`
- Cópia de trabalho com hash idêntico verificado em `firmware/work/`; toda análise ocorre nela.

## Estrutura
| Partição | Offset | Tamanho | Observação |
|---|---|---|---|
| bootloader | 0x1000 | — | magic 0xE9; imprime "secure boot: disabled / flash encryption: disabled" |
| partition table | 0x8000 | — | 5 entradas (magic 0xAA50) |
| nvs | 0x9000 | 0x6000 | Wi-Fi SSID/senha, device.id, api.token em claro |
| otadata | 0xF000 | 0x2000 | |
| phy_init | 0x11000 | 0x1000 | |
| factory (app) | 0x20000 | 0x180000 | strings de debug, endpoints, credenciais |
| config | 0x1A0000 | 0x40000 | JSON com mqtt.tls=false, ota.verify_signature=false |

Entropia global 0,007 bits/byte: a imagem **não** está cifrada (uma flash cifrada ficaria próxima de 8).

## Informações relevantes → achado
| Informação | Achado |
|---|---|
| wifi.sta.pass, api.token, mqtt pass, admin:admin | F01, F07 |
| mqtt://…:1883, tls:false | F02 |
| ota http://, signature SKIPPED, cert verification disabled | F03 |
| secure boot/flash encryption disabled, JTAG_DISABLE=0 | F05 |
| DEBUG console on UART0, shell | F06 |
| Caminho `/home/dev/nexasense/main/sensor.c:142` (assert) | vazamento de informação do build (baixo) |

> Os valores são **fictícios**, criados para o laboratório. Não os reutilize em sistemas reais.
