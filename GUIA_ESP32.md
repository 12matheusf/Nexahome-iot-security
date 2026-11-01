# Guia: transformar o laboratório em avaliação REAL com sua ESP32 (Windows)

**Regras de segurança:** só a sua placa e a sua rede (use o *hotspot* do celular em 2,4 GHz com uma senha descartável; nunca a rede da faculdade ou de produção). Use **somente leitura** nas eFuses (`summary`); **nunca** `espefuse burn`, pois é irreversível.

Todos os comandos no cmd, na pasta interna do projeto: `cd C:\Users\mathe\Downloads\nexahome-iot-security\nexahome-iot-security` (use `py -3.12`).

## 0. Preparação
1. Instale o driver USB-serial da placa (CP210x ou CH340, o chip aparece perto da porta USB). Conecte por um cabo USB **de dados**.
2. Anote a porta em *Gerenciador de Dispositivos > Portas (COM e LPT)*, por exemplo `COM5`.
3. `py -3.12 -m pip install -r requirements.txt esptool pyserial`
4. `mkdir hardware\evidence firmware\real_board`
5. **Tire fotos** da placa (frente e verso): módulo ESP32, chip de flash, USB-serial, botões EN/BOOT, pinos TX0/RX0 (GPIO1/GPIO3) e pinos 12–15 (JTAG). Salve em `hardware\evidence\`.

## 1. Etapa 1: reconhecimento do hardware (evidência real)
```
py -3.12 -m esptool --port COM5 chip_id  > hardware\evidence\esptool_chip_id.txt
py -3.12 -m esptool --port COM5 flash_id > hardware\evidence\esptool_flash_id.txt
py -3.12 -m espefuse --port COM5 summary > hardware\evidence\efuse_summary.txt
```
Isso mostra o chip, as *features*, o MAC, o tamanho da flash e o estado real das eFuses (JTAG, Secure Boot, Flash Encryption). É a base do achado F05 com dados reais.
> Se der "Failed to connect": segure o botão **BOOT** ao iniciar o comando, troque o cabo ou revise o driver.

## 2. Etapa 2: preservar o firmware ORIGINAL da placa (antes de gravar qualquer coisa)
```
py -3.12 -m esptool --port COM5 read_flash 0 0x400000 firmware\real_board\dump_original.bin
py -3.12 lab\analyze_firmware.py firmware\real_board\dump_original.bin
```
`0x400000` é para 4 MB; use o tamanho que o `flash_id` informou. Isso gera `hashes.txt` e `analysis-output.txt` ao lado do dump.

## 3. Gravar o firmware educacional (dispositivo "NexaSense")
1. No VS Code, instale a extensão **PlatformIO IDE** e abra `firmware\educational\nexasense_proto`.
2. Edite `src/main.cpp`: `WIFI_SSID`, `WIFI_PASS`, `MQTT_HOST` (IPv4 do notebook, via `ipconfig`) e o IP em `OTA_URL`.
3. Clique em *Upload* (seta →) ou use `py -3.12 -m platformio run -t upload --upload-port COM5`.
4. Dump do dispositivo já com o firmware: `py -3.12 -m esptool --port COM5 read_flash 0 0x400000 firmware\real_board\dump_nexasense.bin` e depois `py -3.12 lab\analyze_firmware.py firmware\real_board\dump_nexasense.bin`.
   Procure no `analysis-output.txt` o SSID/senha do Wi-Fi (guardados na NVS), as credenciais MQTT, a URL de OTA e a ausência de proteções.

## 4. Etapa 4: UART real
Feche qualquer monitor serial aberto e rode:
```
py -3.12 lab\capture_uart.py COM5 --seconds 25 --commands
```
Isso reinicia a placa, grava o log de boot e envia `help`, `info`, `wifi` e `mqtt` à shell de diagnóstico, que não tem senha e imprime os segredos. A saída vai para `hardware\evidence\uart_boot_REAL.log`. Apague `uart_boot_SIMULATED.log` ao terminar.

## 5. Etapa 5/6: comunicação e demonstração controlada (real)
1. Libere o Python no firewall do Windows (rede **privada**) para a porta 1883.
2. Descubra o nome da interface Wi-Fi: `py -3.12 -c "from scapy.all import get_windows_if_list as g;print([i['name'] for i in g()])"`.
3. Como Administrador: `py -3.12 lab\broker_only.py --seconds 90 --capture-iface "Wi-Fi"`.
4. Aperte **EN** na placa. Ela conecta ao Wi-Fi e publica a cada 5 s. O log e o pcap vão para `network\evidence\real_device_mqtt_log.txt` e `real_device_mqtt.pcap`.
5. Rode `py -3.12 lab\analyze_pcap.py` ajustando o nome do arquivo, ou abra o pcap no Wireshark com o filtro `mqtt` e tire print do pacote **Connect Command** (usuário e senha em claro).

## 6. Opcional: OTA sem assinatura (F03)
Compile uma variante (mude, por exemplo, uma string), copie `.pio\build\esp32dev\firmware.bin` para `firmware\ota\nexasense_latest.bin`, rode `py -3.12 -m http.server 8070 --directory firmware\ota` e digite `ota` na UART. A placa baixa e instala via HTTP **sem verificar nada**.

## 7. Checklist de evidências
| Evidência | Arquivo |
|---|---|
| Fotos da placa e pinos | `hardware\evidence\*.jpg` |
| Chip, flash, MAC | `esptool_chip_id.txt`, `esptool_flash_id.txt` |
| eFuses (JTAG/Secure Boot/Flash Enc.) | `efuse_summary.txt` |
| Hash do firmware original e do gravado | `firmware\real_board\hashes.txt` |
| Segredos, endpoints e partições no dump | `firmware\real_board\analysis-output.txt` |
| UART real | `hardware\evidence\uart_boot_REAL.log` |
| Tráfego MQTT real | `network\evidence\real_device_mqtt.pcap` + print do Wireshark |

Depois me envie as saídas (ou os arquivos) para eu atualizar os achados, o relatório e o roteiro do vídeo com os dados reais.
