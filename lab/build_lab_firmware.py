#!/usr/bin/env python3
"""Gera o firmware EDUCACIONAL do NexaSense (imagem de flash 4 MB estilo ESP32).
Todos os valores (SSID, senhas, tokens) são FICTÍCIOS e existem só no laboratório."""
import struct, hashlib, sys
FLASH = 4 * 1024 * 1024
img = bytearray(b"\xff" * FLASH)

def put(off, data): img[off:off+len(data)] = data

# --- bootloader (0x1000): header ESP32 (magic 0xE9) + strings ---
boot = bytes([0xE9, 3, 2, 0x20]) + struct.pack("<I", 0x4008_0000) + b"\x00"*12
boot += b"ESP-IDF v4.4.6 2nd stage bootloader\x00secure boot: disabled\x00flash encryption: disabled\x00"
put(0x1000, boot)

# --- tabela de partições (0x8000): entradas de 32 bytes, magic 0xAA50 ---
def ent(name, ptype, sub, off, size):
    return struct.pack("<HBBII16sI", 0x50AA, ptype, sub, off, size, name.encode().ljust(16, b"\0"), 0)
parts = [("nvs",1,2,0x9000,0x6000),("otadata",1,0,0xF000,0x2000),("phy_init",1,1,0x11000,0x1000),
         ("factory",0,0,0x20000,0x180000),("config",1,0x82,0x1A0000,0x40000)]
put(0x8000, b"".join(ent(*p) for p in parts))

# --- NVS (0x9000): parâmetros guardados em claro ---
nvs = (b"nvs.net80211\x00wifi.sta.ssid=NexaLab-IoT\x00wifi.sta.pass=nexa2024lab\x00"
       b"device.id=NEXASENSE-0001\x00api.token=lab-token-9f8e7d6c5b4a\x00")
put(0x9000, nvs)

# --- app 'factory' (0x20000): cabeçalho de imagem + rodata com strings ---
app = bytes([0xE9, 6, 2, 0x20]) + struct.pack("<I", 0x400D_0000) + b"\x00"*12
app += b"\x00".join(s.encode() for s in [
 "NexaSense fw 0.9.3-proto (built Sep 01 2026)",
 "ESP-IDF v4.4.6", "mbedtls/2.28.3", "lwIP/2.1.2", "mqtt_client", "esp_https_ota",
 "I (312) nexasense: DEBUG console enabled on UART0 115200 8N1",
 "I (320) nexasense: type 'help' for diagnostic shell",
 "I (331) wifi: connecting to SSID=NexaLab-IoT",
 "I (950) mqtt: broker=mqtt://192.168.56.10:1883 user=nexasense pass=Mqtt#Lab123",
 "I (960) mqtt: publish topic nexahome/NEXASENSE-0001/telemetry",
 "I (962) mqtt: subscribe topic nexahome/NEXASENSE-0001/cmd",
 "ota: update url=http://192.168.56.10:8070/fw/nexasense_latest.bin",
 "ota: signature verification SKIPPED (CONFIG_OTA_VERIFY=n)",
 "ota: TLS cert verification disabled",
 "web: http://192.168.56.20/debug  admin:admin",
 "GET /api/v1/config HTTP/1.1", "I2C sensor SHT31 addr=0x44", "UART0 TX=GPIO1 RX=GPIO3",
 "JTAG enabled (MTDI=12 MTCK=13 MTMS=14 MTDO=15)", "efuse: JTAG_DISABLE=0 DISABLE_DL_ENCRYPT=0",
 "assert failed: sensor_read /home/dev/nexasense/main/sensor.c:142",
]) + b"\x00"
put(0x20000, app)

# --- partição config (0x1A0000): arquivo de configuração em texto ---
cfg = b"""{"mqtt":{"host":"192.168.56.10","port":1883,"tls":false,"user":"nexasense","password":"Mqtt#Lab123"},
 "ota":{"url":"http://192.168.56.10:8070/fw/nexasense_latest.bin","verify_signature":false},
 "debug":{"uart_shell":true,"http_debug":true}}"""
put(0x1A0000, cfg)

out = sys.argv[1] if len(sys.argv) > 1 else "nexasense_lab_fw.bin"
open(out, "wb").write(img)
print(out, len(img), hashlib.sha256(img).hexdigest())
