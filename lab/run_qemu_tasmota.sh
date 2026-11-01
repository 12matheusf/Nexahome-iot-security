#!/usr/bin/env bash
# Executa o firmware REAL do Tasmota32 num ESP32 emulado (QEMU da Espressif) e captura a UART0.
# Requer Linux (ou WSL / VM Kali): sudo apt install libslirp0 xz-utils curl
set -e
TAG=esp-develop-9.2.2-20250817; V=9.2.2_20250817; W=firmware/real/qemu; mkdir -p $W hardware/evidence
[ -x $W/qemu/bin/qemu-system-xtensa ] || { curl -sSL -o $W/q.tar.xz https://github.com/espressif/qemu/releases/download/$TAG/qemu-xtensa-softmmu-esp_develop_${V}-x86_64-linux-gnu.tar.xz; tar -xf $W/q.tar.xz -C $W; }
[ -f firmware/real/tasmota32_factory_flash.bin ] || curl -sSL -o firmware/real/tasmota32_factory_flash.bin https://github.com/arendst/Tasmota/releases/latest/download/tasmota32.factory.bin
python3 - <<'PY'
d=open("firmware/real/tasmota32_factory_flash.bin","rb").read(); open("firmware/real/qemu/flash4m.bin","wb").write(d+b"\xff"*(4*1024*1024-len(d)))
PY
timeout 40 $W/qemu/bin/qemu-system-xtensa -nographic -machine esp32 -m 4M -drive file=$W/flash4m.bin,if=mtd,format=raw -serial file:$W/uart.log -monitor none 2>/dev/null || true
echo "UART capturada em $W/uart.log ($(wc -c < $W/uart.log) bytes)"; head -c 1500 $W/uart.log
