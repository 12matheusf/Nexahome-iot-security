#!/usr/bin/env python3
"""Captura REAL da UART0 da ESP32 (boot + shell de diagnóstico). Uso:
   py -3.12 lab\\capture_uart.py COM5 --seconds 25 --commands   (COM5 = porta da placa no Gerenciador de Dispositivos)"""
import argparse, datetime, os, time, serial
ap = argparse.ArgumentParser(); ap.add_argument("port"); ap.add_argument("--baud", type=int, default=115200)
ap.add_argument("--seconds", type=int, default=25); ap.add_argument("--commands", action="store_true", help="envia help/info/wifi/mqtt à shell"); a = ap.parse_args()
os.makedirs("hardware/evidence", exist_ok=True); out = "hardware/evidence/uart_boot_REAL.log"
s = serial.Serial(a.port, a.baud, timeout=0.2)
s.dtr = False; s.rts = True; time.sleep(.2); s.rts = False            # pulso em EN: reinicia a placa e captura o boot
log = [f"# Captura REAL da UART0 {a.port} @ {a.baud} 8N1 — {datetime.datetime.now().isoformat(timespec='seconds')}"]
t0 = time.time(); sent = False
while time.time() - t0 < a.seconds:
    l = s.readline().decode(errors="replace").rstrip()
    if l: log.append(l); print(l)
    if a.commands and not sent and time.time() - t0 > a.seconds * 0.6:
        sent = True
        for c in ("help", "info", "wifi", "mqtt"):
            s.write((c + "\n").encode()); log.append(f"> {c}"); print(f"> {c}"); time.sleep(.8)
            while s.in_waiting: r = s.readline().decode(errors="replace").rstrip(); log.append(r); print(r)
open(out, "w", encoding="utf-8").write("\n".join(log)); print("salvo em", out)
