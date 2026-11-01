#!/usr/bin/env python3
"""Broker MQTT INSEGURO para o laboratório com a ESP32 real (aceita anônimos, sem TLS), escutando na rede local.
Registra o que a placa envia. Uso:  py -3.12 lab\\broker_only.py [--seconds 120] [--capture-iface "Wi-Fi"]
Rode como Administrador se usar --capture-iface (Npcap). Libere a porta 1883 no firewall (rede privada)."""
import argparse, asyncio, datetime, os, sys, threading, time
import paho.mqtt.client as mqtt
from amqtt.broker import Broker
ap = argparse.ArgumentParser(); ap.add_argument("--seconds", type=int, default=120); ap.add_argument("--capture-iface"); a = ap.parse_args()
os.makedirs("network/evidence", exist_ok=True)
LOG = "network/evidence/real_device_mqtt_log.txt"; PCAP = "network/evidence/real_device_mqtt.pcap"
cfg = {"listeners": {"default": {"type": "tcp", "bind": "0.0.0.0:1883"}},
       "plugins": {"amqtt.plugins.authentication.AnonymousAuthPlugin": {"allow_anonymous": True}}}
pk = []
def sniffer():
    from scapy.all import sniff, wrpcap
    try: pk.extend(sniff(iface=a.capture_iface, timeout=a.seconds, lfilter=lambda p: p.haslayer("TCP") and 1883 in (p["TCP"].sport, p["TCP"].dport)))
    except Exception as e: print("AVISO: captura falhou:", e)
    wrpcap(PCAP, pk); print("pcap salvo:", PCAP, "pacotes:", len(pk))
def log(msg):
    line = f"{datetime.datetime.now().isoformat(timespec='seconds')}  {msg}"; print(line); open(LOG, "a", encoding="utf-8").write(line + "\n")
async def main():
    b = Broker(cfg); await b.start(); log(f"broker inseguro em 0.0.0.0:1883 por {a.seconds}s (anônimo permitido, sem TLS)")
    if a.capture_iface: threading.Thread(target=sniffer, daemon=True).start()
    def spy():
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="analyst-spy")
        c.on_message = lambda cl, u, m: log(f"RECEBIDO topic={m.topic} payload={m.payload.decode(errors='replace')}")
        c.connect("127.0.0.1", 1883); c.subscribe("#"); c.loop_start(); time.sleep(a.seconds); c.loop_stop()
    t = threading.Thread(target=spy); t.start()
    await asyncio.get_running_loop().run_in_executor(None, t.join); await b.shutdown(); log("encerrado")
asyncio.run(main())
