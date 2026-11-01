#!/usr/bin/env python3
"""Etapa 5/6: broker MQTT local (loopback) + dispositivo simulado + captura. Usa as
credenciais extraídas do próprio firmware. Somente 127.0.0.1 — nada sai do laboratório."""
import asyncio, json, re, sys, threading, time, random
import sys
from scapy.all import sniff, wrpcap, conf
LO = "lo" if sys.platform.startswith("linux") else conf.loopback_name  # Windows: Npcap Loopback Adapter
import paho.mqtt.client as mqtt
from amqtt.broker import Broker

fw = open("firmware/nexasense_lab_fw.bin","rb").read()
USER = re.search(rb'user=(\w+) pass=([^\s\x00]+)', fw); U, P = USER.group(1).decode(), USER.group(2).decode()
TOPIC = re.search(rb'publish topic ([^\s\x00]+)', fw).group(1).decode()

cfg = {"listeners":{"default":{"type":"tcp","bind":"127.0.0.1:1883"}},"plugins":{"amqtt.plugins.authentication.AnonymousAuthPlugin":{"allow_anonymous":True}}}
pkts=[]
def sniffer():
  try:
    pkts.extend(sniff(iface=LO, timeout=9, lfilter=lambda p: p.haslayer("TCP") and 1883 in (p["TCP"].sport,p["TCP"].dport)))
  except Exception as e: print("AVISO: captura falhou (instale o Npcap / rode como administrador):", e)
async def main():
    b = Broker(cfg); await b.start(); await asyncio.sleep(1)
    th = threading.Thread(target=sniffer); th.start(); await asyncio.sleep(1)
    def device():
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="NEXASENSE-0001")
        c.username_pw_set(U,P); c.connect("127.0.0.1",1883); c.loop_start()
        for i in range(4):
            c.publish(TOPIC, json.dumps({"id":"NEXASENSE-0001","temp":round(22+random.random(),1),"hum":round(55+random.random()*3,1),"seq":i}))
            time.sleep(0.7)
        c.disconnect(); c.loop_stop()
    # "atacante" passivo/curioso no laboratório: assina o wildcard SEM credenciais
    got=[]
    def spy():
        s = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="analyst-spy")
        s.on_message = lambda c,u,m: got.append((m.topic, m.payload.decode()))
        s.connect("127.0.0.1",1883); s.subscribe("nexahome/#"); s.loop_start(); time.sleep(5); s.loop_stop()
    t2=threading.Thread(target=spy); t2.start(); await asyncio.sleep(0.5)
    threading.Thread(target=device).start()
    await asyncio.sleep(6); th.join(); t2.join(); await b.shutdown()
    seen=set(); uniq=[]
    for p in pkts:
        k=bytes(p)
        if k not in seen: seen.add(k); uniq.append(p)
    wrpcap("network/evidence/mqtt_lab.pcap", uniq)
    open("network/evidence/anonymous_subscriber.txt","w").write("\n".join(f"{t}  {p}" for t,p in got))
    print("pacotes:",len(pkts),"| mensagens obtidas sem credencial:",len(got))
asyncio.run(main())
