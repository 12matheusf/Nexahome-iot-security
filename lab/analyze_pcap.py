#!/usr/bin/env python3
"""Lê o pcap e mostra o que um observador de rede consegue extrair (Etapa 5)."""
from scapy.all import rdpcap, Raw
import re
out=[]
for p in rdpcap("network/evidence/mqtt_lab.pcap"):
    if not p.haslayer(Raw): continue
    b=bytes(p[Raw]); t=b[0]>>4
    name={1:"CONNECT",3:"PUBLISH",8:"SUBSCRIBE",2:"CONNACK",9:"SUBACK"}.get(t,str(t))
    txt=re.sub(rb"[^\x20-\x7e]",b".",b).decode()
    out.append(f"{p['TCP'].sport:>5} -> {p['TCP'].dport:<5} {name:9s} {txt[:120]}")
open("network/evidence/pcap_analysis.txt","w").write("\n".join(out)); print("\n".join(out))
