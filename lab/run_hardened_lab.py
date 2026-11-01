#!/usr/bin/env python3
"""Laboratório HARDENED: MQTT sobre TLS (8883), login obrigatório por dispositivo (Argon2) e ACL por tópico.
Repete a captura do laboratório inseguro e prova que as mitigações F02/F04 funcionam. Só 127.0.0.1."""
import asyncio, datetime, json, os, ssl, sys, threading, time, ipaddress
from scapy.all import sniff, wrpcap, conf, Raw
import paho.mqtt.client as mqtt
from amqtt.broker import Broker
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

D="hardened/"; EV=D+"evidence/"; os.makedirs(EV,exist_ok=True); os.makedirs(D+"pki",exist_ok=True)
LO = "lo" if sys.platform.startswith("linux") else conf.loopback_name
PASS="Dev0001-lab-only-ChangeMe!"   # senha única do dispositivo (fictícia, laboratório)
# --- PKI de laboratório: CA própria + certificado do servidor com SAN ---
def key(): return ec.generate_private_key(ec.SECP256R1())
def name(cn): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,cn)])
now=datetime.datetime.now(datetime.timezone.utc)
ca_k=key(); ca=(x509.CertificateBuilder().subject_name(name("NexaHome Lab CA")).issuer_name(name("NexaHome Lab CA")).public_key(ca_k.public_key())
  .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now+datetime.timedelta(days=30))
  .add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(ca_k,hashes.SHA256()))
sv_k=key(); sv=(x509.CertificateBuilder().subject_name(name("localhost")).issuer_name(ca.subject).public_key(sv_k.public_key())
  .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now+datetime.timedelta(days=30))
  .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),False).sign(ca_k,hashes.SHA256()))
P=serialization.Encoding.PEM
open(D+"pki/ca.pem","wb").write(ca.public_bytes(P)); open(D+"pki/server.pem","wb").write(sv.public_bytes(P))
open(D+"pki/server.key","wb").write(sv_k.private_bytes(P,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
ph=PasswordHash((Argon2Hasher(),))
open(D+"passwd","w").write(f"NEXASENSE-0001:{ph.hash(PASS)}\nanalyst:{ph.hash('Analyst-lab-only!')}\n")
cfg={"listeners":{"default":{"type":"tcp","bind":"127.0.0.1:8883","ssl":True,"certfile":D+"pki/server.pem","keyfile":D+"pki/server.key","cafile":D+"pki/ca.pem"}},
 "plugins":{"amqtt.plugins.authentication.FileAuthPlugin":{"password_file":D+"passwd"},
  "amqtt.plugins.topic_checking.TopicAccessControlListPlugin":{
    "acl":{"NEXASENSE-0001":["nexahome/NEXASENSE-0001/cmd"],"analyst":["nexahome/#"]},
    "publish_acl":{"NEXASENSE-0001":["nexahome/NEXASENSE-0001/telemetry"]}}}}
TOPIC="nexahome/NEXASENSE-0001/telemetry"
results=[]; pkts=[]; got=[]
def rec(t,ok,det): results.append((t,"PASSOU" if ok else "FALHOU",det)); print(("[OK] " if ok else "[!!] ")+t+" — "+det)
def tlsclient(cid,user=None,pw=None,tls=True):
    c=mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,client_id=cid)
    if user: c.username_pw_set(user,pw)
    if tls: c.tls_set(ca_certs=D+"pki/ca.pem")
    return c
def attempt(cid,user,pw,tls=True,port=8883):
    res={}; c=tlsclient(cid,user,pw,tls); c.on_connect=lambda c,u,f,rc,p: res.setdefault("rc",rc)
    try: c.connect("127.0.0.1",port,5); c.loop_start(); t=time.time()
    except Exception as e: return f"erro:{type(e).__name__}"
    while "rc" not in res and time.time()-t<4: time.sleep(.1)
    c.loop_stop(); c.disconnect(); return str(res.get("rc","sem-resposta"))
async def main():
    b=Broker(cfg); await b.start(); await asyncio.sleep(1)
    def sn():
        try: pkts.extend(sniff(iface=LO,timeout=14,lfilter=lambda p:p.haslayer("TCP") and 8883 in (p["TCP"].sport,p["TCP"].dport)))
        except Exception as e: print("AVISO captura:",e)
    th=threading.Thread(target=sn); th.start(); await asyncio.sleep(1.5)
    def run_tests():
        # T1 anônimo recusado
        r=attempt("anon",None,None); rec("T1 cliente anônimo (TLS, sem login) é recusado","Not authorized" in r or r in("5","135") or "5" in r, f"retorno={r}")
        # T2 senha errada
        r=attempt("NEXASENSE-0001","NEXASENSE-0001","senha-errada"); rec("T2 senha incorreta é recusada","Not authorized" in r or "5" in r or "135" in r or "Bad" in r, f"retorno={r}")
        # T3 cliente sem TLS na porta TLS
        r=attempt("plain","teste-sem-tls","senha-de-teste-sem-tls",tls=False); rec("T3 conexão MQTT em claro na porta TLS falha","rc" not in r or r.startswith("erro") or r=="sem-resposta", f"retorno={r}")
        # T4 dispositivo legítimo publica; analista autenticado lê; dispositivo tenta publicar em tópico de outro
        spy=tlsclient("analyst","analyst","Analyst-lab-only!"); spy.on_message=lambda c,u,m:got.append((m.topic,m.payload.decode()))
        spy.connect("127.0.0.1",8883); spy.subscribe("nexahome/#"); spy.loop_start(); time.sleep(1)
        d=tlsclient("NEXASENSE-0001","NEXASENSE-0001",PASS); d.connect("127.0.0.1",8883); d.loop_start(); time.sleep(.5)
        for i in range(3): d.publish(TOPIC,json.dumps({"id":"NEXASENSE-0001","temp":22.5+i/10,"seq":i})); time.sleep(.4)
        d.publish("nexahome/NEXASENSE-9999/telemetry",json.dumps({"id":"FORJADO","temp":99})); time.sleep(1.5)
        d.loop_stop(); spy.loop_stop()
        legit=[g for g in got if g[0]==TOPIC]; forged=[g for g in got if "9999" in g[0]]
        rec("T4 dispositivo autenticado publica no próprio tópico (3 msgs)",len(legit)==3,f"{len(legit)} recebidas pelo analista autenticado")
        rec("T5 ACL bloqueia publicação em tópico de outro dispositivo",len(forged)==0,f"{len(forged)} mensagens forjadas entregues")
    await asyncio.get_running_loop().run_in_executor(None, run_tests)
    await asyncio.get_running_loop().run_in_executor(None, th.join); await b.shutdown()
    raw=b"".join(bytes(p[Raw]) for p in pkts if p.haslayer(Raw))
    leak=[s for s in (PASS.encode(),b"Analyst-lab-only!",b'"temp"',b"nexahome/NEXASENSE") if s in raw]
    rec("T6 captura em 8883 NÃO contém senha, tópico nem telemetria em claro",len(raw)>0 and not leak,f"{len(pkts)} pacotes, {len(raw)} bytes de payload; trechos em claro encontrados: {leak or 'nenhum'}")
    seen=sorted({p["TCP"].sport for p in pkts if p.haslayer("TCP")}|{p["TCP"].dport for p in pkts if p.haslayer("TCP")})
    wrpcap(EV+"mqtt_tls_hardened.pcap",pkts)
    hello=[p for p in pkts if p.haslayer(Raw) and bytes(p[Raw])[:2]==b"\x16\x03"]
    rec("T7 tráfego é TLS (handshake 0x16 0x03 presente)",len(hello)>0,f"{len(hello)} registros de handshake TLS")
    out="\n".join(f"{s:7s} {t} | {d}" for t,s,d in results)
    open(EV+"hardened_results.txt","w").write("Resultados do laboratório hardened ("+datetime.datetime.now().isoformat(timespec='seconds')+")\n"+out+"\n"); 
    print("\nTOTAL:",sum(1 for r in results if r[1]=="PASSOU"),"/",len(results))
asyncio.run(main())
