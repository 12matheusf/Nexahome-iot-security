#!/usr/bin/env python3
"""Demonstra a mitigação F03: OTA com imagem assinada (Ed25519) e verificação obrigatória no dispositivo.
Cenário: o dispositivo INSEGURO (verify_signature=false) aceita qualquer imagem; o HARDENED só aceita a assinada pelo fabricante."""
import hashlib, sys, datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization as S
from cryptography.exceptions import InvalidSignature
SRC="firmware/nexasense_lab_fw.bin"; OUT="firmware/signing/"
fw=bytearray(open(SRC,"rb").read())
priv=Ed25519PrivateKey.generate(); pub=priv.public_key()   # em produto: chave privada em HSM, pública gravada na imagem/eFuse
open(OUT+"vendor_public.pem","wb").write(pub.public_bytes(S.Encoding.PEM,S.PublicFormat.SubjectPublicKeyInfo))
sig=priv.sign(bytes(fw)); open(OUT+"nexasense_lab_fw.bin.sig","wb").write(sig)
tam=bytearray(fw); tam[0x20000+0x40]^=0x01                   # 1 bit alterado na área do app (ex.: atacante mexe no firmware)
mal=bytes(fw).replace(b"mqtt://192.168.56.10:1883",b"mqtt://203.0.113.66:1883")   # atacante troca o broker por um servidor dele (IP de documentação)
def device_insecure(img): return "ACEITA (verify_signature=false: instala qualquer imagem)"
def device_hardened(img,sg):
    try: pub.verify(sg,bytes(img)); return "ACEITA (assinatura válida)"
    except InvalidSignature: return "REJEITADA (assinatura inválida)"
h=lambda b:hashlib.sha256(bytes(b)).hexdigest()[:16]
rows=[("Imagem original, assinada pelo fabricante",fw),("1 bit alterado no código do app",tam),("Endpoint do broker trocado (imagem maliciosa)",mal)]
out=[f"Demo de assinatura de firmware — {datetime.datetime.now().isoformat(timespec='seconds')}","Algoritmo: Ed25519 sobre a imagem inteira; assinatura em firmware/signing/nexasense_lab_fw.bin.sig",""]
for n,img in rows:
    out+= [f"[{n}]  sha256={h(img)}…","   dispositivo INSEGURO : "+device_insecure(img),"   dispositivo HARDENED : "+device_hardened(img,sig),""]
ok = device_hardened(fw,sig).startswith("ACEITA") and all(device_hardened(i,sig).startswith("REJEITADA") for _,i in rows[1:])
out.append("RESULTADO: "+("mitigação validada — só a imagem original é aceita" if ok else "FALHA"))
open("firmware/signing/signing-demo-output.txt","w").write("\n".join(out)); print("\n".join(out)); sys.exit(0 if ok else 1)
