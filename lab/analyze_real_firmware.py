#!/usr/bin/env python3
"""Análise estática de um firmware REAL e público de ESP32 (imagem de aplicação ESP-IDF).
Uso: python lab/analyze_real_firmware.py firmware/real/tasmota32_release.bin"""
import hashlib, os, re, struct, sys, math, datetime, stat, shutil
path = sys.argv[1] if len(sys.argv) > 1 else "firmware/real/tasmota32_release.bin"
data = open(path, "rb").read(); sha = hashlib.sha256(data).hexdigest()
os.chmod(path, stat.S_IRUSR|stat.S_IRGRP|stat.S_IROTH)
os.makedirs("firmware/real/work", exist_ok=True); work = "firmware/real/work/" + os.path.basename(path); shutil.copy2(path, work)
assert hashlib.sha256(open(work,"rb").read()).hexdigest() == sha
o = ["## Preservação", f"arquivo: {os.path.basename(path)}  tamanho: {len(data)} bytes", f"data da análise: {datetime.datetime.now().isoformat(timespec='seconds')}",
     "origem: release oficial pública do Tasmota (github.com/arendst/Tasmota, tasmota32.bin)", f"SHA-256: {sha}", ""]
# Cabeçalho de imagem ESP: magic, nº segmentos, flash mode, flash size/freq, entry, ...
magic, nseg, fmode, fsf, entry = struct.unpack("<BBBBI", data[:8])
chip = struct.unpack("<H", data[12:14])[0]
o += ["## Cabeçalho da imagem ESP32", f"magic=0x{magic:02X} (0xE9 = imagem ESP válida)  segmentos={nseg}  flash_mode={fmode}  entry=0x{entry:08X}  chip_id=0x{chip:04X} ({'ESP32' if chip==0 else 'outro'})",
      f"hash SHA-256 anexado à imagem (flag): {data[23]}"]
pos = 24; segs=[]
for i in range(nseg):
    addr, ln = struct.unpack("<II", data[pos:pos+8]); segs.append((addr,ln,pos+8)); pos += 8 + ln
    o.append(f"  seg{i}: load=0x{addr:08X} len={ln}")
# app descriptor (magic 0xABCD5432) no 1º segmento
i = data.find(struct.pack("<I", 0xABCD5432))
if i > 0:
    ver = data[i+16:i+48].split(b"\0")[0].decode(errors="replace"); proj = data[i+48:i+80].split(b"\0")[0].decode(errors="replace")
    idf = data[i+112:i+144].split(b"\0")[0].decode(errors="replace")
    o += ["", "## App descriptor", f"versão={ver}  projeto={proj}  ESP-IDF={idf}"]
# Assinatura/secure boot: bloco de assinatura (magic 0xE7) após o hash
tail = data[pos:]
o += ["", "## Proteções na própria imagem",
      f"bytes após os segmentos: {len(tail)} (padding+checksum+SHA-256 = ~36-48 bytes; uma imagem assinada com Secure Boot v2 traria um bloco extra de 4096 bytes)"]
o.append("  Bloco de assinatura presente (imagem assinada)" if len(tail) >= 4096 else "  Sem bloco de assinatura Secure Boot v2: a imagem NÃO é assinada (só tem hash de integridade, que não autentica a origem)")
def ent(b):
    c=[0]*256
    for x in b:c[x]+=1
    return -sum(v/len(b)*math.log2(v/len(b)) for v in c if v)
o += ["", f"## Entropia: {ent(data):.3f} bits/byte (≈8 = cifrado/comprimido; ~6 = código+dados em claro)"]
strs = re.findall(rb"[\x20-\x7e]{6,}", data)
pats = {"endpoints/URL":rb"(?i)https?://[\w./:-]{6,}|mqtt://", "protocolos":rb"(?i)\b(mqtt|coap|modbus|telnet|ssdp|upnp|mdns|tls|ssl)\b",
        "credenciais/padrões":rb"(?i)(password|passwd|secret|token|admin)", "OTA/atualização":rb"(?i)(ota|firmware.?upgrade|upgrade)", "debug":rb"(?i)(debug|console|uart|jtag)"}
o += ["", f"## Strings relevantes (total {len(strs)} strings; amostra até 12 por categoria)"]
for cat,p in pats.items():
    hits = sorted({s.decode() for s in strs if re.search(p,s) and len(s)<140}); o.append(f"[{cat}] {len(hits)} únicas")
    o += ["   "+h for h in hits[:12]]
open("firmware/real/real-analysis-output.txt","w").write("\n".join(o)); print("\n".join(o))
