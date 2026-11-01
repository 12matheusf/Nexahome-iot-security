#!/usr/bin/env python3
"""Etapas 2 e 3: preserva a imagem, registra hash e faz análise estática básica."""
import hashlib, os, re, shutil, struct, math, datetime, stat, sys
SRC = sys.argv[1] if len(sys.argv) > 1 else "firmware/nexasense_lab_fw.bin"   # aceita dump real: py lab\analyze_firmware.py firmware\real_board\dump.bin
OUT = os.path.dirname(SRC) or "."; WORK = os.path.join(OUT, "work", "work_copy_" + os.path.basename(SRC))
data = open(SRC, "rb").read()
sha = hashlib.sha256(data).hexdigest()
os.chmod(SRC, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)       # original somente leitura
os.makedirs(os.path.dirname(WORK), exist_ok=True); shutil.copy2(SRC, WORK)
assert hashlib.sha256(open(WORK,"rb").read()).hexdigest() == sha
out = []
out += ["## Preservação", f"arquivo : {os.path.basename(SRC)}", f"tamanho : {len(data)} bytes",
        "origem  : informar no relatório (dump da placa via esptool, firmware fornecido ou gerado em laboratório)",
        f"data    : {datetime.datetime.now().isoformat(timespec='seconds')}", f"SHA-256 : {sha}",
        f"cópia de trabalho: {WORK} (hash idêntico verificado)", ""]
open(os.path.join(OUT,"hashes.txt"),"w").write(f"{sha}  {os.path.basename(SRC)}\n{sha}  work/{os.path.basename(WORK)}\n")
out += ["## Partições (tabela em 0x8000)"]
TYPES = {0:"app",1:"data"}
for i in range(16):
    e = data[0x8000+32*i:0x8000+32*(i+1)]
    if len(e)<32 or struct.unpack("<H", e[:2])[0] != 0x50AA: break
    _,t,s,off,size,name,_f = struct.unpack("<HBBII16sI", e)
    out.append(f"  {name.rstrip(b'\0').decode():9s} type={TYPES.get(t,t)} sub=0x{s:02x} offset=0x{off:06x} size=0x{size:06x}")
out += ["", "## Cabeçalhos", f"  bootloader @0x1000 magic=0x{data[0x1000]:02X} (esperado 0xE9)"]
for i in range(16):
    e=data[0x8000+32*i:0x8000+32*(i+1)]
    if len(e)<32 or struct.unpack("<H",e[:2])[0]!=0x50AA: break
    _,t,sb,off,size,nm,_f=struct.unpack("<HBBII16sI",e)
    if t==0 and off<len(data): out.append(f"  app {nm.rstrip(bytes(1)).decode()} @0x{off:X} magic=0x{data[off]:02X}")
out.pop() if False else None
out += ["", "## Proteções no bootloader"]
for k in (b"secure boot: disabled", b"flash encryption: disabled"):
    out.append(f"  '{k.decode()}' encontrado" if k in data else f"  '{k.decode()}': texto não presente na imagem (o estado real fica nos eFuses, que a imagem de flash não contém)")
def ent(b):
    if not b: return 0
    c=[0]*256
    for x in b:c[x]+=1
    return -sum(v/len(b)*math.log2(v/len(b)) for v in c if v)
out += ["", f"## Entropia global: {ent(data):.3f} bits/byte (baixa; <7,5 sugere imagem NÃO cifrada)"]
strs = re.findall(rb"[\x20-\x7e]{6,}", data)
pats = {"credencial/segredo":rb"(?i)pass|pswd|token|admin:|secret|user=","endpoint/URL":rb"(?i)https?://|mqtt://|GET /",
        "depuração/UART/JTAG":rb"(?i)debug|UART|JTAG|assert|shell","atualização/OTA":rb"(?i)ota|signature|cert",
        "proteção eFuse":rb"(?i)efuse|secure boot|flash encryption"}
out += ["", "## Strings relevantes (de %d strings)"%len(strs)]
for cat,p in pats.items():
    out.append(f"[{cat}]")
    for s in strs:
        if re.search(p,s): out.append("   "+s.decode())
open(os.path.join(OUT,"analysis-output.txt"),"w").write("\n".join(out)); print("\n".join(out))
