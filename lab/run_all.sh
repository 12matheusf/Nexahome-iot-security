#!/usr/bin/env bash
# Reproduz todo o laboratório (executar na raiz do repositório). Requer root para captura na interface lo.
set -e
pip install -r requirements.txt
python3 lab/build_lab_firmware.py firmware/nexasense_lab_fw.bin
python3 lab/analyze_firmware.py
python3 lab/run_network_lab.py
python3 lab/analyze_pcap.py
python3 lab/run_hardened_lab.py
python3 lab/firmware_signing_demo.py
# firmware real público (baixe antes: ver README, seção 'Firmware real')
[ -f firmware/real/tasmota32_release.bin ] && python3 lab/analyze_real_firmware.py || true
sha256sum -c firmware/hashes.txt 2>/dev/null | head -1 || true
