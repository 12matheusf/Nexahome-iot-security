@echo off
REM Executar na raiz do repositorio (cmd como Administrador)
python -m pip install -r requirements.txt || goto :err
python lab\build_lab_firmware.py firmware\nexasense_lab_fw.bin || goto :err
python lab\analyze_firmware.py || goto :err
python lab\run_network_lab.py || goto :err
python lab\analyze_pcap.py || goto :err
python lab\run_hardened_lab.py || goto :err
python lab\firmware_signing_demo.py || goto :err
echo OK & exit /b 0
:err
echo ERRO & exit /b 1
