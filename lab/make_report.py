import json
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import glob
reg=[p for p in glob.glob("/usr/share/fonts/**/DejaVuSans.ttf",recursive=True)]
bold=[p for p in glob.glob("/usr/share/fonts/**/DejaVuSans-Bold.ttf",recursive=True)]
pdfmetrics.registerFont(TTFont("D",reg[0])); pdfmetrics.registerFont(TTFont("D-B",bold[0]))
ss=getSampleStyleSheet()
B=ParagraphStyle("B",parent=ss["BodyText"],fontName="D",fontSize=9,leading=12.5)
S=ParagraphStyle("S",parent=B,fontSize=7.2,leading=9)
H1=ParagraphStyle("H1",parent=B,fontName="D-B",fontSize=13,spaceBefore=10,spaceAfter=4,textColor=colors.HexColor("#1F3A5F"))
T=ParagraphStyle("T",parent=B,fontName="D-B",fontSize=18,leading=22,textColor=colors.HexColor("#1F3A5F"))
P=lambda t,s=B:Paragraph(t,s)
F=json.load(open("findings/findings.json"))
def tbl(rows,widths,hdr=True,style=S):
    d=[[P(str(c),style) for c in r] for r in rows]
    t=Table(d,colWidths=widths,repeatRows=1 if hdr else 0)
    st=[("GRID",(0,0),(-1,-1),.4,colors.grey),("VALIGN",(0,0),(-1,-1),"TOP")]
    if hdr: st+=[("BACKGROUND",(0,0),(-1,0),colors.HexColor("#DCE6F2"))]
    t.setStyle(TableStyle(st)); return t
doc=SimpleDocTemplate("relatorio/Relatorio_Tecnico_NexaSense.pdf",pagesize=A4,leftMargin=1.8*cm,rightMargin=1.8*cm,topMargin=1.6*cm,bottomMargin=1.6*cm,title="Relatório Técnico – Avaliação de Segurança NexaSense")
E=[]
E+=[P("Do Protótipo ao Produto Seguro: Avaliação de Segurança do NexaSense",T),Spacer(1,4),
P("IoT Security Analyst · NexaHome Technologies · Hardware Hacking IoT · 01/11/2026<br/>Autor: <b>Matheus Ferreira Vieira · RA 99693</b> · Repositório: <b>[LINK]</b> · Vídeo: <b>[LINK]</b>"),Spacer(1,6),
P("<b>Aviso de escopo e transparência.</b> Avaliação em ambiente local, no notebook do analista (Windows, Npcap 1.90) e na sua VM Kali (QEMU, binwalk, strings). Nenhum firmware ou placa foi fornecido para a atividade, então há <b>duas camadas de evidência</b>: (1) cenário didático NexaSense, com firmware e dispositivo <b>simulados</b> (credenciais fictícias, log UART reconstruído), usado para demonstrar a metodologia, a captura de tráfego e as mitigações; (2) <b>firmware real e público</b> (Tasmota32) executado em ESP32 <b>emulado</b> (QEMU), com análise de flash e UART verdadeiras. Nenhuma placa física foi usada neste relatório. Nenhum sistema de terceiros foi testado.")]
E+=[P("1. Dispositivo analisado",H1),P("O NexaSense é um sensor de temperatura e umidade baseado em <b>ESP32</b> (flash de 4 MB, sensor SHT31 via I²C) que envia telemetria por Wi-Fi usando <b>MQTT</b>, recebe atualizações <b>OTA</b> e mantém recursos de depuração (UART, JTAG, página HTTP /debug) herdados do protótipo. Firmware 0.9.3-proto, ESP-IDF v4.4.6.")]
E+=[P("2. Arquitetura e componentes",H1),Image("architecture/architecture-diagram.png",width=9.2*cm,height=9.2*cm*1397/1370*1.0)]
E+=[Spacer(1,4),tbl([["Componente","Função","Observação de segurança"],
["MCU ESP32","Execução do firmware, Wi-Fi","JTAG não desabilitado (eFuse)"],
["Flash SPI 4 MB","bootloader, NVS, app, config","Sem Flash Encryption; entropia 0,007"],
["Sensor SHT31 (I²C 0x44)","Temperatura/umidade","Barramento interno, risco baixo"],
["UART0 / JTAG","Console e depuração","Acessíveis e sem proteção"],
["Wi-Fi + MQTT/OTA/HTTP","Comunicação","Sem TLS, OTA sem assinatura"]],[4*cm,5.3*cm,8*cm])]
E+=[P("3. Mapa da superfície de ataque",H1),tbl([["Superfície","Vetor","Atacante","Achados"],
["Física","UART, JTAG, dump da flash SPI","Acesso físico à placa","F01, F05, F06"],
["Firmware","Segredos e configuração embarcados, ausência de Secure Boot","Acesso à imagem (flash ou OTA)","F01, F03, F05, F07"],
["Rede","MQTT 1883, OTA HTTP, /debug","Mesma rede / MITM","F02, F03, F04, F07"]],[2.6*cm,6.6*cm,4.2*cm,3.9*cm])]
E+=[P("4. Metodologia",H1),P("Planejamento e organização dos testes segundo o <b>OWASP IoT Security Testing Guide</b>; ameaças selecionadas com o <b>MITRE EMB3D</b>; comparação de capacidades com <b>NIST IR 8259A</b>; requisitos de hardening da <b>ETSI EN 303 645</b>; controles do chip conforme <b>ESP-IDF Security</b>. Fluxo por achado: evidência → fragilidade → ameaça → impacto → risco → mitigação. Risco = matriz 3×3 impacto × probabilidade. Interface acessível não foi tratada como vulnerabilidade automática: avaliou-se contexto, proteções existentes e impacto.")]
E+=[P("5. Análise do firmware",H1),P("Original preservado como somente leitura; <b>SHA-256 acaa7151e2a60c3117a7b15ce7d72893127f7fe94fd9bf0a7723f985803cbef4</b> (4.194.304 bytes); cópia de trabalho com hash idêntico. Estrutura: bootloader (0x1000), tabela de partições (0x8000), NVS, otadata, phy_init, factory (0x20000) e config (0x1A0000). Entropia global 0,007 bits/byte indica imagem <b>não cifrada</b>. Strings revelam senha de Wi-Fi, token de API, senha MQTT, <b>admin:admin</b>, endpoints (mqtt://…:1883, http://…:8070), 'signature verification SKIPPED', 'TLS cert verification disabled', 'secure boot: disabled', 'flash encryption: disabled' e 'JTAG_DISABLE=0'. Relevância: qualquer pessoa com a imagem (dump ou OTA interceptada) obtém credenciais e sabe que o dispositivo aceitaria firmware não assinado.")]
E+=[P("6. Análise das interfaces físicas",H1),tbl([["Interface","O que permite","Proteção","Conclusão"],
["UART0 (GPIO1/3, 115200)","Log de boot (imprime senha MQTT) e shell","Nenhuma","Exposição relevante com acesso físico (F06)"],
["JTAG (GPIO12–15)","Depuração/leitura de memória","eFuse não queimado","Exposição relevante (F05)"],
["SPI flash","Dump completo","Sem Flash Encryption","Exposição relevante (F01, F05)"],
["I²C (SHT31)","Interação com sensor","Barramento interno","Baixa relevância"]],[3.7*cm,5.3*cm,3.2*cm,5.1*cm]),
P("Raciocínio: a UART não é “insegura por existir”; é relevante porque fornece segredos que dão acesso ao broker (credencial compartilhada) e não há proteção compensatória.")]
E+=[P("7. Análise das comunicações e demonstração controlada",H1),P("No laboratório, um broker MQTT local e um dispositivo simulado foram executados com Scapy capturando a interface de loopback. <b>Demonstração:</b> (1) credenciais MQTT extraídas do firmware por regex; (2) o dispositivo as usa; (3) o pcap mostra <b>usuário e senha em claro</b> no pacote CONNECT; (4) um assinante <b>sem credenciais</b> leu 4/4 mensagens de telemetria em nexahome/#. Protocolo: MQTT 3.1.1/TCP 1883, sem TLS; identificadores (NEXASENSE-0001) expostos. <b>Identificar vs. avaliar:</b> saber que o protocolo é MQTT não diz se é seguro; o mesmo MQTT sobre TLS com certificado por dispositivo e ACL seria adequado. Reprodução: <font name='D'>python3 lab/run_network_lab.py</font>. Limitação: tráfego simulado; OTA e /debug avaliados só estaticamente.")]
E+=[Spacer(1,3),Image("network/evidence/print_execucao_windows_01-11-2026.png",width=15*cm,height=15*cm*652/1112),
P("Figura – Execução no notebook Windows do analista (01/11/2026, Npcap 1.90, Python 3.12): 44 pacotes capturados; o CONNECT do NEXASENSE-0001 expõe usuário e senha em claro; 4 mensagens lidas por assinante sem credenciais.",S)]

E+=[P("8. Validação das mitigações (laboratório hardened)",H1),
P("Para provar que as recomendações funcionam, o mesmo laboratório foi repetido com <b>TLS na porta 8883, login individual por dispositivo (hash Argon2) e ACL por tópico</b> (<font name='D'>lab/run_hardened_lab.py</font>). Resultado: <b>7/7 testes aprovados</b>."),Spacer(1,3),
tbl([["Teste","Resultado observado"],
["T1 Cliente anônimo","Recusado (Not authorized)"],["T2 Senha incorreta","Recusado (Not authorized)"],
["T3 MQTT em claro na porta TLS","Sem resposta (conexão falha)"],
["T4 Dispositivo autenticado publica no próprio tópico","3 de 3 mensagens entregues ao analista autenticado"],
["T5 Publicação em tópico de outro dispositivo","0 mensagens forjadas entregues (ACL bloqueou)"],
["T6 Captura na 8883","200 pacotes; senha, tópico e telemetria <b>não</b> aparecem em claro (antes: senha visível no CONNECT)"],
["T7 Tráfego TLS","16 registros de handshake TLS identificados"]],[7*cm,10.3*cm]),
Spacer(1,3),
P("<b>Assinatura de firmware (F03):</b> com Ed25519 (<font name='D'>lab/firmware_signing_demo.py</font>), a imagem original é aceita, e uma imagem com 1 bit alterado ou com o endereço do broker trocado é <b>rejeitada</b> no modo hardened e <b>aceita</b> no modo inseguro. Ressalva: o dispositivo é um modelo em Python do comportamento de verificação, não um ESP32 real; Secure Boot, Flash Encryption e JTAG off ficam como proposta conceitual.")]
R=json.load(open("findings/findings-real.json"))
E+=[P("9. Firmware real em ESP32 emulado (Tasmota32 + QEMU Espressif)",H1),
P("Como não havia firmware fornecido nem placa física, o laboratório foi complementado com um <b>firmware real e público</b>: a release oficial do Tasmota32 (<font name='D' size='7'>tasmota32.factory.bin</font>, imagem completa de flash de 3.152.416 bytes, SHA-256 <font name='D' size='7'>a0c6ed5fa59e18885db435cb22cb0456d6c9bce92477092462224ab6fa5942eb</font>, obtida em 01/11/2026 de github.com/arendst/Tasmota), executado no <b>emulador QEMU oficial da Espressif</b> (máquina esp32). <b>Não é uma placa física</b>: o QEMU emula CPU e flash, mas não o Wi-Fi. Apenas arquivos públicos foram usados; nenhum dispositivo de terceiros foi atacado."),Spacer(1,3),
tbl([["Etapa","Evidência real obtida"],
["Etapa 2 – preservação","Original somente leitura + hash SHA-256 + cópia de trabalho (firmware/real/flash-hashes.txt)"],
["Etapa 3 – estrutura","Bootloader (magic 0xE9) e tabela de partições reais: nvs, otadata, safeboot, app0 (0xE0000), spiffs; app ESP-IDF 5.5.5 com 6 segmentos; entropia 6,98"],
["Etapa 3 – assinatura","36 bytes após os segmentos: sem bloco de assinatura Secure Boot v2 (hash ≠ autenticação)"],
["Etapa 3 – strings","URLs de OTA em HTTP; campos Password, WebPassword, MqttPassword; mensagem “'Webpassword' is recommended”"],
["Conferência cruzada (VM Kali)","sha256sum idêntico ao do relatório; binwalk confirma o bootloader, as 3 imagens ESP (safeboot e app0) e as 5 partições; entropia 6,984 igual à do script; execução no QEMU reproduziu o mesmo log de boot (firmware/real/kali_crosscheck.txt)"],
["Etapa 4 – UART (real, emulada)","Log de boot do ROM e do bootloader seguido de “Tasmota Version 16.0.0 … ESP32-D0WDQ6”, “CFG: Use defaults”, “WifiManager active for 3 minutes”"]],[3.8*cm,13.5*cm]),
Spacer(1,3),
P("<b>Observação:</b> o binwalk mostra “flags: 0x0 (not encrypted)” nas entradas da tabela de partições; isso é o flag da própria tabela e <b>não</b> informa o estado da Flash Encryption nas eFuses. Também aparecem caminhos de build (/home/runner/.platformio/…) e certificados X.509 públicos embutidos, sem relevância de risco aqui. <b>Limitações dessa parte:</b> o <i>Guru Meditation Error</i> ao iniciar o Wi-Fi é limitação do emulador (acesso a periférico não emulado), não vulnerabilidade; o estado real das eFuses (Secure Boot, Flash Encryption, JTAG) não é avaliável sem hardware; OTA e MQTT do Tasmota não foram testados dinamicamente. <b>Leitura correta:</b> isto não prova que o Tasmota seja inseguro, e sim que uma build padrão do ESP-IDF não vem assinada nem cifrada e que essas proteções precisam ser habilitadas pelo fabricante do produto. Os achados R01–R04 abaixo têm evidência real; F01–F07 vêm do cenário didático simulado."),
Spacer(1,3),
P("Reprodução: <font name='D'>lab/run_qemu_tasmota.sh</font> (Linux, WSL ou VM Kali) e <font name='D'>python lab/analyze_firmware.py firmware/real/tasmota32_factory_flash.bin</font>.",S)]
E+=[P("10. Riscos identificados e classificação",H1)]
rows=[["Achado","Evidência","Impacto","Prob.","Risco","Recomendação"]]
for f in F: rows.append([f"<b>{f['id']}</b> {f['title']}",f['evidencia'],f['impacto'],f['prob'],f"<b>{f['risco']}</b>",f['rec']])
rowsR=[["Achado","Evidência","Impacto","Prob.","Risco","Recomendação"]]
for f in R: rowsR.append([f"<b>{f['id']}</b> {f['title']}",f['evidencia'],f['impacto'],f['prob'],f"<b>{f['risco']}</b>",f['rec']])
E+=[P("<b>10.1 Achados com evidência real (R01–R04)</b>"),tbl(rowsR,[3.0*cm,4.3*cm,1.6*cm,1.4*cm,1.8*cm,5.2*cm]),Spacer(1,4),P("<b>10.2 Achados do cenário didático NexaSense (F01–F07, dispositivo simulado)</b>"),tbl(rows,[3.0*cm,4.3*cm,1.6*cm,1.4*cm,1.8*cm,5.2*cm]),Spacer(1,3),
P("Matriz: Alto×Média=Alto; Alto×Baixa=Médio; Médio×Alta=Alto; Médio×Média=Médio. F07 é indício estático, ainda não confirmado dinamicamente.")]
E+=[P("11. Relação com as referências",H1),tbl([["Referência","Aplicação aos achados"],
["OWASP ISTG","Estrutura das etapas e cobertura das superfícies física, firmware e rede"],
["NIST IR 8259A","Lacunas: proteção de dados (F01, F02), atualização (F03), controle de acesso a interfaces (F04–F06)"],
["ETSI EN 303 645","5.1 senhas padrão (F01, F07); 5.3 atualizações (F03); 5.4 parâmetros sensíveis (F01); 5.5 comunicação segura (F02, F04); 5.6 superfície de ataque (F06, F07)"],
["MITRE EMB3D","Extração de firmware por hardware e interfaces privilegiadas expostas (F01, F05, F06)"],
["ESP-IDF Security","Secure Boot, Flash Encryption e desativação de JTAG (F03, F05)"]],[4*cm,13.3*cm])]
E+=[P("12. Recomendações e proposta de hardening",H1),tbl([["Prio.","Medida","Achados"],
["P0","MQTT sobre TLS com mTLS por dispositivo; credenciais únicas e sem segredos no binário; OTA por HTTPS com imagem assinada e anti-rollback","F01, F02, F03, F07"],
["P1","Secure Boot v2 + Flash Encryption (release) + JTAG desabilitado por eFuse; ACL e remoção de acesso anônimo no broker","F04, F05"],
["P2","Console/shell desativado, logs mínimos, remover /debug, pads protegidos, recuperação A/B de OTA","F06, F07"],
["P3","Threat model EMB3D, revisão por release, política de divulgação e suporte de atualizações","todos"]],[1.3*cm,13*cm,3*cm]),
P("Medidas irreversíveis (eFuses) foram propostas apenas conceitualmente; exigem gestão de chaves e teste prévio em unidades de desenvolvimento.")]
E+=[P("13. Caso real pesquisado: Espressif ESP32, fault injection e Secure Boot (CVE-2019-15894)",H1),
P("<b>Dispositivo:</b> SoC ESP32 (o mesmo da NexaHome). <b>Superfície:</b> física; falhas de tensão/clock (<i>fault injection</i>). <b>Problema:</b> com glitches precisamente temporizados, um atacante com acesso físico pode contornar a verificação do Secure Boot na inicialização e executar código não verificado a partir da flash; sem Flash Encryption, isso permite execução arbitrária. Reportado por Riscure (Yashin Mehaboobe e Santiago Cordoba Pellicer) e, independentemente, por LimitedResults; aviso da Espressif de 03/09/2019. <b>Mitigação:</b> atualizar o ESP-IDF (3.0.9, 3.1.6, 3.2.3, 3.3.1 ou ≥ 4.0), que impede desativar a Flash Encryption quando o Secure Boot é usado, e adotar versões de chip com ROM reforçada. <b>Lição para a NexaHome:</b> Secure Boot não basta isoladamente; é preciso defesa em profundidade (Secure Boot + Flash Encryption + JTAG off) e plano de atualização, pois quem tem a placa em mãos é um atacante realista para sensores instalados em ambientes de clientes. Fonte: "),
P("<link href='https://www.espressif.com/en/news/Espressif_Security_Advisory_Concerning_Fault_Injection_and_Secure_Boot'><u>Espressif Security Advisory Concerning Fault Injection and Secure Boot</u></link>; <link href='https://nvd.nist.gov/vuln/detail/CVE-2019-15894'><u>NVD CVE-2019-15894</u></link>.",S)]
E+=[P("14. Limitações",H1),P("Sem placa física: dispositivo NexaSense e log UART didáticos simulados, firmware real apenas em emulador; verificação de assinatura modelada em Python; Secure Boot/Flash Encryption não gravados (irreversíveis); análise do Tasmota apenas estática; OTA e /debug sem teste dinâmico; broker de laboratório configurado de forma permissiva por design, então F04 descreve a configuração de teste e deve ser verificada no broker real do piloto. Referências: OWASP ISTG, NIST IR 8259A, ETSI EN 303 645 V3.1.3, MITRE EMB3D e documentação ESP-IDF Security.")]
doc.build(E)
