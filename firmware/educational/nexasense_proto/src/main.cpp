// NexaSense 0.9.3-proto — FIRMWARE EDUCACIONAL, INTENCIONALMENTE INSEGURO (uso em laboratório próprio).
// Reproduz práticas comuns de protótipo: segredos no binário, MQTT sem TLS, console de diagnóstico e OTA sem assinatura.
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <Update.h>
#include <PubSubClient.h>

// >>> EDITE estes 3 valores para a SUA rede de laboratório (2,4 GHz) e o IP do notebook que roda o broker <<<
#define WIFI_SSID   "NexaLab-IoT"
#define WIFI_PASS   "nexa2024lab"
#define MQTT_HOST   "192.168.0.10"
// credenciais compartilhadas e embarcadas (práticas ruins de propósito)
#define MQTT_PORT   1883
#define MQTT_USER   "nexasense"
#define MQTT_PASS   "Mqtt#Lab123"
#define DEVICE_ID   "NEXASENSE-0001"
#define OTA_URL     "http://192.168.0.10:8070/nexasense_latest.bin"   // HTTP, sem assinatura

WiFiClient net; PubSubClient mqtt(net);
unsigned long lastPub = 0; int seq = 0;

void ota_update() {                       // sem verificação de assinatura nem de certificado
  Serial.printf("ota: update url=%s\n", OTA_URL);
  Serial.println("ota: signature verification SKIPPED");
  HTTPClient http; http.begin(OTA_URL);
  if (http.GET() == 200) {
    int len = http.getSize();
    if (Update.begin(len)) { Update.writeStream(*http.getStreamPtr()); if (Update.end()) { Serial.println("ota: ok, reboot"); ESP.restart(); } }
  } else Serial.println("ota: download failed");
  http.end();
}

void shell(String c) {                    // shell de diagnóstico herdada do protótipo, sem autenticação
  c.trim();
  if (c == "help") Serial.println("cmds: help info wifi mqtt ota reboot");
  else if (c == "info") Serial.printf("id=%s fw=0.9.3-proto chip=%s rev=%d flash=%uB\n", DEVICE_ID, ESP.getChipModel(), ESP.getChipRevision(), ESP.getFlashChipSize());
  else if (c == "wifi") Serial.printf("ssid=%s pass=%s ip=%s\n", WIFI_SSID, WIFI_PASS, WiFi.localIP().toString().c_str());
  else if (c == "mqtt") Serial.printf("broker=mqtt://%s:%d user=%s pass=%s\n", MQTT_HOST, MQTT_PORT, MQTT_USER, MQTT_PASS);
  else if (c == "ota") ota_update();
  else if (c == "reboot") ESP.restart();
  Serial.print("nexasense> ");
}

void setup() {
  Serial.begin(115200); delay(300);
  Serial.println("\nI (0) nexasense: NexaSense 0.9.3-proto (educacional)");
  Serial.println("I (10) nexasense: DEBUG console enabled on UART0 115200 8N1");
  Serial.println("I (20) nexasense: type 'help' for diagnostic shell");
  Serial.printf("I (30) wifi: connecting to SSID=%s\n", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) { delay(400); Serial.print("."); }
  Serial.printf("\nI wifi: connected ip=%s mac=%s\n", WiFi.localIP().toString().c_str(), WiFi.macAddress().c_str());
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  Serial.printf("I mqtt: broker=mqtt://%s:%d user=%s pass=%s\n", MQTT_HOST, MQTT_PORT, MQTT_USER, MQTT_PASS);
  Serial.print("nexasense> ");
}

void loop() {
  if (!mqtt.connected()) { if (mqtt.connect(DEVICE_ID, MQTT_USER, MQTT_PASS)) Serial.println("I mqtt: connected"); else { delay(2000); } }
  mqtt.loop();
  if (millis() - lastPub > 5000 && mqtt.connected()) {
    lastPub = millis();
    char p[160]; snprintf(p, sizeof p, "{\"id\":\"%s\",\"temp\":%.1f,\"rssi\":%d,\"seq\":%d}", DEVICE_ID, temperatureRead(), WiFi.RSSI(), seq++);
    mqtt.publish("nexahome/" DEVICE_ID "/telemetry", p);
    Serial.printf("I mqtt: publish %s\n", p);
  }
  if (Serial.available()) shell(Serial.readStringUntil('\n'));
}
