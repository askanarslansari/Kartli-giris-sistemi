#include <ESP8266WiFi.h>        // Wi-Fi sürücüleri
#include <ESP8266WebServer.h>   // Basit HTTP sunucu
#include <SPI.h>                // SPI (RC522 için)
#include <MFRC522.h>            // RC522 RFID kütüphanesi
#include <Wire.h>               // I2C (DS3231 için)
#include "RTClib.h"             // DS3231 RTC yardımcıları
#include <EEPROM.h>             // Kalıcı hafıza

// Wi-Fi kimlik bilgileri
const char* WIFI_SSID = "Teknopark";
const char* WIFI_PASS = "şifre gizli";

// Web arayüzü (Digest) kullanıcı/parola
const char* WEB_USER = "admin";
const char* WEB_PASS = "changeme";

// Donanım pinleri
#define PIN_SS    D2    // RC522 SS (SDA)
#define PIN_RST   D1    // RC522 RST
#define PIN_RELAY D0    // Röle çıkışı
#define PIN_BUZZ  D8    // Buzzer
#define PIN_LED   LED_BUILTIN // Kart üzeri LED

#define RELAY_ACTIVE_HIGH true // Röle aktif seviyesi (modülüne göre)
#define DOOR_UNLOCK_MS 2000    // Kapı açık kalma süresi (ms)

// Buzzer ton parametreleri (OK/NO)
#define TONE_OK_FREQ   2000
#define TONE_NO_FREQ   800
#define TONE_MS_SHORT  120
#define TONE_MS_LONG   350
#define TONE_GAP_MS     80

// EEPROM toplam boyut (bayt)
#define EEPROM_SIZE 4096

// Yetkili kart kayıt alanı (sabit boyutlu)
#define AUTH_START     64      // Yetkili alan başlangıç adresi
#define AUTH_REC_SIZE  24      // 1 kayıt = 24B (uidLen+uid[7]+name[16])
#define AUTH_MAX       80      // Maks. 80 yetkili kart

// Log alanı (halka/döngüsel tampon)
#define LOG_START      (AUTH_START + AUTH_MAX * AUTH_REC_SIZE)
#define LOG_REC_SIZE   16      // 1 log = 16B (uidLen+uid[7]+ts(4)+allowed+pad)
#define LOG_CAPACITY   ((EEPROM_SIZE - LOG_START) / LOG_REC_SIZE) // Toplam log adedi
#define LOG_THRESHOLD  ((uint16_t)((LOG_CAPACITY * 90) / 100))    // %90 eşik

// Global nesneler
ESP8266WebServer server(80);   // HTTP 80 port
MFRC522 mfrc522(PIN_SS, PIN_RST);
RTC_DS3231 rtc;

// EEPROM kayıt şablonları (belgeleme amaçlı)
struct AuthRec {
  uint8_t uidLen;
  uint8_t uid[7];
  char name[16];               // NUL sonlu isim etiketi
};

struct LogRec {
  uint8_t uidLen;
  uint8_t uid[7];
  uint32_t ts;                 // UNIX zaman damgası
  uint8_t allowed;             // 1=OK, 0=NO
  uint8_t pad[3];              // hizalama
};

// Çalışma durumu (son okutulan vs.)
uint8_t lastUID[7] = {0};
uint8_t lastUIDLen = 0;
bool ds3231_ok = false;        // RTC hazır mı?

// EEPROM yardımcıları (16-bit okuma/yazma)
uint16_t e16(int addr) {
  uint16_t v = EEPROM.read(addr) | (EEPROM.read(addr+1) << 8);
  return v;
}
void w16(int addr, uint16_t v) {
  EEPROM.write(addr, v & 0xFF);
  EEPROM.write(addr+1, (v >> 8) & 0xFF);
}
void eepromCommit() { EEPROM.commit(); } // Değişiklikleri flash'a yaz

// UID karşılaştırma (uzunluk + içerik)
bool sameUID(const uint8_t *a, uint8_t alen, const uint8_t *b, uint8_t blen) {
  if (alen != blen) return false;
  for (uint8_t i=0;i<alen;i++) if (a[i]!=b[i]) return false;
  return true;
}

// RTC'den UNIX zamanını al (yoksa 0)
uint32_t nowUnix() {
  if (ds3231_ok) {
    DateTime now = rtc.now();
    return now.unixtime();
  }
  return 0;
}

// Buzzer: OK deseni
void beepOK() {
  tone(PIN_BUZZ, TONE_OK_FREQ); delay(TONE_MS_SHORT);
  noTone(PIN_BUZZ); delay(TONE_GAP_MS);
  tone(PIN_BUZZ, TONE_OK_FREQ); delay(TONE_MS_SHORT);
  noTone(PIN_BUZZ);
}

// Buzzer: NO deseni
void beepNO() {
  tone(PIN_BUZZ, TONE_NO_FREQ); delay(TONE_MS_LONG);
  noTone(PIN_BUZZ); delay(TONE_GAP_MS);
  tone(PIN_BUZZ, TONE_NO_FREQ); delay(TONE_MS_LONG);
  noTone(PIN_BUZZ);
}

// Röle sürme (aktif seviye dikkate alınır)
void relaySet(bool on) {
  bool level = RELAY_ACTIVE_HIGH ? on : !on;
  digitalWrite(PIN_RELAY, level ? HIGH : LOW);
}

// Web arayüzü için şifre koruması (HTTP Digest)
bool requireAuth() {
  if (!server.authenticate(WEB_USER, WEB_PASS)) {
    server.requestAuthentication(DIGEST_AUTH, "ESP Door Panel", "Authentication required");
    return false;
  }
  return true;
}

// EEPROM'u ilk kez hazırlama (imza/sürüm yoksa)
void eepromInitIfNeeded() {
  uint16_t magic = e16(0);
  uint16_t ver   = e16(2);
  if (magic != 0xBEEF || ver != 1) {
    w16(0, 0xBEEF);
    w16(2, 1);
    w16(4, 0);   // authCount = 0
    w16(6, 0);   // logHead = 0
    w16(8, 0);   // logTail = 0
    w16(10, 0);  // logCount = 0

    // Yetkili alanını boşla (0xFF = boş)
    for (int i=AUTH_START; i<LOG_START; i++) EEPROM.write(i, 0xFF);
    // Log alanını temizle (0x00)
    for (int i=LOG_START; i<EEPROM_SIZE; i++) EEPROM.write(i, 0x00);
    eepromCommit();
  }
}

// Yetkili sayısı (header'dan)
uint16_t authCount() { return e16(4); }

// UID yetkili listede var mı?
bool authFind(const uint8_t* uid, uint8_t uidLen, uint16_t* outIndex=nullptr) {
  uint16_t count = authCount();
  for (uint16_t i=0;i<count;i++) {
    int base = AUTH_START + i*AUTH_REC_SIZE;
    uint8_t len = EEPROM.read(base);
    if (len == 0xFF || len == 0) continue; // boş kayıt
    uint8_t tmp[7]; for (int k=0;k<7;k++) tmp[k]=EEPROM.read(base+1+k);
    if (sameUID(uid, uidLen, tmp, len)) {
      if (outIndex) *outIndex = i;
      return true;
    }
  }
  return false;
}

// Yeni yetkili kart ekleme (idempotent)
bool authAdd(const uint8_t* uid, uint8_t uidLen, const String& name) {
  if (uidLen==0 || uidLen>7) return false;        // Geçersiz UID uzunluğu
  if (authFind(uid, uidLen, nullptr)) return true; // Varsa tekrar yazma

  uint16_t count = authCount();
  if (count >= AUTH_MAX) return false;            // Kapasite dolu

  int base = AUTH_START + count*AUTH_REC_SIZE;    // Sıradaki boş slot
  EEPROM.write(base, uidLen);
  for (int k=0;k<7;k++) EEPROM.write(base+1+k, k<uidLen?uid[k]:0);

  char buf[16]; memset(buf, 0, sizeof(buf));      // İsim 16 bayta sığdır
  name.substring(0,15).toCharArray(buf, 16);
  for (int i=0;i<16;i++) EEPROM.write(base+8+i, (uint8_t)buf[i]);

  w16(4, count+1);                                // authCount++
  eepromCommit();
  return true;
}

// Yetkili kartları HTML listele
String authListHTML() {
  String s;
  s += "<h3>Authorized Cards (" + String(authCount()) + ")</h3><ol>";
  uint16_t count = authCount();
  for (uint16_t i=0;i<count;i++) {
    int base = AUTH_START + i*AUTH_REC_SIZE;
    uint8_t len = EEPROM.read(base);
    if (len==0xFF || len==0) continue;
    String uidhex;
    for (int k=0;k<len;k++) {
      uint8_t b = EEPROM.read(base+1+k);
      if (b<16) uidhex += "0";
      uidhex += String(b, HEX);
      if (k<len-1) uidhex += ":";
    }
    char name[16]; for (int j=0;j<16;j++) name[j]=EEPROM.read(base+8+j);
    name[15]='\0';
    s += "<li><b>" + uidhex + "</b> — " + String(name) + "</li>";
  }
  s += "</ol>";
  return s;
}

// Log baş/kuyruk/sayı (header alanından)
uint16_t logHead() { return e16(6); }
uint16_t logTail() { return e16(8); }
uint16_t logCount() { return e16(10); }

// Tek bir log kaydı yaz (ring buffer)
void logWriteOne(const uint8_t* uid, uint8_t uidLen, bool allowed) {
  uint16_t head = logHead();
  uint16_t tail = logTail();
  uint16_t cnt  = logCount();
  if (cnt >= LOG_THRESHOLD) {              // %90 dolduysa önce en eskisini düşür
    tail = (tail + 1) % LOG_CAPACITY;
    if (cnt > 0) cnt--;
  }

  int base = LOG_START + head * LOG_REC_SIZE; // Yazılacak slot
  EEPROM.write(base+0, uidLen);
  for (int k=0;k<7;k++) EEPROM.write(base+1+k, k<uidLen?uid[k]:0);
  uint32_t ts = nowUnix();                    // Zaman damgası
  for (int i=0;i<4;i++) EEPROM.write(base+8+i, (ts >> (8*i)) & 0xFF);
  EEPROM.write(base+12, allowed ? 1 : 0);     // OK/NO
  EEPROM.write(base+13, 0);
  EEPROM.write(base+14, 0);
  EEPROM.write(base+15, 0);

  head = (head + 1) % LOG_CAPACITY;          // head ileri
  if (cnt < LOG_CAPACITY) cnt++;             // sayaç artar

  w16(6, head);                              // header güncelle
  w16(8, tail);
  w16(10, cnt);
  eepromCommit();                            // kalıcı yaz
}

// Log doluluk yüzdesi
float logFillPercent() {
  if (LOG_CAPACITY == 0) return 0.f;
  return 100.0f * (float)logCount() / (float)LOG_CAPACITY;
}

// Zamanı okunur formata çevir
String tsToStr(uint32_t ts) {
  if (ts==0) return String("—");             // RTC yoksa tire
  DateTime dt(ts);
  char buf[24];
  snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
           dt.year(), dt.month(), dt.day(), dt.hour(), dt.minute(), dt.second());
  return String(buf);
}

// UID'yi HEX metne çevir (aa:bb:cc)
String uidToHex(const uint8_t* uid, uint8_t len) {
  String s;
  for (int i=0;i<len;i++){
    if (uid[i]<16) s+="0";
    s += String(uid[i], HEX);
    if (i<len-1) s += ":";
  }
  return s;
}

// Logları HTML tablo halinde üret
String logListHTML(int maxRows=100) {
  String s;
  s += "<h3>Logs (" + String(logCount()) + ") — Fill: " + String((int)logFillPercent()) + "%</h3>";
  s += "<table border=1 cellpadding=4 cellspacing=0><tr><th>#</th><th>Time</th><th>UID</th><th>Status</th></tr>";
  uint16_t tail = logTail();
  uint16_t cnt  = logCount();
  int shown = 0;
  for (uint16_t i=0; i<cnt && shown<maxRows; i++) {
    uint16_t idx = (tail + i) % LOG_CAPACITY; // İlk gösterilecek: en eski
    int base = LOG_START + idx * LOG_REC_SIZE;
    uint8_t len = EEPROM.read(base+0);
    uint8_t u[7]; for (int k=0;k<7;k++) u[k]=EEPROM.read(base+1+k);
    uint32_t ts =
      (uint32_t)EEPROM.read(base+8) |
      ((uint32_t)EEPROM.read(base+9)<<8) |
      ((uint32_t)EEPROM.read(base+10)<<16) |
      ((uint32_t)EEPROM.read(base+11)<<24);
    uint8_t allowed = EEPROM.read(base+12);

    s += "<tr><td>"+String(i+1)+"</td><td>" + tsToStr(ts) + "</td><td>" + uidToHex(u,len) + "</td><td>" + (allowed?"OK":"NO") + "</td></tr>";
    shown++;
  }
  s += "</table>";
  if (cnt>maxRows) s += "<p>… (" + String(cnt-maxRows) + " more hidden)</p>";
  s += "<form action='/wipe_logs' method='post'><button>Clear Logs</button></form>";
  return s;
}

// Kapı kilidini belirli süre aç
void unlockDoor() {
  relaySet(true);
  delay(DOOR_UNLOCK_MS);
  relaySet(false);
}

// Basit HTML şablon (üst kısım)
String pageHeader(const String& title) {
  String s;
  s += "<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>";
  s += "<title>"+title+"</title>";
  s += "<style>body{font-family:sans-serif;margin:16px}button{padding:8px 12px;margin:4px}table{width:100%;border-collapse:collapse}th,td{text-align:left}input[type=text]{padding:6px;width:100%;max-width:320px}</style>";
  s += "</head><body><h2>"+title+"</h2><p><a href='/'>Home</a> | <a href='/logs'>Logs</a> | <a href='/cards'>Cards</a> | <a href='/logout'>Logout</a></p>";
  return s;
}
// HTML şablon (alt kısım)
String pageFooter(){ return "</body></html>"; }

// Ana sayfa: özet bilgiler
void handleRoot() {
  if (!requireAuth()) return;          // Parola kontrolü
  String s = pageHeader("Door Access System");
  s += "<p><b>Last Scanned UID:</b> ";
  if (lastUIDLen) s += uidToHex(lastUID,lastUIDLen);
  else s += "—";
  s += "</p>";
  s += "<ul>";
  s += "<li><a href='/logs'><button>Logs</button></a></li>";
  s += "<li><a href='/cards'><button>Cards</button></a></li>";
  s += "</ul>";
  s += "<p>Log Fill: "+String((int)logFillPercent())+"%</p>";
  s += pageFooter();
  server.send(200, "text/html", s);
}

// Log listesi sayfası
void handleLogs() {
  if (!requireAuth()) return;
  String s = pageHeader("Logs");
  s += logListHTML(200);
  s += pageFooter();
  server.send(200, "text/html", s);
}

// Tüm logları temizle (POST)
void handleWipeLogs() {
  if (!requireAuth()) return;
  w16(6, 0);  // head=0
  w16(8, 0);  // tail=0
  w16(10, 0); // count=0
  for (int i=LOG_START; i<EEPROM_SIZE; i++) EEPROM.write(i, 0x00);
  eepromCommit();
  server.sendHeader("Location","/logs");
  server.send(303);
}

// Kartlar sayfası (liste + son kartı ekleme formu)
void handleCards() {
  if (!requireAuth()) return;
  String s = pageHeader("Cards");
  s += authListHTML();

  s += "<h3>Add Last Scanned Card</h3>";
  if (lastUIDLen) {
    s += "<form action='/add_last' method='post'>";
    s += "<p>UID: <code>"+uidToHex(lastUID,lastUIDLen)+"</code></p>";
    s += "<p>Name label: <input type='text' name='name' placeholder='e.g. Askan Card' required></p>";
    s += "<button>Save</button></form>";
  } else {
    s += "<p>No card scanned yet.</p>";
  }

  s += "<form action='/wipe_cards' method='post' onsubmit='return confirm(\"Delete ALL authorized cards?\")'><button>Clear Authorized Cards</button></form>";
  s += pageFooter();
  server.send(200, "text/html", s);
}

// Son okutulan kartı yetkili listeye ekle (POST)
void handleAddLast() {
  if (!requireAuth()) return;
  if (!lastUIDLen) { server.send(400,"text/plain","No last card"); return; }
  if (!server.hasArg("name")) { server.send(400,"text/plain","name required"); return; }
  String name = server.arg("name");
  name.trim();
  bool ok = authAdd(lastUID, lastUIDLen, name);
  if (!ok) server.send(500,"text/plain","add failed (maybe full)");
  else {
    server.sendHeader("Location","/cards");
    server.send(303);
  }
}

// Tüm yetkili kartları temizle (POST)
void handleWipeCards() {
  if (!requireAuth()) return;
  w16(4, 0); // authCount=0
  for (int i=AUTH_START; i<LOG_START; i++) EEPROM.write(i, 0xFF);
  eepromCommit();
  server.sendHeader("Location","/cards");
  server.send(303);
}

// RTC zamanı ayarla (GET /settime?ts=<unix>)
void handleSetTime() {
  if (!requireAuth()) return;
  if (!server.hasArg("ts")) { server.send(400,"text/plain","ts missing"); return; }
  uint32_t ts = (uint32_t) strtoul(server.arg("ts").c_str(), nullptr, 10);
  if (ts < 1500000000UL) { server.send(400,"text/plain","invalid ts"); return; }
  rtc.adjust(DateTime(ts));        // RTC'yi yeni zamana ayarla
  ds3231_ok = rtc.begin();         // Yeniden başlat/tesdi̇k
  server.send(200,"text/plain","OK");
}

// Oturumu sıfırlamak için yeni realm ile 401 tetikle
void handleLogout() {
  server.requestAuthentication(DIGEST_AUTH, "ESP Door Logout", "Logged out");
}

// RFID okuma ve iş akışı
void processRFID() {
  if (!mfrc522.PICC_IsNewCardPresent()) return; // Yeni kart var mı?
  if (!mfrc522.PICC_ReadCardSerial()) return;   // UID oku

  lastUIDLen = mfrc522.uid.size;
  for (int i=0;i<lastUIDLen && i<7;i++) lastUID[i]=mfrc522.uid.uidByte[i];

  bool allowed = authFind(lastUID, lastUIDLen, nullptr); // Yetkili mi?

  logWriteOne(lastUID, lastUIDLen, allowed);   // Logla (OK/NO, zaman)

  digitalWrite(PIN_LED, LOW);                  // LED kısa yan
  if (allowed) {
    beepOK();
    unlockDoor();                               // Röleyi tetikle
  } else {
    beepNO();
  }
  digitalWrite(PIN_LED, HIGH);

  mfrc522.PICC_HaltA();                         // Kart iletişimini kapat
  mfrc522.PCD_StopCrypto1();
}

// Kurulum (GPIO, EEPROM, RTC, Wi-Fi, SPI/RC522, HTTP rotalar)
void setup() {
  pinMode(PIN_LED, OUTPUT); digitalWrite(PIN_LED, HIGH);
  pinMode(PIN_RELAY, OUTPUT); relaySet(false);
  pinMode(PIN_BUZZ, OUTPUT); noTone(PIN_BUZZ);

  Serial.begin(115200);
  delay(100);

  EEPROM.begin(EEPROM_SIZE);
  eepromInitIfNeeded();

  Wire.begin(0, 3);              // I2C pinleri: SDA=GPIO0(D3), SCL=GPIO3(RX)
  ds3231_ok = rtc.begin();
  if (rtc.lostPower()) {
    rtc.adjust(DateTime(F(__DATE__), F(__TIME__))); // İlk kurulumda derleme zamanı
  }

  // Wi-Fi bağlan
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("WiFi connecting");
  int tries=0;
  while (WiFi.status()!=WL_CONNECTED && tries<60) {
    delay(500); Serial.print(".");
    tries++;
  }
  Serial.println();
  Serial.print("IP: "); Serial.println(WiFi.localIP());

  // RC522 başlat (SPI)
  SPI.begin();
  mfrc522.PCD_Init(PIN_SS, PIN_RST);

  // HTTP route tanımları
  server.on("/", handleRoot);
  server.on("/logs", handleLogs);
  server.on("/wipe_logs", HTTP_POST, handleWipeLogs);
  server.on("/cards", handleCards);
  server.on("/add_last", HTTP_POST, handleAddLast);
  server.on("/wipe_cards", HTTP_POST, handleWipeCards);
  server.on("/settime", handleSetTime);
  server.on("/logout", handleLogout);
  server.begin();
  Serial.println("Web server ready.");
}

// Ana döngü: HTTP istekleri + RFID kontrolü
void loop() {
  server.handleClient();
  processRFID();
}
