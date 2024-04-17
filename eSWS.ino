//#define DEBUG

// Software name and version
#define PROGNAME    "eSWS"
#define PROGVERS    "0.1"

// SD card chip select line
#define SDCS        (D8)

// Certificate and key
#define SSL_CERT    "/ssl/crt.pem"
#define SSL_KEY     "/ssl/key.pem"

// WiFi credentials
#define WIFI_CFG    "/wifi.cfg"
#define HOSTNAME    "/hostname"

// TCP port
#define PORT        (1965)

// LED configuration
#define LEDinv      (true)
#if defined(BUILTIN_LED)
#define LED         (BUILTIN_LED)
#elif defined(LED_BUILTIN)
#define LED         (LED_BUILTIN)
#else
#define LED         (13)
#endif



#define DBG_OUTPUT_PORT Serial

#include <ESP8266WiFi.h>
#include <ESP8266WiFiMulti.h>
#include <ESP8266WebServer.h>
#include <ESP8266mDNS.h>
#include <time.h>
#include <sntp.h>
#include <SPI.h>
#include <SD.h>


// WiFi multiple access points
ESP8266WiFiMulti wifiMulti;

// response headers
static const char *HEADER_GEM_OK            = "20 text/gemini\r\n";                 // .gmi
static const char *HEADER_MARKDOWN_OK       = "20 text/markdown\r\n";               // .md
static const char *HEADER_PLAIN_OK          = "20 text/plain\r\n";                  // .txt
static const char *HEADER_HTML_OK           = "20 text/html\r\n";                   // .htm
static const char *HEADER_JPEG_OK           = "20 image/jpeg\r\n";                  // .jpg
static const char *HEADER_PNG_OK            = "20 image/png\r\n";                   // .png
static const char *HEADER_BIN_OK            = "20 application/octet-stream\r\n";    // other stuff
static const char *HEADER_NOT_FOUND         = "51 File Not Found\r\n";
static const char *HEADER_INTERNAL_FAIL     = "50 Internal Server Error\r\n";
static const char *HEADER_INVALID_URL       = "59 Invalid URL\r\n";

// TLS server
// openssl req -new -x509 -keyout key.pem -out cert.pem -days 3650 -nodes -subj "/C=RO/ST=Bucharest/L=Bucharest/O=Eridu/OU=IT/CN=eridu.eu.org" -addext "subjectAltName=DNS:*.eridu.eu.org,DNS:*.eridu.duckdns.org,DNS:gemini.local,DNS:localhost"
BearSSL::WiFiServerSecure server(PORT);
BearSSL::X509List         *srvCert;
BearSSL::PrivateKey       *srvKey;
// #define USE_EC       // Enable Elliptic Curve signed cert
//#define CACHE_SIZE 5  // Number of sessions to cache.
//#define USE_CACHE     // Enable SSL session caching.
// Caching SSL sessions shortens the length of the SSL handshake.
// You can see the performance improvement by looking at the
// Network tab of the developer tools of your browser.
// #define DYNAMIC_CACHE // Whether to dynamically allocate the cache.

#if defined(USE_CACHE) && defined(DYNAMIC_CACHE)
// Dynamically allocated cache.
BearSSL::ServerSessions   serverCache(CACHE_SIZE);
#elif defined(USE_CACHE)
// Statically allocated cache.
ServerSession             store[CACHE_SIZE];
BearSSL::ServerSessions   serverCache(store, CACHE_SIZE);
#endif

// HTTP
ESP8266WebServer srvHTTP(80);
// Spartan
WiFiServer srvSpartan(300);
// Gopher
WiFiServer srvGopher(70);

// Networking stuff
char *host;
char *ssid;
char *pass;
char buf[1025];

// Load the certificate and the key from storage
void loadCertKey() {
  File file;
  Serial.print(F("GEMD: Reading certificate from ")); Serial.print(SSL_CERT); Serial.print(F(" ... "));
  file = SD.open(SSL_CERT, "r");
  if (file.isFile()) {
    Serial.println();
    srvCert = new BearSSL::X509List(file, file.size());
  }
  else
    Serial.println(F("ERROR"));
  file.close();
  Serial.print(F("GEMD: Reading key from ")); Serial.print(SSL_KEY); Serial.print(F(" ... "));
  file = SD.open(SSL_KEY, "r");
  if (file.isFile()) {
    Serial.println();
    srvKey = new BearSSL::PrivateKey(file, file.size());
  }
  else
    Serial.println(F("ERROR"));
  file.close();
}

// Load WiFi configuration
void initWiFi() {
  int  len = 0xFF;
  File file;

  WiFi.mode(WIFI_STA);
  // Read the host name
  Serial.print(F("GEMD: Reading host name from ")); Serial.print(HOSTNAME); Serial.print(F(" ... "));
  file = SD.open(HOSTNAME, "r");
  if (file.isFile()) {
    len = file.read((uint8_t*)buf, 255);
    char *token = strtok(buf, "\t\r\n");
    if (token != NULL) {
      Serial.println(); Serial.print(F("GEMD: Setting host name to '")); Serial.print(token); Serial.println(F("'"));
      host = new char[strlen(token) + 1];
      strcpy(host, token);
      WiFi.hostname(host);
    }
  }
  else
    Serial.println(F("ERROR"));
  file.close();

  // Read the WiFi configuration
  Serial.print(F("GEMD: Reading WiFi configuration from ")); Serial.print(WIFI_CFG); Serial.print(F(" ... "));
  file = SD.open(WIFI_CFG, "r");
  if (file.isFile()) {
    while (true) {
      yield();
      int i = 0;
      char c;
      while (c = file.read()) {
        // SSID must start with a character
        if (i == 0 and c < 32) continue;
        // Limit line length
        if (i >= 255) break;
        buf[i++] = c;
        // Break on reading newline or no char available
        if (c == '\r' or c == '\n' or c == 255) break;
      }
      // Break on no char available
      if (c == 255) break;
      buf[i] = '\0';
      // Skip over comment lines
      if (buf[0] == '#') continue;
      // Find the SSID and the PSK, TAB-separated
      ssid = strtok((char*)buf, "\t");
      pass = strtok(NULL, "\r\n\t");
      // Add SSID and PASS to WiFi Multi
      if (ssid != NULL and pass != NULL) {
        Serial.println(); Serial.print(F("GEMD: Add '")); Serial.print(ssid); Serial.print(F("' "));
#ifdef DEBUG
        Serial.print(F("with pass '")); Serial.print(pass); Serial.print(F("' "));
#endif
        wifiMulti.addAP(ssid, pass);
      }
    }
    Serial.println();
  }
  else
    Serial.println(F("ERROR"));
  file.close();
}

// Set time via NTP, as required for x.509 validation
// TODO Need a timeout
void setClock() {
  // https://www.gnu.org/software/libc/manual/html_node/TZ-Variable.html
  const char *TZstr = "EET-2EEST,M3.5.0/3,M10.5.0/4";
  //configTime(3 * 3600, 0, "pool.ntp.org", "time.nist.gov");
  //configTime("TZ_Europe_Bucharest", "pool.ntp.org", "time.nist.gov");

  sntp_stop();
  sntp_setservername(0, "pool.ntp.org");
  setenv("TZ", TZstr, 1);
  tzset();
  sntp_init();

  Serial.print(F("GEMD: Waiting for NTP time sync "));
  time_t now = time(nullptr);
  while (now < 8 * 3600 * 2) {
    delay(500);
    Serial.print(".");
    now = time(nullptr);
  }
  Serial.println();
  struct tm timeinfo;
  gmtime_r(&now, &timeinfo);
  Serial.print(F("GEMD: Current time: "));
  Serial.print(asctime(&timeinfo));
}


void handleClient(WiFiClient *client) {
  client->println("2 text/plain; charset=utf-8");
  client->println("Hi, Bob!");
  client->flush();
  client->stop();
}


void handleClient(BearSSL::WiFiClientSecure *client) {
  char *rsp = (char*)HEADER_INVALID_URL;
  client->setTimeout(5000);
  while (client->connected()) {
    int len = 0;
    char c;
    while (client->available()) {
      // Read one char
      c = client->read();
      // URL must start with a character
      if (len == 0 and c < 32) continue;
      // Limit line length
      if (len >= 1023) {
        len = 0;
        break;
      }
      buf[len++] = c;
      // Break on reading newline or no char available
      if (c == '\r' or c == '\n' or c == 255) break;
    }
    // Break on no char available
    if (c == 255) break;
    buf[len] = '\0';

    if (len) {
      Serial.print(F("GEMD: Request ("));
      Serial.print(len);
      Serial.print(" bytes) '");
      Serial.print(buf);
      Serial.println("'");

      char *pSchema, *pHost, *pPort, *pPath, *pQuery, *pEOL;

      // Find CRLF as EOL
      pEOL = strchr(buf, '\r');
      if (pEOL == NULL) return;
      pEOL[0] = '\0';

      // Find the schema
      if (strncmp(buf, "gemini://", 9) == 0) {
        Serial.println(buf);
        pSchema = buf;
        pSchema[6] = '\0';
        pHost = pSchema + 7;
        // Move the host down 2 chars
        int i;
        for (i = 0; pHost[i + 2] != '/' and pHost[i + 2] != '?' and pHost[i + 2] != '\0'; i++)
          pHost[i] = pHost[i + 2];
        pHost[i] = '\0';
        // Find the requested path
        if (pHost[i + 2] == '/') {
          pPath = &pHost[i + 2];
          pHost[i + 1] = '\0';
        }
        else  {
          pPath = &pHost[i + 1];
          pPath[0] = '/';
        }

        // Find the port, if any
        pPort = strchr(pHost, ':');
        if (pPort == NULL)
          pPort = pEOL;
        else {
          pPort[0] = '\0';
          pPort++;
        }
        // Find the query
        pQuery = strchr(pPath, '?');
        if (pQuery != NULL) {
          pQuery[0] = '\0';
          pQuery++;
        }
        else
          pQuery = pEOL;

        Serial.print(F("Schema: ")); Serial.println(pSchema);
        Serial.print(F("Host: ")); Serial.println(pHost);
        Serial.print(F("Port: ")); Serial.println(pPort);
        Serial.print(F("Path: ")); Serial.println(pPath);
        Serial.print(F("Query: ")); Serial.println(pQuery);


        // Validate the path (../../ ...)

        // Virtual hosting

        // Dinamically create the file path ("/gemini" + path (+ "index.gmi"))
        char *filePath = new char[strlen(pPath) + strlen(host) + 20];
        strcpy(filePath, "/");
        strcat(filePath, host);
        strcat(filePath, pPath);


        Serial.println(filePath);
        File file = SD.open(filePath, "r");
        if (file.isDirectory()) {
          file.close();
          if (filePath[strlen(filePath) - 1] != '/')
            strcat(filePath, "/");
          strcat(filePath, "index.gmi");
          file = SD.open(filePath, "r");
        };

        if (file.isFile()) {
          // Detect mime type
          char *pExt = strrchr(filePath, '.');
          if (pExt == NULL)
            client->print(HEADER_BIN_OK);
          else {
            pExt++;
            if (strcmp(pExt, "gmi") == 0)
              client->print(HEADER_GEM_OK);
            else if (strcmp(pExt, "txt") == 0)
              client->print(HEADER_PLAIN_OK);
            else if (strcmp(pExt, "md") == 0)
              client->print(HEADER_MARKDOWN_OK);
            else if (strcmp(pExt, "jpg") == 0 or strcmp(pExt, "jpeg") == 0)
              client->print(HEADER_JPEG_OK);
            else if (strcmp(pExt, "htm") == 0 or strcmp(pExt, "html") == 0)
              client->print(HEADER_HTML_OK);
            else if (strcmp(pExt, "png") == 0)
              client->print(HEADER_PNG_OK);
            else
              client->print(HEADER_BIN_OK);
          }
          //Send content
          uint8_t fileBuf[512];
          while (file.available()) {
            int len = file.read(fileBuf, 512);
            client->write(fileBuf, len);
          }
          file.close();
        }
        else if (strcmp(pPath, "/status.gmi") == 0) {
          client->print(HEADER_GEM_OK);
          client->print("# Server status\n");
          //client->print(("IP address: " + WiFi.localIP().toString() + "\n").c_str());
          //client->write(("Free memory: " + String(ESP.getFreeHeap()) + " bytes\n").c_str());
          //client->write(("Power voltage: " + String(analogRead(0)) + "V\n").c_str());
          //client->write(("Uptime: " + String(millis() / 1000) + " seconds\n").c_str());
          //client->write(("Connected to: " + WiFi.SSID() + "\n").c_str());
          //client->write(("Hostname: " + String(HOSTNAME) + "\n").c_str());
          //client->write(("Signal strength: " + String(WiFi.RSSI()) + "dBm\n").c_str());
        }
        else
          client->print(HEADER_NOT_FOUND);

        // Destroy the file path string
        delete(filePath);

      }
      else
        client->print(HEADER_INVALID_URL);

      client->flush();
      client->stop();
    }
  }
}




void handleHTTPRoot() {
  srvHTTP.send(200, "text / plain", "Hi, Bob!");
}

// Main Arduino setup function
void setup() {
  // Configure the LED
  pinMode(LED, OUTPUT);
  digitalWrite(LED, LOW ^ LEDinv);

  // Serial port configuration
  Serial.flush();
  Serial.begin(115200);
  Serial.print(F("\r\n"));
  Serial.print(F("\r\n"));

  // SPI
  SPI.begin();
  // Init SD card
  Serial.print(F("GEMD: Initializing SD card: "));
  if (!SD.begin(SDCS)) {
    Serial.println(F("failed!"));
    while (true) {
      yield();
      // Flash the led
      digitalWrite(LED, HIGH ^ LEDinv);
      delay(50);
      digitalWrite(LED, LOW ^ LEDinv);
      delay(50);
      digitalWrite(LED, HIGH ^ LEDinv);
      delay(50);
      digitalWrite(LED, LOW ^ LEDinv);
      delay(250);
    }
  }
  else {
    switch (SD.type()) {
      case 1:  Serial.print(F("SD1"));  break;
      case 2:  Serial.print(F("SD2"));  break;
      case 3:  Serial.print(F("SDHC")); break;
      default: Serial.println(F("Unknown"));
    }
    Serial.printf(" FAT % d % dMb\r\n", SD.fatType(), SD.size64() / 1048576);
    // Set time callback
    //SD.setTimeCallback(timeCallback);
  }

  // Connect to WiFi
  initWiFi();

  // Configure secure server
  loadCertKey();
#ifndef USE_EC
  server.setRSACert(srvCert, srvKey);
#else
  server.setECCert(srvCert, BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN, srvKey);
#endif
  // Set the server's cache
#if defined(USE_CACHE)
  server.setCache(&serverCache);
#endif

  /*
    // list files in SD
    File root = SD.open(" / gemini / ");
    while (File entry = root.openNextFile()) {
    Serial.print(entry.name());
    Serial.print("\t\t");
    Serial.print(entry.size(), DEC);
    time_t cr = entry.getCreationTime();
    time_t lw = entry.getLastWrite();
    struct tm* tmstruct = localtime(&cr);
    Serial.printf("\tCREATION: % d - % 02d - % 02d % 02d: % 02d: % 02d", (tmstruct->tm_year) + 1900, (tmstruct->tm_mon) + 1, tmstruct->tm_mday, tmstruct->tm_hour, tmstruct->tm_min, tmstruct->tm_sec);
    tmstruct = localtime(&lw);
    Serial.printf("\tLAST WRITE: % d - % 02d - % 02d % 02d: % 02d: % 02d\n", (tmstruct->tm_year) + 1900, (tmstruct->tm_mon) + 1, tmstruct->tm_mday, tmstruct->tm_hour, tmstruct->tm_min, tmstruct->tm_sec);
    }
  */


  srvHTTP.on("/", handleHTTPRoot);
  //server.onNotFound(handleNotFound);


}

// Main Arduino loop
void loop() {
  static bool reconn = true;
  if (wifiMulti.run(5000) == WL_CONNECTED) {
    if (reconn) {
      // Connected
      Serial.println(F("GEMD: WiFi connected"));
      Serial.print(F("GEMD: SSID: "));
      Serial.println(WiFi.SSID());
      Serial.print(F("GEMD: IP address: "));
      Serial.println(WiFi.localIP());

      // Set up mDNS responder:
      if (!MDNS.begin(host)) {
        Serial.println(F("GEMD: Error setting up MDNS"));
      }
      else {
        MDNS.addService("gemini", "tcp", PORT);
        MDNS.addService("http",   "tcp", 80);
        MDNS.addService("gopher", "tcp", 70);
        Serial.println(F("GEMD: mDNS responder started"));
      }

      // Set clock
      setClock();

      // Start accepting connections
      server.begin();
      Serial.print(F("GEMD: Gemini server '")); Serial.print(host); Serial.print(F(".local' started on ")); Serial.print(WiFi.localIP()); Serial.print(": "); Serial.println(PORT);
      srvHTTP.begin();
      Serial.println("HTTP server started");

      srvSpartan.begin();
      srvGopher.begin();

      reconn = false;
    }


    MDNS.update();

    srvHTTP.handleClient();

    BearSSL::WiFiClientSecure client = server.available();
    if (client) {
      // LED on
      digitalWrite(LED, HIGH ^ LEDinv);

      //std::vector<uint16_t> cyphers = { BR_TLS_RSA_WITH_AES_256_CBC_SHA256, BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, BR_TLS_RSA_WITH_3DES_EDE_CBC_SHA };
      //client.setCiphers(cyphers);

      //client.setFingerprint("39b2204993bab61373aed82c24a20919b4bb7a9fb6c9342452b3e5f6836848de");

      // Handle the client
      handleClient(&client);
      //client.flush();
      //client.stop();

      // LED off
      digitalWrite(LED, LOW ^ LEDinv);
    }

    WiFiClient spartan  = srvSpartan.available();
    if (spartan) {
      // LED on
      digitalWrite(LED, HIGH ^ LEDinv);
      // Handle the client
      handleClient(&spartan);
      // LED off
      digitalWrite(LED, LOW ^ LEDinv);
    }


    WiFiClient gopher  = srvGopher.available();
    if (gopher) {
      // LED on
      digitalWrite(LED, HIGH ^ LEDinv);
      // Handle the client
      handleClient(&gopher);
      // LED off
      digitalWrite(LED, LOW ^ LEDinv);
    }

  }
  else {
    Serial.println(F("GEMD: WiFi disconnected"));
    MDNS.end();
    server.stop();
    srvHTTP.stop();
    reconn = true;
  }
}
