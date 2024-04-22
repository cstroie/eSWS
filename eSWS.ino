//#define DEBUG

//#define USE_UPNP

// Software name and version
#define PROGNAME    "eSWS"
#define PROGVERS    "0.1"

// Certificate and key
#define SSL_CERT    "/ssl/crt.pem"
#define SSL_KEY     "/ssl/key.pem"

// WiFi credentials
#define WIFI_CFG    "/wifi.cfg"
#define HOSTNAME    "/hostname.cfg"
#define DDNS_TOK     "/duckdns.cfg"

// Mime types
#define MIMETYPE    "/mimetype.cfg"

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




#include <ESP8266WiFi.h>
#include <ESP8266WiFiMulti.h>
#include <ESP8266WebServer.h>
#include <ESP8266HTTPClient.h>
#include <ESP8266mDNS.h>
#include <time.h>
#include <TZ.h>
#include <sntp.h>
#include <SPI.h>
#include <SD.h>

// UPnP
#ifdef USE_UPNP
#  include "TinyUPnP.h"
TinyUPnP *tinyUPnP = new TinyUPnP(5000);
#endif

// WiFi multiple access points
ESP8266WiFiMulti wifiMulti;

// SD card CS pins
int spiCS = -1;
int spiCSPins[] = {D4, D8, D1, D2, D3, D0};



// Protocols
enum proto_t {GEMINI, SPARTAN, GOPHER, HTTP};

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
// openssl req -new -x509 -keyout key.pem -out crt.pem -days 3650 -nodes -subj "/C=RO/ST=Bucharest/L=Bucharest/O=Eridu/OU=IT/CN=esws.duckdns.org" -addext "subjectAltName=DNS:eridu.eu.org,DNS:*.esws.duckdns.org,DNS:esws.local,DNS:localhost"
BearSSL::WiFiServerSecure srvGemini(PORT);
BearSSL::X509List         *srvCert;
BearSSL::PrivateKey       *srvKey;
// #define USE_EC       // Enable Elliptic Curve signed cert
#define CACHE_SIZE 5  // Number of sessions to cache.
#define USE_CACHE     // Enable SSL session caching.
// Caching SSL sessions shortens the length of the SSL handshake.
// You can see the performance improvement by looking at the
// Network tab of the developer tools of your browser.
//#define DYNAMIC_CACHE // Whether to dynamically allocate the cache.

#if defined(USE_CACHE) && defined(DYNAMIC_CACHE)
// Dynamically allocated cache.
BearSSL::ServerSessions   sslCache(CACHE_SIZE);
#elif defined(USE_CACHE)
// Statically allocated cache.
ServerSession             sslStore[CACHE_SIZE];
BearSSL::ServerSessions   sslCache(sslStore, CACHE_SIZE);
#endif

// HTTP
ESP8266WebServer srvHTTP(80);
// Spartan
WiFiServer srvSpartan(300);
// Gopher
WiFiServer srvGopher(70);

// Networking stuff
char *host;
char *fqdn;
char *ddns;
char *ssid;
char *pass;
char buf[1025];

// Mime types list
struct MimeTypeEntry {
  char *ext;
  char *typ;
};
// Dynamically allocated vector to keep the associations
std::vector<MimeTypeEntry> mtList;

// Log time format
#define LOG_TIMEFMT "[%d/%b/%Y:%H:%M:%S %z]"
char tmbuf[30];


// Read one line from stream, delimited by the specified char,
// with maximum of specified lenght, and return the lenght read string
int readln(Stream *stream, char *buf, int maxLen = 1024) {
  int len = 0;
  char c;
  while (stream->available()) {
    // Read one char
    c = stream->read();
    // Limit line length
    if (len > maxLen - 1) {
      len = -1;
      break;
    }

    // Will always store CRLF, then ZERO
    if (c == '\r' or c == '\0') {
      // Consume one more char if CRLF
      if (c == '\r' and stream->peek() == '\n')
        stream->read();
      buf[len++] = '\r';
      buf[len++] = '\n';
      buf[len] = '\0';
      break;
    }
    else
      buf[len++] = c;
  }
  Serial.println(buf);
  // Return the lenght
  return len;
}

// Read one line from file, delimited by the specified char,
// with maximum of specified lenght, and return the lenght read string
int readln(File *file, char *buf, int maxLen = 1024) {
  int len = 0;
  char c;
  while (file->available()) {
    // Read one char
    c = file->read();
    // Line must start with a non-control character
    if (len == 0 and c < 32) continue;
    // Limit line length
    if (len > maxLen - 1) {
      len = -1;
      break;
    }
    buf[len++] = c;
    // Break on reading delimiter or no char available
    if (c == '\r' or c == '\n' or c == '\0') break;
  }
  // Ensure a zero-terminated string
  buf[len] = '\0';
  // Return the lenght
  return len;
}

// Load the certificate and the key from storage
void loadCertKey() {
  File file;
  Serial.print(F("SYS: Reading SSL certificate from ")); Serial.print(SSL_CERT); Serial.print(F(" ... "));
  file = SD.open(SSL_CERT, "r");
  if (file.isFile()) {
    Serial.println();
    srvCert = new BearSSL::X509List(file, file.size());
  }
  else
    Serial.println(F("ERROR"));
  file.close();
  Serial.print(F("SYS: Reading SSL key from ")); Serial.print(SSL_KEY); Serial.print(F(" ... "));
  file = SD.open(SSL_KEY, "r");
  if (file.isFile()) {
    Serial.println();
    srvKey = new BearSSL::PrivateKey(file, file.size());
  }
  else
    Serial.println(F("ERROR"));
  file.close();
}

// Load hostname configuration
void setHostname() {
  int len = 1024;
  // Read the host name
  Serial.print(F("SYS: Reading host name from ")); Serial.print(HOSTNAME); Serial.print(F(" ... "));
  File file = SD.open(HOSTNAME, "r");
  if (file.isFile()) {
    len = file.read((uint8_t*)buf, 255);
    char *token = strtok(buf, "\t\r\n");
    if (token != NULL) {
      fqdn = strdup(token);
      // Find the first occurence of '.' in FQDN
      char *dom = strchr(token, '.');
      if (dom != NULL) {
        dom[0] = '\0';
        host = strdup(token);
      }
      else
        host = fqdn;
      Serial.println(); Serial.print(F("SYS: Setting host name to '")); Serial.print(token); Serial.println(F("'"));
      WiFi.hostname(host);
    }
  }
  else
    Serial.println(F("ERROR"));
  file.close();
}

// Load DuckDNS configuration
void loadDuckDNS() {
  int len = 1024;
  // Read the DuckDNS token
  Serial.print(F("DNS: Reading DuckDNS token from ")); Serial.print(DDNS_TOK); Serial.print(F(" ... "));
  File file = SD.open(DDNS_TOK, "r");
  if (file.isFile()) {
    len = file.read((uint8_t*)buf, 255);
    char *token = strtok(buf, "\t\r\n");
    if (token != NULL) {
      Serial.println(F("done."));
      ddns = new char[strlen(token) + 1];
      strcpy(ddns, token);
    }
  }
  else
    Serial.println(F("ERROR"));
  file.close();
}

// Load WiFi configuration
void initWiFi() {
  int len = 1024;
  // Read the WiFi configuration
  Serial.print(F("WFI: Reading WiFi configuration from ")); Serial.print(WIFI_CFG); Serial.print(F(" ... "));
  File file = SD.open(WIFI_CFG, "r");
  if (file.isFile()) {
    while (len > 0) {
      // Read one line from file
      len = readln(&file, buf, 256);
      // Skip over comment lines
      if (buf[0] == '#') continue;
      // Find the SSID and the PASS, TAB-separated
      ssid = strtok((char*)buf, "\t");
      pass = strtok(NULL, "\r\n\t");
      // Add SSID and PASS to WiFi Multi
      if (ssid != NULL and pass != NULL) {
        Serial.println(); Serial.print(F("WFI: Add '")); Serial.print(ssid); Serial.print(F("' "));
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

// Load mime-types
void loadMimeTypes() {
  int len = 1024;
  char *ext;
  char *typ;
  // Read the mime-type definitions
  Serial.print(F("MIM: Reading mime-types from ")); Serial.print(MIMETYPE); Serial.print(F(" ... "));
  File file = SD.open(MIMETYPE, "r");
  if (file.isFile()) {
    while (len > 0) {
      // Read one line from file
      len = readln(&file, buf, 256);
      // Skip over comment lines
      if (buf[0] == '#') continue;
      // Find the extension and the mime type, TAB-separated
      ext = strtok((char*)buf, "\t");
      typ = strtok(NULL, "\r\n\t");
      // Append to vector
      if (ext != NULL and typ != NULL) {
        Serial.println(); Serial.print(F("MIM: Add '")); Serial.print(typ); Serial.print(F("' for '"));
        Serial.print(ext); Serial.print(F("' "));
        MimeTypeEntry mtNew;
        mtNew.ext = strdup(ext);
        mtNew.typ = strdup(typ);
        mtList.push_back(mtNew);
      }
    }
    // Shrink the vector now
    mtList.shrink_to_fit();
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

  configTime(TZ_Europe_Bucharest, "pool.ntp.org", "time.nist.gov");

  /*
    sntp_stop();
    sntp_setservername(0, "pool.ntp.org");
    setenv("TZ", TZstr, 1);
    tzset();
    sntp_init();
  */

  yield();

  Serial.print(F("NTP: Waiting for NTP time sync "));
  time_t now = time(nullptr);
  while (now < 8 * 3600 * 2) {
    delay(500);
    Serial.print(".");
    now = time(nullptr);
  }
  Serial.println();
  struct tm timeinfo;
  gmtime_r(&now, &timeinfo);
  Serial.print(F("NTP: Current time: "));
  Serial.print(ctime(&now));
}

// Update DuckDNS
bool upDuckDNS(char *subdomain, char *token) {
  bool updated = false;
  WiFiClient client;
  HTTPClient http;
  String request = "http://www.duckdns.org/update/" + String(subdomain) + "/" + String(token);
  http.begin(client, request);
  int httpCode = http.GET();
  if (httpCode == HTTP_CODE_OK) {
    String payload = http.getString();
    if (payload == "OK")
      updated = true;
  }
  http.end();
  return updated;
}

void sendFile(Stream *client, proto_t proto, char *pHost, char *pPath, char *pExt, const char *pFile) {
  int dirEnd = 0;
  // Validate the path (../../ ...)

  // Virtual hosting
  int hostLen = strlen(host);
  // Find the longest host name
  if (pHost != NULL)
    if (hostLen < strlen(pHost))
      hostLen = strlen(pHost);
  // Dinamically create the file path ("/" + host + path (+ "index.gmi"))
  char *filePath = new char[strlen(pPath) + hostLen + 20];
  strcpy(filePath, "/");
  // Check if the hostname and request host are the same and append the host
  if (pHost == NULL)
    strcat(filePath, host);
  else if (strncmp(host, pHost, strlen(host)) == 0 and strncmp(&pHost[strlen(host)], ".local", 6) == 0)
    strcat(filePath, host);
  else {
    strcat(filePath, pHost);
    // Check the virtual host directory exists
    File file = SD.open(filePath, "r");
    if (!file.isDirectory()) {
      Serial.println("No virtual directory");
      // Fallback to default
      file.close();
      strcpy(filePath, "/");
      strcat(filePath, host);
    }
  }
  // Append the path
  if (filePath[strlen(filePath) - 1] != '/' and pPath[0] != '/')
    strcat(filePath, "/");
  strcat(filePath, pPath);
  Serial.println(filePath);

  for (int i = 0; i <= strlen(filePath); i++) {
    Serial.print(i);
    Serial.print("\t");
    Serial.print((char)filePath[i]);
    Serial.print("\t");
    Serial.println((int)filePath[i]);
  }

  // Check if directory and append default file name for protocol
  File file = SD.open(filePath, "r");
  if (file.isDirectory()) {
    Serial.println("Path is directory");

    file.close();
    if (filePath[strlen(filePath) - 1] != '/')
      strcat(filePath, "/");
    dirEnd = strlen(filePath);
    Serial.println(dirEnd);
    strcat(filePath, pFile);
    file = SD.open(filePath, "r");
    Serial.println(filePath);
  };
  Serial.println("Path is not directory");

  Serial.print(F("DBG: File path: "));
  Serial.println(filePath);

  // Check if the file exists
  if (file.isFile()) {
    // Detect mime type
    pExt = strrchr(filePath, '.');
    if (proto != GOPHER) {
      if (pExt == NULL)
        client->print(HEADER_BIN_OK);
      else {
        pExt++;
        // Find the mime type
        char *mimetype = NULL;
        for (auto entry : mtList) {
          if (strncmp(entry.ext, pExt, 3) == 0) {
            mimetype = entry.typ;
            break;
          }
        }
        // TODO Add gopher and http
        if (proto == GEMINI)
          client->print("20 ");
        else if (proto == SPARTAN)
          client->print("2 ");
        if (mimetype == NULL)
          client->print("application/octet-stream\r\n");
        else {
          client->print(mimetype);
          client->print(" \r\n");
        }
      }
    }
    // Send content
    uint8_t fileBuf[512];
    while (file.available()) {
      int len = file.read(fileBuf, 512);
      client->write(fileBuf, len);
    }
    file.close();
  }
  else if (dirEnd > 0) {
    // The request was for a directory and there is no directory index.
    // Create a file listing
    // Restore the directory path
    filePath[dirEnd] = '\0';
    // Send the response
    switch (proto) {
      case GOPHER:
        client->print("iContent of ");
        client->print(pPath);
        client->print("\t\tnull\t1\r\n");
        client->print("i\t\tnull\t1\r\n");
        break;
      case SPARTAN:
        client->print("2 text/gemini\r\n");
        client->print("# Content of ");
        client->print(pPath);
        client->print("\r\n\r\n");
        break;
      case HTTP:
        break;
      default:
        client->print(HEADER_GEM_OK);
        client->print("# Content of ");
        client->print(pPath);
        client->print("\r\n\r\n");
    }
    // List files in SD
    File root = SD.open(filePath);
    while (File entry = root.openNextFile()) {
      // Hidden files
      if (entry.name()[0] == '.') continue;
      switch (proto) {
        case GOPHER:
          if (entry.isDirectory())
            client->print("1");
          else
            client->print("0");
          client->print(entry.name());
          client->print("\t");
          if (pPath[0] != '/')
            client->print("/");
          client->print(pPath);
          if (pPath[strlen(pPath) - 1] != '/')
            client->print("/");
          client->print(entry.name());
          if (entry.isDirectory())
            client->print("/");
          client->print("\t");
          client->print(pHost);
          client->print("\t70\r\n");
          break;
        case HTTP:
          break;
        case SPARTAN:
        default:
          client->print("=> ");
          client->print(pPath);
          if (pPath[strlen(pPath) - 1] != '/')
            client->print("/");
          client->print(entry.name());
          client->print("\t");
          client->print(entry.name());
          if (entry.isDirectory())
            client->print("/");
          client->print("\r\n");
      }
    }
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

// Handle Gemini protocol
void clGemini(BearSSL::WiFiClientSecure *client) {
  char *pSchema, *pHost, *pPort, *pPath, *pExt, *pQuery, *pEOL;
  char *rsp = (char*)HEADER_INVALID_URL;
  client->setTimeout(5000);
  while (client->connected()) {
    // Read one line from request
    int len = readln(client, buf);
    // Check the length
    if (len == 0) continue;

    // Log
    struct tm timeinfo;
    getLocalTime(&timeinfo);
    strftime(tmbuf, 30, LOG_TIMEFMT, &timeinfo);
    Serial.print(F("LOG: "));
    Serial.print(client->remoteIP());
    Serial.print(" - - ");
    Serial.print(tmbuf);
    Serial.print (" \"");
    Serial.print(buf);
    Serial.print("\" ");
    Serial.println();

    // Check if invalid request
    if (len < 0)
      client->print("59 Invalid URL\r\n");

    // EOL at CRLF chars
    pEOL = &buf[len - 2];
    pEOL[0] = '\0';

    // Find the schema
    if (strncmp(buf, "gemini://", 9) == 0) {
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

      /*
            Serial.print(F("Schema: ")); Serial.println(pSchema);
            Serial.print(F("Host:   ")); Serial.println(pHost);
            Serial.print(F("Port:   ")); Serial.println(pPort);
            Serial.print(F("Path:   ")); Serial.println(pPath);
            Serial.print(F("Query:  ")); Serial.println(pQuery);
      */

      // Send the requested file or the generated response
      sendFile(client, GEMINI, pHost, pPath, pExt, "index.gmi");
    }
    else
      client->print(HEADER_INVALID_URL);

    client->flush();
    client->stop();
  }
}

// Handle Spartan protocol
void clSpartan(WiFiClient * client) {
  char *pHost, *pPath, *pExt, *pQuery, *pLen, *pEOL;
  long int lQuery;
  client->setTimeout(5000);
  while (client->connected()) {
    // Read one line from request
    int len = readln(client, buf);
    // Check the length
    if (len == 0) continue;

    // Log
    struct tm timeinfo;
    getLocalTime(&timeinfo);
    strftime(tmbuf, 30, LOG_TIMEFMT, &timeinfo);
    Serial.print(F("LOG: "));
    Serial.print(client->remoteIP());
    Serial.print(" - - ");
    Serial.print(tmbuf);
    Serial.print (" \"");
    Serial.print(buf);
    Serial.print("\" ");
    Serial.println();

    // Check if invalid request
    if (len < 0)
      client->print("4 Invalid URL\r\n");

    // EOL at CRLF chars
    pEOL = &buf[len - 2];
    pEOL[0] = '\0';

    // Find the host
    pHost = buf;
    // Find the path
    pPath = strchr(pHost, ' ');
    if (pPath == NULL)
      return;
    else {
      pPath[0] = '\0';
      pPath++;
    }
    // Find the length
    pLen = strchr(pPath, ' ');
    if (pLen == NULL)
      return;
    else {
      pLen[0] = '\0';
      pLen++;
      // Convert to long integer
      lQuery = strtol(pLen, NULL, 10);
    }

    /*
        Serial.print(F("Host: ")); Serial.println(pHost);
        Serial.print(F("Path: ")); Serial.println(pPath);
        Serial.print(F("Length: ")); Serial.println(lQuery);
        Serial.print(F("Query: ")); Serial.println(pQuery);
    */

    // Send the requested file or the generated response
    sendFile(client, SPARTAN, pHost, pPath, pExt, "index.gmi");

    client->flush();
    client->stop();
  }
}


// Handle Gopher protocol
void clGopher(WiFiClient * client) {
  client->setTimeout(5000);
  while (client->connected()) {
    // Read one line from request
    int len = readln(client, buf);
    // Check the length
    if (len == 0) continue;

    // Log
    struct tm timeinfo;
    getLocalTime(&timeinfo);
    strftime(tmbuf, 30, LOG_TIMEFMT, &timeinfo);
    Serial.print(F("LOG: "));
    Serial.print(client->remoteIP());
    Serial.print(" - - ");
    Serial.print(tmbuf);
    Serial.print (" \"");
    Serial.print(buf);
    Serial.print("\" ");
    Serial.println();

    char *pPath, *pExt, *pQuery, *pEOL;

    // Path might be empty, in this case will consider root ('/')
    if (buf[0] == '\r') {
      buf[0] = '/';
      buf[1] = '\0';
      pEOL = &buf[1];
    }
    else {
      // Find the path
      pPath = buf;
      // Find the query
      pQuery = strchr(pPath, '\t');
      if (pQuery != NULL) {
        pQuery[0] = '\0';
        pQuery++;
      }
      // Find EOL
      pEOL = strchr(buf, '\r');
      pEOL[0] = '\0';
    }

    Serial.print(F("Path: ")); Serial.println(pPath);
    Serial.print(F("Query: ")); Serial.println(pQuery);



    sendFile(client, GOPHER, "esws.duckdns.org", pPath, pExt, "gopher.map");
    client->print("\r\n.\r\n");

    client->flush();
    client->stop();

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
  Serial.print(F("SYS: Searching SD card, trying CS "));
  for (auto cs : spiCSPins) {
    Serial.print(cs); Serial.print(" ");
    if (SD.begin(cs)) {
      spiCS = cs;
      break;
    }
  }
  if (spiCS > -1) {
    Serial.println(F("found!"));
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
  else {
    Serial.println(F("failed!"));
    while (true) {
      yield();
      // Flash the led
      digitalWrite(LED, HIGH ^ LEDinv); delay(50);
      digitalWrite(LED, LOW  ^ LEDinv); delay(50);
      digitalWrite(LED, HIGH ^ LEDinv); delay(50);
      digitalWrite(LED, LOW  ^ LEDinv); delay(250);
    }
  }

  // Set hostname
  setHostname();
  // Load DuckDNS config
  loadDuckDNS();
  // Configure WiFi
  initWiFi();
  // Load the mime-types
  loadMimeTypes();
  // Configure secure server
  loadCertKey();
#ifndef USE_EC
  srvGemini.setRSACert(srvCert, srvKey);
#else
  srvGemini.setECCert(srvCert, BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN, srvKey);
#endif
  // Set the server's cache
#if defined(USE_CACHE)
  srvGemini.setCache(&sslCache);
#endif


  srvHTTP.on("/", handleHTTPRoot);
  //server.onNotFound(handleNotFound);
}

// Main Arduino loop
void loop() {
  static bool reconn = true;
  if (wifiMulti.run(5000) == WL_CONNECTED) {
    if (reconn) {
      // Connected
      Serial.print(F("SYS: WiFi connected: "));
      Serial.println(WiFi.SSID());
      Serial.print(F("NET: IP address: "));
      Serial.println(WiFi.localIP());

      // Set up mDNS responder:
      if (!MDNS.begin(host)) {
        Serial.println(F("DNS: Error setting up MDNS"));
      }
      else {
        MDNS.addService("gemini", "tcp", PORT);
        MDNS.addService("http",   "tcp", 80);
        MDNS.addService("gopher", "tcp", 70);
        Serial.println(F("DNS: mDNS responder started"));
      }

#ifdef USE_UPNP
      // UPnP port mappings
      Serial.println(F("NET: Adding UPnP port mappings ... "));
      tinyUPnP->addPortMappingConfig(WiFi.localIP(), 1965, RULE_PROTOCOL_TCP, 36000, "eSWS Gemini");
      tinyUPnP->addPortMappingConfig(WiFi.localIP(),  300, RULE_PROTOCOL_TCP, 36000, "eSWS Spartan");
      tinyUPnP->addPortMappingConfig(WiFi.localIP(),   70, RULE_PROTOCOL_TCP, 36000, "eSWS Gopher");
      // Commit the port mappings to the IGD
      portMappingResult portMappingAdded = tinyUPnP->commitPortMappings();
#endif

      // Update DuckDNS
      Serial.print(F("DNS: Updating DuckDNS... "));
      bool updated = upDuckDNS(host, ddns);
      if (updated)  Serial.println(F("done."));
      else          Serial.println(F("failed."));

      // Set clock
      setClock();

      // Start accepting connections
      srvGemini.begin();
      Serial.print(F("GMI: Gemini server '")); Serial.print(host); Serial.print(F(".local' started on ")); Serial.print(WiFi.localIP()); Serial.print(":"); Serial.println(PORT);
      srvSpartan.begin();
      Serial.print(F("SPN: Spartan server '")); Serial.print(host); Serial.print(F(".local' started on ")); Serial.print(WiFi.localIP()); Serial.print(":"); Serial.println(300);
      srvGopher.begin();
      Serial.print(F("GPH: Gopher server '")); Serial.print(host); Serial.print(F(".local' started on ")); Serial.print(WiFi.localIP()); Serial.print(":"); Serial.println(70);
      srvHTTP.begin();
      Serial.println("HTTP server started");

      reconn = false;
    }


    MDNS.update();

    srvHTTP.handleClient();

    BearSSL::WiFiClientSecure client = srvGemini.available();
    if (client) {
      // LED on
      digitalWrite(LED, HIGH ^ LEDinv);

      //std::vector<uint16_t> cyphers = { BR_TLS_RSA_WITH_AES_256_CBC_SHA256, BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, BR_TLS_RSA_WITH_3DES_EDE_CBC_SHA };
      //client.setCiphers(cyphers);

      //client.setFingerprint("39b2204993bab61373aed82c24a20919b4bb7a9fb6c9342452b3e5f6836848de");

      // Handle the client
      clGemini(&client);
      // LED off
      digitalWrite(LED, LOW ^ LEDinv);
    }

    WiFiClient spartan = srvSpartan.available();
    if (spartan) {
      // LED on
      digitalWrite(LED, HIGH ^ LEDinv);
      // Handle the client
      clSpartan(&spartan);
      // LED off
      digitalWrite(LED, LOW ^ LEDinv);
    }

    WiFiClient gopher = srvGopher.available();
    if (gopher) {
      // LED on
      digitalWrite(LED, HIGH ^ LEDinv);
      // Handle the client
      clGopher(&gopher);
      // LED off
      digitalWrite(LED, LOW ^ LEDinv);
    }

  }
  else {
    Serial.println(F("WFI: WiFi disconnected"));
    MDNS.end();
    srvGemini.stop();
    srvHTTP.stop();
    reconn = true;
  }

#ifdef USE_UPNP
  // UPnP
  tinyUPnP->updatePortMappings(600000, NULL);
#endif
}
