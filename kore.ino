/**
  kore - Embedded small net multi-protocol server for ESP8266

  Copyright (c) 2024 Costin STROIE <costinstroie@eridu.eu.org>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, orl
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// The DEBUG flag
//#define DEBUG

//#define USE_UPNP

// Software name and version
#define PROGNAME    "kore"
#define PROGVERS    "0.2"

// Certificate and key
#define SSL_CERT    "/ssl/crt.pem"
#define SSL_KEY     "/ssl/key.pem"

// WiFi credentials
#define WIFI_CFG    "/wifi.cfg"
#define HOSTNAME    "/hostname.cfg"
#define DDNS_TOK    "/duckdns.cfg"

// Mime types
#define MIMETYPE    "/mimetype.cfg"

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

// TLS server
// openssl req -new -x509 -keyout key.pem -out crt.pem -days 3650 -nodes -subj "/C=RO/ST=Bucharest/L=Bucharest/O=Eridu/OU=IT/CN=koremoon.duckdns.org" -addext "subjectAltName=DNS:eridu.eu.org,DNS:kore.eridu.eu.org,DNS:koremoon.duckdns.org,DNS:*.koremoon.duckdns.org,DNS:koremoon.localDNS:kore.local,DNS:localhost"
BearSSL::WiFiServerSecure srvGemini(1965);
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
bool haveRSAKeyCert = true;

// HTTP
WiFiServer srvHTTP(80);
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
struct tm logTime;
char bufTime[30];
int logErrCode;
int fileSize;

// Set ADC to Voltage
ADC_MODE(ADC_VCC);


// Read one line from stream, delimited by the specified char,
// with maximum of specified lenght, and return the lenght read string
int readln(Stream *stream, char *buf, int maxLen = 1024) {
  int len = 0;
  char c;
  while (stream->available()) {
    // Read one char
    c = stream->read();
    // Limit line length
    if (len >= maxLen - 1) {
      len = -1;
      break;
    }

    // Will always store CRLF, then ZERO
    if (c == '\r') {
      // Consume one more char if CRLF
      if (stream->peek() == '\n')
        stream->read();
      buf[len++] = '\r';
      buf[len++] = '\n';
      buf[len] = '\0';
      break;
    }
    else
      buf[len++] = c;
  }
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
    Serial.println(F("done."));
    srvCert = new BearSSL::X509List(file, file.size());
  }
  else {
    haveRSAKeyCert = false;
    Serial.println(F("failed."));
  }
  file.close();
  Serial.print(F("SYS: Reading SSL key from ")); Serial.print(SSL_KEY); Serial.print(F(" ... "));
  file = SD.open(SSL_KEY, "r");
  if (file.isFile()) {
    Serial.println(F("done."));
    srvKey = new BearSSL::PrivateKey(file, file.size());
  }
  else {
    haveRSAKeyCert = false;
    Serial.println(F("failed."));
  }
  file.close();
  if (!haveRSAKeyCert)
    Serial.println(F("GMI: No RSA key and/or certificate. Gemini server is disabled."));
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
      Serial.println(fqdn);
      WiFi.hostname(host);
    }
  }
  else
    Serial.println(F("failed."));
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
    Serial.println(F("failed."));
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
    Serial.println(F("failed."));
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

/**
  Get the uptime

  @param buf character array to return the text to
  @param len the maximum length of the character array
  @return uptime in seconds
*/
unsigned long uptime(char *buf, size_t len) {
  // Get the uptime in seconds
  unsigned long upt = millis() / 1000;
  // Compute days, hours, minutes and seconds
  int ss =  upt % 60;
  int mm = (upt % 3600) / 60;
  int hh = (upt % 86400L) / 3600;
  int dd =  upt / 86400L;
  // Create the formatted time
  if (dd == 1) snprintf_P(buf, len, PSTR("%d day, %02d:%02d:%02d"),  dd, hh, mm, ss);
  else         snprintf_P(buf, len, PSTR("%d days, %02d:%02d:%02d"), dd, hh, mm, ss);
  // Return the uptime in seconds
  return upt;
}

int sendFile(Stream *client, proto_t proto, char *pHost, char *pPath, char *pExt, const char *pFile) {
  int fileSize = 0;
  int dirEnd = 0;
  // Validate the path (../../ ...)

  // Virtual hosting
  int hostLen = strlen(fqdn);
  // Find the longest host name
  if (pHost != NULL)
    if (hostLen < strlen(pHost))
      hostLen = strlen(pHost);
  // Dinamically create the file path ("/" + host + path (+ "index.gmi"))
  char *filePath = new char[strlen(pPath) + hostLen + 20];
  strcpy(filePath, "/");
  // Check if the hostname and request host are the same and append the host
  if (pHost == NULL)
    // No host in request (Gopher)
    strcat(filePath, fqdn);
  else if (strncmp(host, pHost, strlen(host)) == 0 and strncmp(&pHost[strlen(host)], ".local", 6) == 0)
    // Host for .local
    strcat(filePath, host);
  else {
    strcat(filePath, pHost);
    // Check the virtual host directory exists
    File file = SD.open(filePath, "r");
    if (!file.isDirectory()) {
      // Fallback to FQDN
      file.close();
      strcpy(filePath, "/");
      strcat(filePath, fqdn);
    }
  }
  // Append the path
  if (filePath[strlen(filePath) - 1] != '/' and pPath[0] != '/')
    strcat(filePath, "/");
  strcat(filePath, pPath);
  // Check if directory and append default file name for protocol
  File file = SD.open(filePath, "r");
  if (file.isDirectory()) {
    file.close();
    if (filePath[strlen(filePath) - 1] != '/')
      strcat(filePath, "/");
    dirEnd = strlen(filePath);
    strcat(filePath, pFile);
    file = SD.open(filePath, "r");
  };

  Serial.print(F("DBG: File path: "));
  Serial.println(filePath);

  // Check if the file exists
  if (file.isFile()) {
    // Detect mime type
    pExt = strrchr(filePath, '.');
    if (proto != GOPHER) {
      if (pExt == NULL) {
        // TODO add HTTP
        if      (proto == GEMINI)  client->print("20 ");
        else if (proto == SPARTAN) client->print("2 ");
        client->print("application/octet-stream\r\n");
      }
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
        // TODO Add http
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
        client->print("20 text/gemini\r\n");
        client->print("# Content of ");
        client->print(pPath);
        client->print("\r\n\r\n");
    }
    // List files in SD
    File root = SD.open(filePath);
    while (File entry = root.openNextFile()) {
      // Ignore hidden files
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
          if (strlen(pPath) > 1 and pPath[strlen(pPath) - 1] != '/')
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
        case GEMINI:
          client->print("=> ");
          client->print(pPath);
          if (strlen(pPath) > 1 and pPath[strlen(pPath) - 1] != '/')
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
    client->print("20 text/gemini\r\n");
    client->print("# Server status\r\n\r\n");
    // Hostname
    client->print(fqdn);
    client->print("\t");
    client->print(host);
    client->print(".local\r\n\r\n");
    // Uptime in seconds and text
    unsigned long ups = 0;
    char upt[32] = "";
    ups = uptime(upt, sizeof(upt));
    client->print("Uptime: "); client->print(upt); client->print("\r\n");
    // SSID
    client->print("SSID: "); client->print(WiFi.SSID()); client->print("\r\n");
    // Get RSSI
    client->print("Signal: "); client->print(WiFi.RSSI()); client->print(" dBm\r\n");
    // IP address
    client->print("IP address: "); client->print(WiFi.localIP()); client->print("\r\n");
    // Free Heap
    client->print("Free memory: "); client->print(ESP.getFreeHeap()); client->print(" bytes\r\n");
    // Read the Vcc (mV)
    client->print("Voltage: "); client->print(ESP.getVcc()); client->print(" mV\r\n");
  }
  else
    client->print("51 File Not Found\r\n");
  // Destroy the file path string
  delete(filePath);
  // Return the file size
  return fileSize;
}

// Print the first part of the log line
void logPrint(IPAddress ip) {
  strftime(bufTime, 30, LOG_TIMEFMT, &logTime);
  Serial.print(F("LOG: "));
  Serial.print(ip);
  Serial.print(" - - ");
  Serial.print(bufTime);
  Serial.print (" \"");
  Serial.print(buf);
  Serial.print("\" ");
}

// Print the last part of the log line
void logPrint(int code, int size) {
  Serial.print(code);
  Serial.print (" ");
  Serial.println(size);
}

// Handle Gemini protocol
void clGemini(BearSSL::WiFiClientSecure *client) {
  char *pSchema, *pHost, *pPort, *pPath, *pExt, *pQuery, *pEOL;
  // Prepare the log
  getLocalTime(&logTime);
  logErrCode = 20;
  // Set a global time out
  unsigned long timeOut = millis() + 5000;
  // Loop as long as connected (and before timed out)
  while (client->connected() and millis() < timeOut) {
    // Read one line from request
    int len = readln(client, buf);
    // If zero, there is no data yet; read again
    if (len == 0) continue;
    // If last char is not zero, the line is not complete
    if (buf[len] != '\0') continue;

    // The buffer has at least 2 chars (CR LF) if no error
    if (len >= 2) {
      // Set EOL at CRLF chars
      pEOL = &buf[len - 2];
      // Trim the string
      pEOL[0] = '\0';
    }

    // Print the first part of the log line
    logPrint(client->remoteIP());

    // Check if the buffer was overflown
    if (len < 0) {
      logErrCode = 59;
      client->print("59 Invalid URL\r\n");
      break;
    }

    // Find the schema
    if (strncmp(buf, "gemini://", 9) != 0) {
      logErrCode = 59;
      client->print("59 Unsupported protocol\r\n");
      break;
    }

    // Decompose the request
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
    fileSize = sendFile(client, GEMINI, pHost, pPath, pExt, "index.gmi");
    // We can now safely break the loop
    break;
  }
  // Print final log part
  logPrint(logErrCode, fileSize);
  // Close connection
  client->flush();
  client->stop();
}

// Handle Spartan protocol
void clSpartan(WiFiClient * client) {
  char *pHost, *pPath, *pExt, *pQuery, *pLen, *pEOL;
  long int lQuery;
  // Prepare the log
  getLocalTime(&logTime);
  logErrCode = 2;
  // Set a global time out
  unsigned long timeOut = millis() + 5000;
  while (client->connected() and millis() < timeOut) {
    // Read one line from request
    int len = readln(client, buf);
    // If zero, there is no data yet; read again
    if (len == 0) continue;
    // If last char is not zero, the line is not complete
    if (buf[len] != '\0') continue;

    // The buffer has at least 2 chars (CR LF) if no error
    if (len >= 2) {
      // Set EOL at CRLF chars
      pEOL = &buf[len - 2];
      // Trim the string
      pEOL[0] = '\0';
    }

    // Print the first part of the log line
    logPrint(client->remoteIP());

    // Check if the buffer was overflown
    if (len < 0) {
      logErrCode = 4;
      client->print("4 Invalid request\r\n");
      break;
    }

    // Analyze the request
    pHost = buf;
    // Find the path
    pPath = strchr(pHost, ' ');
    if (pPath == NULL) {
      logErrCode = 4;
      client->print("4 Invalid request\r\n");
      break;
    }
    else {
      pPath[0] = '\0';
      pPath++;
    }
    // Find the length
    pLen = strchr(pPath, ' ');
    if (pLen == NULL) {
      logErrCode = 4;
      client->print("4 Invalid request\r\n");
      break;
    }
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
    fileSize = sendFile(client, SPARTAN, pHost, pPath, pExt, "index.gmi");
    // We can now safely break the loop
    break;
  }
  // Print final log part
  logPrint(logErrCode, fileSize);
  // Close connection
  client->flush();
  client->stop();
}

// Handle Gopher protocol
void clGopher(WiFiClient * client) {
  // Prepare the log
  getLocalTime(&logTime);
  logErrCode = 0;
  // Set a global time out
  unsigned long timeOut = millis() + 5000;
  while (client->connected() and millis() < timeOut) {
    // Read one line from request
    int len = readln(client, buf);
    // If zero, there is no data yet; read again
    if (len == 0) continue;
    // If last char is not zero, the line is not complete
    if (buf[len] != '\0') continue;

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
      // Set EOL at CRLF chars
      pEOL = &buf[len - 2];
      // Trim the string
      pEOL[0] = '\0';
    }

    // Print the first part of the log line
    logPrint(client->remoteIP());

    // Check if the buffer was overflown
    if (len < 0) {
      logErrCode = 1;
      break;
    }

    // Find the query
    pQuery = strchr(pPath, '\t');
    if (pQuery != NULL) {
      pQuery[0] = '\0';
      pQuery++;
    }


    /*
        Serial.print(F("Path: ")); Serial.println(pPath);
        Serial.print(F("Query: ")); Serial.println(pQuery);
    */

    fileSize = sendFile(client, GOPHER, fqdn, pPath, pExt, "gopher.map");
    client->print("\r\n.\r\n");
    // We can now safely break the loop
    break;
  }
  // Print final log part
  logPrint(logErrCode, fileSize);
  // Close connection
  client->flush();
  client->stop();
}

// Handle HTTP protocol
void clHTTP(WiFiClient * client) {
  // Prepare the log
  getLocalTime(&logTime);
  logErrCode = 200;
  // Set a global time out
  unsigned long timeOut = millis() + 5000;
  while (client->connected() and millis() < timeOut) {
    // Read one line from request
    int len = readln(client, buf);
    // If zero, there is no data yet; read again
    if (len == 0) continue;
    // If last char is not zero, the line is not complete
    if (buf[len] != '\0') continue;

    // Print the first part of the log line
    logPrint(client->remoteIP());

    client->print(F("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nHi, Bob!"));
    // FIXME
    fileSize = 0;
  }
  // Print final log part
  logPrint(logErrCode, fileSize);
  // Close connection
  client->flush();
  client->stop();
}


// Main Arduino setup function
void setup() {
  // Init the serial interface
  Serial.begin(115200);
  Serial.println();
  Serial.print(PROGNAME);
  Serial.print(F(" "));
  Serial.print(PROGVERS);
  Serial.print(F(" "));
  Serial.println(__DATE__);

  // Configure the LED
  pinMode(LED, OUTPUT);
  digitalWrite(LED, LOW ^ LEDinv);

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
}

// Main Arduino loop
void loop() {
  static bool reconnecting = true;
  if (wifiMulti.run(5000) == WL_CONNECTED) {
    if (reconnecting) {
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
        if (haveRSAKeyCert)
          MDNS.addService("gemini", "tcp", 1965);
        MDNS.addService("spartan", "tcp", 300);
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
      Serial.print(F("DNS: Updating DuckDNS for domain ... "));
      Serial.print(host);
      Serial.print(F(" ... "));
      bool updated = upDuckDNS(host, ddns);
      if (updated)  Serial.println(F("done."));
      else          Serial.println(F("failed."));

      // Set clock
      setClock();

      // Start accepting connections
      if (haveRSAKeyCert) {
        srvGemini.begin();
        Serial.print(F("GMI: Gemini server '")); Serial.print(host); Serial.print(F(".local' started on ")); Serial.print(WiFi.localIP()); Serial.print(":"); Serial.println(1965);
      };
      srvSpartan.begin();
      Serial.print(F("SPN: Spartan server '")); Serial.print(host); Serial.print(F(".local' started on ")); Serial.print(WiFi.localIP()); Serial.print(":"); Serial.println(300);
      srvGopher.begin();
      Serial.print(F("GPH: Gopher server '")); Serial.print(host); Serial.print(F(".local' started on ")); Serial.print(WiFi.localIP()); Serial.print(":"); Serial.println(70);
      srvHTTP.begin();
      Serial.print(F("HTP: HTTP server '")); Serial.print(host); Serial.print(F(".local' started on ")); Serial.print(WiFi.localIP()); Serial.print(":"); Serial.println(80);

      reconnecting = false;
    }

    // Do MDNS stuff
    MDNS.update();

    if (haveRSAKeyCert) {
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

    WiFiClient http = srvHTTP.available();
    if (http) {
      // LED on
      digitalWrite(LED, HIGH ^ LEDinv);
      // Handle the client
      clHTTP(&http);
      // LED off
      digitalWrite(LED, LOW ^ LEDinv);
    }

  }
  else {
    Serial.println(F("WFI: WiFi disconnected"));
    MDNS.end();
    if (haveRSAKeyCert)
      srvGemini.stop();
    srvSpartan.stop();
    srvGopher.stop();
    srvHTTP.stop();
    reconnecting = true;
  }

#ifdef USE_UPNP
  // UPnP
  tinyUPnP->updatePortMappings(600000, NULL);
#endif
}
