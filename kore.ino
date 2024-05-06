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
#define PROGNAME "kore"
#define PROGVERS "0.2"

// Certificate and key
#define SSL_CERT "/ssl/crt.pem"
#define SSL_KEY "/ssl/key.pem"

// WiFi credentials
#define WIFI_CFG "/wifi.cfg"
#define HOSTNAME "/hostname.cfg"
#define DDNS_TOK "/duckdns.cfg"
#define TITAN_TOK "/titan.cfg"
#define TZ_CFG "/tz.cfg"

// Mime types
#define MIMETYPE "/mimetype.cfg"

// LED configuration
#define LEDinv (true)
#if defined(BUILTIN_LED)
#define LED (BUILTIN_LED)
#elif defined(LED_BUILTIN)
#define LED (LED_BUILTIN)
#else
#define LED (13)
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
#include "TinyUPnP.h"
TinyUPnP *tinyUPnP = new TinyUPnP(5000);
#endif

// WiFi multiple access points
ESP8266WiFiMulti wifiMulti;

// SD card CS pins
int spiCS = -1;
int spiCSPins[] = {D4, D8, D1, D2, D3, D0};



// Protocols
enum proto_t {GEMINI, SPARTAN, HTTP, GOPHER, _PROTO_ALL};
// Pseudo-statuses
enum status_t {ST_OK, ST_INPUT, ST_REDIR, ST_NOTFOUND, ST_INVALID, ST_SERVERERROR, _ST_ALL};
int rspStatus[_PROTO_ALL][_ST_ALL] = {
  {20, 10, 30, 51, 59, 59},
  {2, 2, 3, 4, 4, 5},
  {200, 200, 200, 404, 500, 500},
  {0, 0, 0, 0, 0, 0}
};

// TLS server
// openssl req -new -x509 -keyout key.pem -out crt.pem -days 3650 -nodes -subj "/C=RO/ST=Bucharest/L=Bucharest/O=Eridu/OU=IT/CN=koremoon.duckdns.org" -addext "subjectAltName=DNS:eridu.eu.org,DNS:kore.eridu.eu.org,DNS:koremoon.duckdns.org,DNS:*.koremoon.duckdns.org,DNS:koremoon.localDNS:kore.local,DNS:localhost"
BearSSL::WiFiServerSecure srvGemini(1965);
BearSSL::X509List *srvCert;
BearSSL::PrivateKey *srvKey;
// #define USE_EC       // Enable Elliptic Curve signed cert
#define CACHE_SIZE 5  // Number of sessions to cache.
#define USE_CACHE     // Enable SSL session caching.
// Caching SSL sessions shortens the length of the SSL handshake.
// You can see the performance improvement by looking at the
// Network tab of the developer tools of your browser.
//#define DYNAMIC_CACHE // Whether to dynamically allocate the cache.

#if defined(USE_CACHE) && defined(DYNAMIC_CACHE)
// Dynamically allocated cache.
BearSSL::ServerSessions sslCache(CACHE_SIZE);
#elif defined(USE_CACHE)
// Statically allocated cache.
ServerSession sslStore[CACHE_SIZE];
BearSSL::ServerSessions sslCache(sslStore, CACHE_SIZE);
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
char *cfgTitanToken;
char *tz;
char *ssid;
char *pass;
char buf[1025];

// Mime types list
struct MimeTypeEntry {
  char *ext;
  char *mmt;
  char gph;
};
// Dynamically allocated vector to keep the associations
std::vector<MimeTypeEntry> mtList;
char binMimeType[] = "application/octet-stream";

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
  while (stream->available()) {
    // Read one char
    char c = stream->read();
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
// with maximum of specified lenght, and return the lenght of the read string
int readln(File *file, char *buf, int maxLen = 1024) {
  int len = 0;
  while (file->available()) {
    // Read one char
    char c = file->read();
    // Line must start with a non-control character
    if (len == 0 and c < 32) continue;
    // Limit line length
    if (len >= maxLen - 1) {
      // Return an error code for line too long
      len = -1;
      break;
    }
    // Will never store CRLF
    if (c == '\r' or c == '\n') {
      // Consume one more char if CRLF
      if (file->peek() == '\n')
        file->read();
      buf[len] = '\0';
      break;
    }
    else
      buf[len++] = c;
  }
  // Return another error code on no data
  if (!file->available() and len == 0)
    len = -2;
  // Return the line lenght
  return len;
}

// Load the certificate and the key from storage
void loadCertKey() {
  File file;
  Serial.print(F("SYS: Reading SSL certificate from "));
  Serial.print(SSL_CERT);
  Serial.print(F(" ... "));
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
  Serial.print(F("SYS: Reading SSL key from "));
  Serial.print(SSL_KEY);
  Serial.print(F(" ... "));
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
  Serial.print(F("SYS: Reading host name from "));
  Serial.print(HOSTNAME);
  Serial.print(F(" ... "));
  File file = SD.open(HOSTNAME, "r");
  if (file.isFile()) {
    len = file.read((uint8_t *)buf, 255);
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
  Serial.print(F("DNS: Reading DuckDNS token from "));
  Serial.print(DDNS_TOK);
  Serial.print(F(" ... "));
  File file = SD.open(DDNS_TOK, "r");
  if (file.isFile()) {
    len = file.read((uint8_t *)buf, 255);
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

// Load titan:// token
void loadTitanToken() {
  int len = 1024;
  // Read the titan:// token
  Serial.print(F("GMI: Reading titan:// token from "));
  Serial.print(TITAN_TOK);
  Serial.print(F(" ... "));
  File file = SD.open(TITAN_TOK, "r");
  if (file.isFile()) {
    while (len >= 0) {
      // Read one line from file
      len = readln(&file, buf, 256);
      // Skip over empty lines
      if (len == 0) continue;
      // Skip over comment lines
      if (buf[0] == '#') continue;
      Serial.println(F("done."));
      cfgTitanToken = new char[strlen(buf) + 1];
      strcpy(cfgTitanToken, buf);
      break;
    }
  }
  else
    Serial.println(F("failed."));
  file.close();
}

// Load timezone configuration
void loadTimeZone() {
  int len = 1024;
  // Read the timezone configuration
  Serial.print(F("NTP: Reading timezone configuration from "));
  Serial.print(TZ_CFG);
  Serial.print(F(" ... "));
  File file = SD.open(TZ_CFG, "r");
  if (file.isFile()) {
    len = file.read((uint8_t *)buf, 255);
    char *token = strtok(buf, "\t\r\n");
    if (token != NULL) {
      tz = new char[strlen(token) + 1];
      strcpy(tz, token);
      Serial.println(tz);
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
  Serial.print(F("WFI: Reading WiFi configuration from "));
  Serial.print(WIFI_CFG);
  Serial.print(F(" ... "));
  File file = SD.open(WIFI_CFG, "r");
  if (file.isFile()) {
    while (len >= 0) {
      // Read one line from file
      len = readln(&file, buf, 256);
      // Skip over empty lines
      if (len == 0) continue;
      // Skip over comment lines
      if (buf[0] == '#') continue;
      // Find the SSID and the PASS, TAB-separated
      ssid = strtok((char *)buf, "\t");
      pass = strtok(NULL, "\r\n\t");
      // Add SSID and PASS to WiFi Multi
      if (ssid != NULL and pass != NULL) {
        Serial.println();
        Serial.print(F("WFI: Add '"));
        Serial.print(ssid);
        Serial.print(F("' "));
#ifdef DEBUG
        Serial.print(F("with pass '"));
        Serial.print(pass);
        Serial.print(F("' "));
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
  char *mmt;
  char *gph;
  // Read the mime-type definitions
  Serial.print(F("MIM: Reading mime-types from "));
  Serial.print(MIMETYPE);
  Serial.print(F(" ... "));
  File file = SD.open(MIMETYPE, "r");
  if (file.isFile()) {
    while (len >= 0) {
      // Read one line from file
      len = readln(&file, buf, 256);
      // Skip over empty lines
      if (len == 0) continue;
      // Skip over comment lines
      if (buf[0] == '#') continue;
      // Find the extension and the mime type, TAB-separated
      ext = strtok((char *)buf, "\t");
      gph = strtok(NULL, "\t");
      mmt = strtok(NULL, "\r\n\t");
      // Append to vector
      if (ext != NULL and mmt != NULL) {
        Serial.println();
        Serial.print(F("MIM: Add '"));
        Serial.print(mmt);
        Serial.print(F("' for '"));
        Serial.print(ext);
        Serial.print(F("' "));
        MimeTypeEntry mtNew;
        mtNew.ext = strdup(ext);
        mtNew.gph = gph[0];
        mtNew.mmt = strdup(mmt);
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

  configTime(tz, "pool.ntp.org", "time.nist.gov");

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

// CallBack time function for SD
time_t cbTime() {
  return time(nullptr);
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
  int ss = upt % 60;
  int mm = (upt % 3600) / 60;
  int hh = (upt % 86400L) / 3600;
  int dd = upt / 86400L;
  // Create the formatted time
  if (dd == 1) snprintf_P(buf, len, PSTR("%d day, %02d:%02d:%02d"), dd, hh, mm, ss);
  else snprintf_P(buf, len, PSTR("%d days, %02d:%02d:%02d"), dd, hh, mm, ss);
  // Return the uptime in seconds
  return upt;
}


// Send the proper header according to protocol and return the real status
int sendHeader(Stream *client, proto_t proto, status_t status, const char *pText) {
  switch (proto) {
    case GEMINI:
    case SPARTAN:
      client->print(rspStatus[proto][status]);
      client->print(" ");
      client->print(pText);
      client->print("\r\n");
      break;
    case HTTP:
      client->print(F("HTTP/1.0 "));
      client->print(rspStatus[proto][status]);
      client->print(" ");
      if (status == ST_OK) {
        client->print(F("OK"));
        client->print(F("\r\nContent-Type: "));
        client->print(pText);
        client->print(F("; encoding=utf8"));
      }
      else
        client->print(pText);
      client->print("\r\nConnection: close\r\n\r\n");
      break;
    case GOPHER:
      if (status != ST_OK) {
        client->print(pText);
        client->print("\r\n");
      }
      break;
  }
  // Return the status code
  return rspStatus[proto][status];
}

// Send a file in CPIO arhive
int cpioSendFile(Stream *client, File file) {
  int outSize = 0;
  int pad = 0;
  // ino type+mode uid gid nlink mtime size devM devm rdevM rdevm filename_len filename 0
  int hdrSize = sprintf(buf, "070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X00000000%s%c",
                        0, 0100644,  0, 0, 1, (uint32_t)file.getLastWrite(), (uint32_t)file.size(), 0, 0, 0, 0, strlen(file.fullName()) + 1, file.fullName(), '\0');
  outSize += hdrSize;
  // Padding
  pad = (- outSize) & 3;
  outSize += pad;
  // Write the header and the pad
  client->write(buf, hdrSize);
  client->write("\0\0\0\0", pad);
  // Send the file content, if any
  if (file.size()) {
    outSize += file.size();
    // Send content
    uint8_t fileBuf[512];
    while (file.available()) {
      int len = file.read(fileBuf, 512);
      client->write(fileBuf, len);
    }
    // Padding
    pad = (- outSize) & 3;
    outSize += pad;
    // Write the pad after file content
    client->write("\0\0\0\0", pad);
  }
  // Return the output size
  return outSize;
}

// Send a directory in CPIO arhive
int cpioSendDir(Stream *client, File dir) {
  int outSize = 0;
  while (File entry = dir.openNextFile()) {
    if (entry.isFile())
      // Send the file
      outSize += cpioSendFile(client, entry);
    else if (entry.isDirectory())
      // Recurse into directory
      outSize += cpioSendDir(client, entry);
    // Close the file
    entry.close();
  }
  // Return the output size
  return outSize;
}

// Send a simple ascii CPIO archive with card contents
int cpioSendArchive(Stream * client, proto_t proto, char *path) {
  int outSize = 0;
  // Check the path exists
  if (!SD.exists(path)) {
    logErrCode = sendHeader(client, proto, ST_NOTFOUND, "File not found");
    return 0;
  }
  // Start with the header
  logErrCode = sendHeader(client, proto, ST_OK, binMimeType);
  // Open the directory
  File dir = SD.open(path);
  // Send its content
  outSize += cpioSendDir(client, dir);
  dir.close();
  // Write the TRAILER
  client->write("070701", 6);
  for (int i = 88; i > 0; i--)
    client->write('0');
  client->write("0000000B00000000TRAILER!!!\0", 27);
  outSize += 121;
  // Padding
  int pad = (- outSize) & 3;
  outSize += pad;
  // Write the pad after file content
  client->write("\0\0\0\0", pad);
  // Return the archive size
  return outSize;
}

// Try to read the title of a gemini page (open file)
int readPageTitle(File *file, char *line, const int maxLen = 100, const int maxLines = 5) {
  int len = 0;
  int count = maxLines;
  if (file->isFile()) {
    // Read the first maxLines lines from the file, at most
    while (count-- > 0) {
      // Read one line from file
      len = readln(file, line, maxLen - 5);
      // Skip over empty lines
      if (len == 0) continue;
      // Break if read error
      if (len == -2) break;
      // Break if title found
      if (line[0] == '#') break;
      // Reset the buffer
      line[0] = '\0';
    }
    // Error reading file or nothing in the first maxLines lines
    if (len == -2 or len == 0) {
      len = 0;
      line[len] = '\0';
    }
    else {
      // Line too long, trim its tail
      if (len == -1) {
        strcpy(&line[maxLen - 5], " ...");
        len = maxLen;
      }
      // Check if it's a title and trim its head
      if (line[0] == '#') {
        int head = strspn(line, "# \t");
        line = &line[head];
        len -= head;
      }
    }
  }
  // Return the line lenght
  return len;
}

// Try to read the title of a gemini page (by path)
int readPageTitle(char *path, char *line, const int maxLen = 100, const int maxLines = 5) {
  // Open the file
  File file = SD.open(path);
  int len = readPageTitle(&file, line, maxLen, maxLines);
  // Close the file
  file.close();
  // Return the line lenght
  return len;
}

// Send a gemini feed
int sendFeed(Stream * client, proto_t proto, char *path, char *pathFS) {
  int outSize = 0;
  int len;
  time_t modTime;
  struct tm* stTime;
  char line[100];
  char *pTitle;
  // Check the directory exists
  if (!SD.exists(pathFS)) {
    logErrCode = sendHeader(client, proto, ST_NOTFOUND, "File not found");
    return 0;
  }
  // Find the requested file name
  char *pName = strrchr(path, '/');
  // Trim the path at this position
  pName[0] = '\0';
  // Start with the header
  logErrCode = sendHeader(client, proto, ST_OK, "text/gemini");

  // Use the 'index.gmi' file to get the feed title
  char *pathIndex = new char[strlen(pathFS) + 20];
  strcpy(pathIndex, pathFS);
  strcat(pathIndex, "/index.gmi");
  // Read the title
  len = readPageTitle(pathIndex, line);
  // Check if we got something
  if (len > 0) {
    // Trim its head
    int head = strspn(line, "# \t");
    pTitle = &line[head];
    len -= head;
    outSize += client->print("# ");
    outSize += client->print(pTitle);
    outSize += client->print("\r\n\r\n");
  }
  else
    outSize += client->print("# No title\r\n\r\n");
  // Delete the temporary path string
  delete(pathIndex);

  // List files in the specified filesystem path
  File root = SD.open(pathFS);
  while (File entry = root.openNextFile()) {
    // Ignore some items
    if (entry.isDirectory() or                        // directories
        entry.name()[0] == '.' or                     // hidden files
        strncmp(entry.name(), "index.", 6) == 0 or    // index
        strncmp(entry.name(), "gopher.", 7) == 0 or   // gopher map
        strspn(entry.name(), "1234567890") < 2)       // needs to start with 2 digits
      continue;
    // Get the last modified time
    time_t modTime = entry.getLastWrite();
    stTime = localtime(&modTime);

    // Read the title
    len = readPageTitle(&entry, line);
    // Check if we got something
    if (len > 0) {
      // Trim its head
      int head = strspn(line, "# \t");
      pTitle = &line[head];
      len -= head;
    }
    else {
      // Just use the file name
      // FIXME
      strcpy(line, (char*)entry.name());
      pTitle = &line[0];
    }

    // Different for different protocols
    switch (proto) {
      case GOPHER:
        outSize += client->printf("0%4d-%02d-%02d %s\t%s/%s\t%s\t%d\r\n",
                                  (stTime->tm_year) + 1900, (stTime->tm_mon) + 1, stTime->tm_mday, pTitle, path, entry.name(), fqdn, 70);
        break;
      case GEMINI:
      case SPARTAN:
      case HTTP:
        outSize += client->printf("=> %s/%s\t%d-%02d-%02d %s\r\n",
                                  path, entry.name(), (stTime->tm_year) + 1900, (stTime->tm_mon) + 1, stTime->tm_mday, pTitle);
        break;
    }
    // Close the file
    entry.close();
  }
  // Close the directory
  root.close();

  outSize += client->print("\r\n");
  // Restore the path
  pName[0] = '/';
  // Return the feed size
  return outSize;
}

// Send the virtual server status page
int sendStatusPage(Stream *client) {
  int fileSize = 0;
  logErrCode = sendHeader(client, GEMINI, ST_OK, "text/gemini");
  fileSize += client->print("# Server status\r\n\r\n");
  // Hostname
  fileSize += client->print(fqdn);
  fileSize += client->print("\t");
  fileSize += client->print(host);
  fileSize += client->print(".local\r\n\r\n");
  // Uptime in seconds and text
  unsigned long ups = 0;
  char upt[32] = "";
  ups = uptime(upt, sizeof(upt));
  fileSize += client->print("Uptime: "); fileSize += client->print(upt); fileSize += client->print("\r\n");
  // SSID
  fileSize += client->print("SSID: "); fileSize += client->print(WiFi.SSID()); fileSize += client->print("\r\n");
  // Get RSSI
  fileSize += client->print("Signal: "); fileSize += client->print(WiFi.RSSI()); fileSize += client->print(" dBm\r\n");
  // IP address
  fileSize += client->print("IP address: "); fileSize += client->print(WiFi.localIP()); fileSize += client->print("\r\n");
  // Free Heap
  fileSize += client->print("Free memory: "); fileSize += client->print(ESP.getFreeHeap()); fileSize += client->print(" bytes\r\n");
  // Read the Vcc (mV)
  fileSize += client->print("Voltage: "); fileSize += client->print(ESP.getVcc()); fileSize += client->print(" mV\r\n");
  // Return the file size
  return fileSize;
}

// Receive a file using the titan:// schema and write it to filesystem
int receiveFile(Stream *client, char *pHost, char *pPath, char *plData, int plSize, int bufSize) {
  int fileSize = 0;
  // Validate the path (.. /./ //)
  if (strstr(pPath, "..") != NULL or
      strstr(pPath, "/./") != NULL or
      strstr(pPath, "//") != NULL) {
    logErrCode = sendHeader(client, GEMINI, ST_INVALID, "Invalid path");
    return 0;
  }
  // Virtual hosting, find the server root directory
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
    // No host in request (Gopher, HTTP/1.0)
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
      strcpy(filePath, "/");
      strcat(filePath, fqdn);
    }
    file.close();
  }
  // Append the path
  if (filePath[strlen(filePath) - 1] != '/' and pPath[0] != '/')
    strcat(filePath, "/");
  strcat(filePath, pPath);
  // If directory return error
  File file = SD.open(filePath, "r");
  if (file.isDirectory()) {
    file.close();
    logErrCode = sendHeader(client, GEMINI, ST_INVALID, "Path is a directory");
    delete (filePath);
    return 0;
  };
  file.close();
  // Total bytes received
  int total = 0;
  // Open the temporary file for writing
  File wrFile = SD.open("/~titan~.tmp", "w");
  // If the file is available, write to it
  if (wrFile) {
    int toRead = plSize;
    while (toRead > 0) {
      toRead = plSize - total;
      int qLen = client->readBytes(plData, ((toRead > bufSize) ? bufSize : toRead));
      if (qLen > 0) {
        wrFile.write(plData, qLen);
        total += qLen;
      }
    }
    wrFile.close();
  }
  else {
    logErrCode = sendHeader(client, GEMINI, ST_INVALID, "Cannot open file for writing");
    delete (filePath);
    return 0;
  };
  if (total != plSize) {
    logErrCode = sendHeader(client, GEMINI, ST_INVALID, "Error reading payload");
    delete (filePath);
    return 0;
  }
  // Move the temporary file
  File srcFile = SD.open("/~titan~.tmp", "r");
  File dstFile = SD.open(filePath, "w");
  uint8_t buf[512];
  while (srcFile.available()) {
    int len = srcFile.read(buf, 512);
    dstFile.write(buf, len);
  }
  dstFile.close();
  srcFile.close();
  SD.remove("/~titan~.tmp");

  // Destroy the file path string
  delete (filePath);
  // Return the file size
  return fileSize;
}

// Send file content, autoindex or generated file
int sendFile(Stream *client, proto_t proto, char *pHost, char *pPath, char *pExt, char *pQuery, const char *pFile) {
  int fileSize = 0;
  int dirEnd = 0;
  char *pFName;
  // Validate the path (.. /./ //)
  if (strstr(pPath, "..") != NULL or
      strstr(pPath, "/./") != NULL or
      strstr(pPath, "//") != NULL) {
    logErrCode = sendHeader(client, proto, ST_INVALID, "Invalid path");
    return 0;
  }
  // Virtual hosting, find the server root directory
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
    // No host in request (Gopher, HTTP/1.0)
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
  // Find the requested file name in filesystem path
  pFName = strrchr(filePath, '/');
  // Find the extension
  // FIXME stack overflow if it does not exists
  pExt = strrchr(pFName, '.');

  // Check if the file exists
  if (file.isFile() and strcmp(pQuery, "nofile") != 0) {
    // Keep the size
    fileSize = file.size();
    // Detect mime type
    if (proto != GOPHER) {
      if (pExt == NULL)
        // No file extension
        logErrCode = sendHeader(client, proto, ST_OK, binMimeType);
      else {
        // Extension found
        pExt++;
        // Find the mime type
        char *mimetype = NULL;
        for (auto entry : mtList) {
          if (strncmp(entry.ext, pExt, 3) == 0) {
            mimetype = entry.mmt;
            break;
          }
        }
        if (mimetype == NULL)
          mimetype = binMimeType;
        // Send header
        logErrCode = sendHeader(client, proto, ST_OK, mimetype);
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
        fileSize += client->printf("iContent of %s\t\tnull\t70\r\n", pPath);
        fileSize += client->print("i\t\tnull\t70\r\n");
        break;
      case GEMINI:
      case SPARTAN:
      case HTTP:
        logErrCode = sendHeader(client, proto, ST_OK, "text/gemini");
        fileSize += client->print("# Content of ");
        fileSize += client->print(pPath);
        fileSize += client->print("\r\n\r\n");
        break;
    }
    // List files in SD
    File root = SD.open(filePath);
    while (File entry = root.openNextFile()) {
      // Ignore hidden files
      if (entry.name()[0] == '.') continue;
      // Different for different protocols
      switch (proto) {
        case GOPHER: {
            char gType = '9';
            char gPath[200];
            if (entry.isDirectory())
              gType = '1';
            else {
              // Detect type type
              pExt = strrchr(entry.name(), '.');
              if (pExt != NULL) {
                // Extension found
                pExt++;
                // Find the type
                for (auto entry : mtList) {
                  if (strncmp(entry.ext, pExt, 3) == 0) {
                    gType = entry.gph;
                    break;
                  }
                }
              }
            }
            if (pPath[0] != '/') {
              strcpy(gPath, "/");
              strcat(gPath, pPath);
            }
            else {
              strcpy(gPath, pPath);
            }
            if (strlen(pPath) > 1 and pPath[strlen(pPath) - 1] != '/')
              strcat(gPath, "/");
            strcat(gPath, entry.name());
            if (entry.isDirectory())
              strcat(gPath, "/");
            // Write the line
            fileSize += client->printf("%c%s\t%s\t%s\t%d\r\n",
                                       gType, (char*)entry.name(), gPath, fqdn, 70);

          }
          break;
        case GEMINI:
        case SPARTAN:
        case HTTP:
          fileSize += client->print("=> ");
          fileSize += client->print(pPath);
          if (strlen(pPath) > 1 and pPath[strlen(pPath) - 1] != '/')
            fileSize += client->print("/");
          fileSize += client->print(entry.name());
          if (entry.isDirectory())
            fileSize += client->print("/");
          fileSize += client->print("\t");
          fileSize += client->print(entry.name());
          fileSize += client->print("\r\n");
          break;
      }
    }
  }
  else if (strcmp(pPath, "/status.gmi") == 0 and proto == GEMINI) {
    // Send the server status page
    fileSize = sendStatusPage(client);
  }
  else if (strncmp(pExt, ".cpio", 5) == 0) {
    // The requested virtual file is a CPIO archive. Trim the filepath
    // to the file name and get the parent directory (it can also be a
    // single file). Use it for archive root.
    pFName[0] = '\0';
    // Send the archive
    fileSize = cpioSendArchive(client, proto, filePath);
    // Restore the filePath
    pFName[0] = '/';
  }
  else if (strncmp(pFName, "/feed.gmi", 9) == 0) {
    // The requested virtual file is a gemini feed
    pFName[0] = '\0';
    // Send the feed
    fileSize = sendFeed(client, proto, pPath, filePath);
    // Restore the filePath
    pFName[0] = '/';
  }
  else
    // File not found
    logErrCode = sendHeader(client, proto, ST_NOTFOUND, "File not found");
  // Destroy the file path string
  delete (filePath);
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
  Serial.print(" \"");
  Serial.print(buf);
  Serial.print("\" ");
}

// Print the last part of the log line
void logPrint(int code, int size) {
  Serial.print(code);
  Serial.print(" ");
  Serial.println(size);
}

// Handle Gemini protocol
void clGemini(BearSSL::WiFiClientSecure * client) {
  char *pSchema, *pHost, *pPort, *pPath, *pExt, *pQuery, *pEOL;
  bool titan = false;
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
      logErrCode = sendHeader(client, GEMINI, ST_INVALID, "Invalid URL");
      break;
    }

    // Find the schema
    if (strncmp(buf, "gemini://", 9) == 0)
      titan = false;
    else if (strncmp(buf, "titan://", 8) == 0)
      titan = true;
    else {
      logErrCode = sendHeader(client, GEMINI, ST_INVALID, "Unsupported protocol");
      break;
    }

    // Decompose the request
    pSchema = buf;
    // Find the host
    pHost = strchr(pSchema, ':');
    pHost[0] = '\0';
    pHost++;
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
    else {
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
    if (pQuery == NULL) {
      // Try to identify parameters, as used by titan
      pQuery = strchr(pPath, ';');
    }
    if (pQuery != NULL) {
      pQuery[0] = '\0';
      pQuery++;
    }
    else
      pQuery = pEOL;

    /*
        Serial.println();
        Serial.print(F("Schema: ")); Serial.println(pSchema);
        Serial.print(F("Host:   ")); Serial.println(pHost);
        Serial.print(F("Port:   ")); Serial.println(pPort);
        Serial.print(F("Path:   ")); Serial.println(pPath);
        Serial.print(F("Query:  ")); Serial.println(pQuery);
    */

    // If the protocol is 'titan', we need to read the upcoming data. We will use the same buffer, after pEOL
    if (titan) {
      // Quick check the query
      if (strlen(pQuery) <= 0) {
        logErrCode = sendHeader(client, GEMINI, ST_INVALID, "Invalid query fot titan");
        break;
      }
      // We need to decompose the query and get mime, size and token
      char *pKey, *pVal, *pMime, *pToken, *plData;
      long int plSize;
      // Get a fragment from query
      pKey = strtok(pQuery, ";");
      while (pKey != NULL) {
        // Check if it has the form "key=value"
        pVal = strchr(pKey, '=');
        if (pVal != NULL) {
          // Starting with the next char there is the value
          pVal++;
          if      (strncmp(pKey, "mime", 4) == 0) pMime = pVal;
          else if (strncmp(pKey, "token", 5) == 0) pToken = pVal;
          else if (strncmp(pKey, "size", 4) == 0) plSize = strtol(pVal, NULL, 10);
        }
        // Next fragment
        pKey = strtok(NULL, ";");
      }
      // Check the token, if configured
      if (cfgTitanToken != NULL) {
        // XXX
        Serial.println();
        Serial.println(cfgTitanToken);
        Serial.println(pToken);
        // FIXME
        if (strncmp(cfgTitanToken, pToken, strlen(pToken)) != 0) {
          logErrCode = sendHeader(client, GEMINI, ST_INVALID, "Invalid token");
          break;
        }
      }
      // Check if the payload size is greater than zero
      if (plSize <= 0) {
        logErrCode = sendHeader(client, GEMINI, ST_INVALID, "Invalid payload size");
        break;
      }
      int wrBufSize = 1023 - len;
      // Ensure a minimum buffer size
      if (wrBufSize > 16) {
        plData = pEOL + 1;
        // Receive the file and write it to filesystem
        fileSize = receiveFile(client, pHost, pPath, plData, plSize, wrBufSize);
      }
      else {
        // Insufficient space
        logErrCode = sendHeader(client, GEMINI, ST_INVALID, "Insufficient buffer");
        break;
      }
      // Redirect to the same page using gemini:// schema
      char *redir = new char[len + 1];
      strcpy(redir, "gemini://");
      strcat(redir, pHost);
      if (pPort) {
        strcat(redir, ":");
        strcat(redir, pPort);
      }
      strcat(redir, pPath);
      // Redirect
      logErrCode = sendHeader(client, GEMINI, ST_REDIR, redir);
      delete(redir);
      break;
    }
    // Send the requested file or the generated response
    fileSize = sendFile(client, GEMINI, pHost, pPath, pExt, pQuery, "index.gmi");
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
      logErrCode = sendHeader(client, SPARTAN, ST_INVALID, "Invalid request");
      break;
    }

    // Analyze the request
    pHost = buf;
    // Find the path
    pPath = strchr(pHost, ' ');
    if (pPath == NULL) {
      logErrCode = sendHeader(client, SPARTAN, ST_INVALID, "Invalid request");
      break;
    }
    else {
      pPath[0] = '\0';
      pPath++;
    }
    // Find the length
    pLen = strchr(pPath, ' ');
    if (pLen == NULL) {
      logErrCode = sendHeader(client, SPARTAN, ST_INVALID, "Invalid request");
      break;
    }
    else {
      pLen[0] = '\0';
      pLen++;
      // Convert to long integer
      lQuery = strtol(pLen, NULL, 10);
    }

    // If there is any query, we need to read it. We will use the same buffer, after pEOL
    if (lQuery > 0) {
      // Check the space we have
      if ((1023 - len) > lQuery) {
        // Read all the remaining data
        pQuery = pEOL + 1;
        int qLen = client->readBytes(pQuery, lQuery);
        // Check the read data lenght
        if (qLen != lQuery) {
          logErrCode = sendHeader(client, SPARTAN, ST_INVALID, "Error reading query");
          break;
        }
        // Ensure a zero terminated string
        pQuery[lQuery] = '\0';
      }
      else {
        // Insufficient space
        logErrCode = sendHeader(client, SPARTAN, ST_INVALID, "Query too long");
        break;
      }
    }
    // Send the requested file or the generated response
    fileSize = sendFile(client, SPARTAN, pHost, pPath, pExt, pQuery, "index.gmi");
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

    fileSize = sendFile(client, GOPHER, fqdn, pPath, pExt, pQuery, "gopher.map");
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
  char *pMethod, *pPath, *pExt, *pQuery, *pProto, *pEOL;
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

    // Read and ignore the rest of the request
    while (client->available())
      client->read();

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
      logErrCode = sendHeader(client, HTTP, ST_INVALID, "Invalid request");
      break;
    }

    // Analyze the request
    // TODO Reject unsupported methods
    pMethod = buf;
    // Find the path
    pPath = strchr(pMethod, ' ');
    if (pPath == NULL) {
      logErrCode = sendHeader(client, HTTP, ST_INVALID, "Invalid request");
      break;
    }
    else {
      pPath[0] = '\0';
      pPath++;
    }
    // Find the proto
    pProto = strchr(pPath, ' ');
    if (pProto == NULL) {
      logErrCode = sendHeader(client, HTTP, ST_INVALID, "Invalid request");
      break;
    }
    else {
      pProto[0] = '\0';
      pProto++;
    }
    // Find the query
    pQuery = strchr(pPath, '?');
    if (pQuery != NULL) {
      pQuery[0] = '\0';
      pQuery++;
    }
    else
      pQuery = pEOL;

    // Send the requested file or the generated response
    fileSize = sendFile(client, HTTP, NULL, pPath, pExt, pQuery, "index.gmi");
    // We can now safely break the loop
    break;
  }
  // Print final log part
  logPrint(logErrCode, fileSize);
  // Close connection
  client->flush();
  client->stop();
}


// Main Arduino setup function
void setup() {
  delay(1000);
  // Init the serial interface
  Serial.begin(115200);
  Serial.println();
  Serial.print(PROGNAME);
  Serial.print(F(" "));
  Serial.print(PROGVERS);
  Serial.print(F(" "));
  Serial.println(__DATE__);

  // Configure the LED
  //pinMode(LED, OUTPUT);
  //digitalWrite(LED, LOW ^ LEDinv);

  // SPI
  SPI.begin();
  // Init SD card
  Serial.print(F("SYS: Searching SD card, trying CS "));
  for (auto cs : spiCSPins) {
    Serial.print(cs);
    Serial.print(" ");
    if (SD.begin(cs)) {
      spiCS = cs;
      break;
    }
    delay(100);
  }
  if (spiCS > -1) {
    Serial.println(F("found!"));
    switch (SD.type()) {
      case 1: Serial.print(F("SD1")); break;
      case 2: Serial.print(F("SD2")); break;
      case 3: Serial.print(F("SDHC")); break;
      default: Serial.println(F("Unknown"));
    }
    Serial.printf(" FAT %d %dMb\r\n", SD.fatType(), SD.size64() / 1048576);
    // Set time callback
    SD.setTimeCallback(cbTime);
  }
  else {
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
  // Load time zone configuration
  loadTimeZone();
  // Load the titan:// token
  loadTitanToken();
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
        MDNS.addService("http", "tcp", 80);
        MDNS.addService("gopher", "tcp", 70);
        Serial.println(F("DNS: mDNS responder started"));
      }

#ifdef USE_UPNP
      // UPnP port mappings
      Serial.println(F("NET: Adding UPnP port mappings ... "));
      tinyUPnP->addPortMappingConfig(WiFi.localIP(), 1965, RULE_PROTOCOL_TCP, 36000, "eSWS Gemini");
      tinyUPnP->addPortMappingConfig(WiFi.localIP(), 300, RULE_PROTOCOL_TCP, 36000, "eSWS Spartan");
      tinyUPnP->addPortMappingConfig(WiFi.localIP(), 70, RULE_PROTOCOL_TCP, 36000, "eSWS Gopher");
      // Commit the port mappings to the IGD
      portMappingResult portMappingAdded = tinyUPnP->commitPortMappings();
#endif

      // Update DuckDNS
      Serial.print(F("DNS: Updating DuckDNS for domain \""));
      Serial.print(host);
      Serial.print(F("\" ... "));
      bool updated = upDuckDNS(host, ddns);
      if (updated) Serial.println(F("done."));
      else Serial.println(F("failed."));

      // Set clock
      setClock();

      // Start accepting connections
      if (haveRSAKeyCert) {
        srvGemini.begin();
        Serial.print(F("GMI: Gemini server '"));
        Serial.print(host);
        Serial.print(F(".local' started on "));
        Serial.print(WiFi.localIP());
        Serial.print(":");
        Serial.println(1965);
      };
      srvSpartan.begin();
      Serial.print(F("SPN: Spartan server '"));
      Serial.print(host);
      Serial.print(F(".local' started on "));
      Serial.print(WiFi.localIP());
      Serial.print(":");
      Serial.println(300);
      srvGopher.begin();
      Serial.print(F("GPH: Gopher server '"));
      Serial.print(host);
      Serial.print(F(".local' started on "));
      Serial.print(WiFi.localIP());
      Serial.print(":");
      Serial.println(70);
      srvHTTP.begin();
      Serial.print(F("HTP: HTTP server '"));
      Serial.print(host);
      Serial.print(F(".local' started on "));
      Serial.print(WiFi.localIP());
      Serial.print(":");
      Serial.println(80);

      reconnecting = false;
    }

    // Do MDNS stuff
    MDNS.update();

    if (haveRSAKeyCert) {
      BearSSL::WiFiClientSecure client = srvGemini.accept();
      if (client) {
        // LED on
        //digitalWrite(LED, HIGH ^ LEDinv);

        //std::vector<uint16_t> cyphers = { BR_TLS_RSA_WITH_AES_256_CBC_SHA256, BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, BR_TLS_RSA_WITH_3DES_EDE_CBC_SHA };
        //client.setCiphers(cyphers);

        //client.setFingerprint("39b2204993bab61373aed82c24a20919b4bb7a9fb6c9342452b3e5f6836848de");

        // Handle the client
        clGemini(&client);
        // LED off
        //digitalWrite(LED, LOW ^ LEDinv);
      }
    }

    WiFiClient spartan = srvSpartan.accept();
    if (spartan) {
      // LED on
      //digitalWrite(LED, HIGH ^ LEDinv);
      // Handle the client
      clSpartan(&spartan);
      // LED off
      //digitalWrite(LED, LOW ^ LEDinv);
    }

    WiFiClient gopher = srvGopher.accept();
    if (gopher) {
      // LED on
      //digitalWrite(LED, HIGH ^ LEDinv);
      // Handle the client
      clGopher(&gopher);
      // LED off
      //digitalWrite(LED, LOW ^ LEDinv);
    }

    WiFiClient http = srvHTTP.accept();
    if (http) {
      // LED on
      //digitalWrite(LED, HIGH ^ LEDinv);
      // Handle the client
      clHTTP(&http);
      // LED off
      //digitalWrite(LED, LOW ^ LEDinv);
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
