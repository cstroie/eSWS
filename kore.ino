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
#define PROGVERS "0.4"

// Certificate and key
#define SSL_CERT "/ssl/crt.pem"
#define SSL_KEY "/ssl/key.pem"

// Main configuartion file
#define CFG_FILE "/kore.cfg"

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
enum status_t {ST_OK, ST_INPUT, ST_PASSWORD, ST_REDIR, ST_MOVED, ST_NOTFOUND, ST_INVALID, ST_SERVERERROR, _ST_ALL};
int rspStatus[_PROTO_ALL][_ST_ALL] = {
  {20, 10, 11, 30, 31, 51, 59, 59},
  {2, 2, 2, 3, 3, 4, 4, 5},
  {200, 200, 200, 301, 301, 404, 500, 500},
  {0, 0, 0, 0, 0, 0, 0, 0}
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

// Main buffer
char buf[1025];

// Main configuration
char *cfgHOST, *cfgFQDN, *cfgAdminHost, *cfgTitanToken;
char *cfgDuckDNS;
char *cfgTimeZone;
bool cfgMDNS = true;

// Mime types list
struct MimeTypeEntry {
  char *ext;
  char *mmt;
  char  gph;
};
// Dynamically allocated vector to keep the associations
std::vector<MimeTypeEntry> mtList;
char binMimeType[] = "application/octet-stream";

// Log time format
#define LOG_TIMEFMT "[%d/%b/%Y:%H:%M:%S %z]"
struct tm logTime;
char bufTime[30];
int logErrCode;
int outSize;

// Set ADC to Voltage
ADC_MODE(ADC_VCC);


// Read one line from stream, delimited by the specified char,
// with maximum of specified lenght, and return the lenght read string
int readLine(Stream *stream, char *buf, int maxLen = 1024) {
  int len = 0;
  while (stream->available()) {
    // Read one char
    char c = stream->read();
    // Limit line length
    if (len >= maxLen - 1) {
      len = -1;
      break;
    }
    // Will always return CRLF, then ZERO
    if (c == '\r' or c == '\n') {
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
  // No (more) data available
  if (!stream->available()) {
    // No EOL?
    buf[len] = '\0';
  }
  // Return the lenght
  return len;
}

// Read one line from file, delimited by the specified char,
// with maximum of specified lenght, and return the lenght of the read string
int readLine(File *file, char *buf, int maxLen = 1024) {
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
    // Will never return CRLF
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
  // No (more) data available
  if (!file->available()) {
    if (len == 0)
      // No data at all
      len = -2;
    else
      // No EOL?
      buf[len] = '\0';
  }
  // Return the line lenght
  return len;
}

// URI decoder
void percentDecode(char *uri) {
  char *p, *result;
  int i = 0;
  bool changed = false;
  result = new char[strlen(uri) + 1];
  if (!result)
    return;
  for (p = (char *)uri; *p != '\0'; p++) {
    if (*p == '%' && isxdigit(*(p + 1)) && isxdigit(*(p + 2))) {
      changed = true;
      // Percent encoded hex: %xx
      char tmp[] = { *(p + 1), *(p + 2), '\0' };
      result[i++] = (char)strtol(tmp, NULL, 16);
      p += 2;
    }
    else {
      result[i++] = *p;
    }
  }
  result[i] = '\0';
  if (changed)
    strcpy(uri, result);
  delete(result);
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

// Set the host name and FQDN
void setHostName(char *str) {
  Serial.print(F("SYS: Hostname: "));
  cfgFQDN = strdup(str);
  // Find the first occurence of '.' in FQDN
  char *dom = strchr(str, '.');
  if (dom != NULL) {
    dom[0] = '\0';
    cfgHOST = strdup(str);
  }
  else
    cfgHOST = cfgFQDN;
  Serial.println(cfgFQDN);
  WiFi.hostname(cfgHOST);
}

// Set the admin host name
void setAdminHost(char *str) {
  Serial.print(F("SYS: Admin hostname: "));
  cfgAdminHost = strdup(str);
  Serial.println(cfgAdminHost);
}

// Set the DuckDNS token
void setDuckDNS(char *str) {
  Serial.print(F("SYS: DuckDNS token: "));
  cfgDuckDNS = strdup(str);
  Serial.println(cfgDuckDNS);
}

// Set the titan token
void setTitanToken(char *str) {
  Serial.print(F("SYS: Titan token: "));
  cfgTitanToken = strdup(str);
  Serial.println(cfgTitanToken);
}

// Set the timezone
void setTimeZone(char *str) {
  Serial.print(F("SYS: Timezone: "));
  cfgTimeZone = strdup(str);
  Serial.println(cfgTimeZone);
}

// Set MDNS
void setMDNS(char *str) {
  Serial.print(F("DNS: MDNS: "));
  if ((str[0] == 'n') or
      (str[0] == 'N') or
      (str[0] == '0')) {
    cfgMDNS = false;
    Serial.println(F("disabled"));
  }
  else {
    cfgMDNS = true;
    Serial.println(F("enabled"));
  }
}

// Set WiFi authentication
void setWiFiAuth(char *ssid) {
  // Find the first occurence of ','
  char *pass = strchr(ssid, ',');
  if (pass != NULL) {
    pass[0] = '\0';
    pass++;
    Serial.print(F("WFI: Add '")); Serial.print(ssid); Serial.print(F("' "));
#ifdef DEBUG
    Serial.print(F("with pass '")); Serial.print(pass); Serial.print(F("' "));
#endif
    Serial.println();
    wifiMulti.addAP(ssid, pass);
  }
}

// Set mime-type
void setMimeType(char *ext) {
  // Find the first occurence of ','
  char *gph = strchr(ext, ',');
  if (gph != NULL) {
    gph[0] = '\0';
    gph++;
    // Find the second occurence of ','
    char *mmt = strchr(gph, ',');
    if (mmt != NULL) {
      mmt[0] = '\0';
      mmt++;
      Serial.print(F("MIM: Add '")); Serial.print(mmt); Serial.print(F("' for '")); Serial.print(ext); Serial.println(F("' "));
      MimeTypeEntry mtNew;
      mtNew.ext = strdup(ext);
      mtNew.gph = gph[0];
      mtNew.mmt = strdup(mmt);
      mtList.push_back(mtNew);
    }
  }
}

// Trim the string and return the trimmed one
char *trim_move(char *s) {
  char *o = s;
  size_t len = 0;
  while (isspace((unsigned char) *s))
    s++;
  if (*s) {
    char *p = s;
    while (*p) p++;
    while (isspace((unsigned char) * (--p)));
    p[1] = '\0';
    len = (size_t)(p - s + 1);
  }
  return (char*)((s == o) ? s : memmove(o, s, len + 1));
}

// Trim the string and return the length
size_t trim(char *s) {
  size_t len = 0;
  while (isspace((unsigned char) *s))
    s++;
  if (*s) {
    char *p = s;
    while (*p) p++;
    while (isspace((unsigned char) * (--p)));
    p[1] = '\0';
    len = (size_t)(p - s);
  }
  return len;
}

// Load configuration
void loadConfig() {
  int len = 1024;
  char *pKey, *pVal;

  // Read the main configuration file
  Serial.print(F("SYS: Reading main configuration from "));
  Serial.print(CFG_FILE);
  Serial.println(F(" ... "));
  File file = SD.open(CFG_FILE, "r");
  if (file.isFile()) {
    while (len >= 0) {
      // Read one line from file
      len = readLine(&file, buf, 256);
      // Skip over empty lines
      if (len == 0) continue;
      // Skip over comment lines
      if (buf[0] == '#') continue;
      // Find the key and value, separated by '='
      pKey = strtok((char *)buf, "=");
      if (trim(pKey) > 0) {
        pVal = strtok(NULL, "\r\n");
        if (pVal != NULL) {
          // The value starts at the next char
          pVal++;
          if (trim(pVal) > 0) {
            if      (!strcmp(pKey, "hostname")) setHostName(pVal);
            else if (!strcmp(pKey, "admin"))    setAdminHost(pVal);
            else if (!strcmp(pKey, "titan"))    setTitanToken(pVal);
            else if (!strcmp(pKey, "ddns"))     setDuckDNS(pVal);
            else if (!strcmp(pKey, "tz"))       setTimeZone(pVal);
            else if (!strcmp(pKey, "wifi"))     setWiFiAuth(pVal);
            else if (!strcmp(pKey, "mime"))     setMimeType(pVal);
            else if (!strcmp(pKey, "mdns"))     setMDNS(pVal);
          }
        }
      }
    }
    // Shrink the mime-type vector now
    mtList.shrink_to_fit();
  }
  else
    Serial.println(F("ERROR"));
  file.close();
}



// Set time via NTP, as required for x.509 validation
// TODO Need a timeout
void setClock() {
  // https://www.gnu.org/software/libc/manual/html_node/TZ-Variable.html
  configTime(cfgTimeZone, "pool.ntp.org", "time.nist.gov");
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
  return time(NULL);
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

// Copy a file from src to dst
void copyFile(const char *src, const char *dst) {
  File srcFile = SD.open(src, "r");
  File dstFile = SD.open(dst, "w");
  uint8_t buf[512];
  while (srcFile.available()) {
    int len = srcFile.read(buf, 512);
    dstFile.write(buf, len);
  }
  dstFile.close();
  srcFile.close();
}

// Move a file from src to dst
void moveFile(const char *src, const char *dst) {
  copyFile(src, dst);
  SD.remove(src);
}

// Send the proper header according to protocol and return the real status
int sendHeader(Stream *client, proto_t proto, status_t status, const char *pText) {
  uint16_t stCode = rspStatus[proto][status];
  switch (proto) {
    case GEMINI:
    case SPARTAN:
      client->printf("%d %s\r\n", stCode, pText);
      break;
    case HTTP:
      if (status == ST_OK)
        client->printf("HTTP/1.0 %d OK\r\nContent-Type: %s; encoding=utf8\r\nConnection: close\r\n\r\n", stCode, pText);
      else if (status == ST_MOVED or status == ST_REDIR)
        client->printf("HTTP/1.0 %d Moved\r\nLocation: %s\r\nConnection: close\r\n\r\n", stCode, pText);
      else
        client->printf("HTTP/1.0 %d %s\r\nConnection: close\r\n\r\n", stCode, pText);
      break;
    case GOPHER:
      if (status == ST_MOVED or status == ST_REDIR)
        client->printf("1Redirect to %s\t%s\t%s\t%d\r\n", pText, pText, cfgFQDN, 70);
      else if (status != ST_OK)
        client->printf("i%s\t\t%s\t%d\r\n", pText, cfgFQDN, 70);
      break;
  }
  // Return the status code
  return (int)stCode;
}

// Send a file in CPIO arhive
int sendFileCPIO(Stream *client, File file) {
  int outSize = 0;
  int pad = 0;
  // ino type+mode uid gid nlink mtime size devM devm rdevM rdevm filename_len filename 0
  int hdrSize = sprintf(buf, "070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X00000000%s%c",
                        0, 0100644, 0, 0, 1, (uint32_t)file.getLastWrite(), (uint32_t)file.size(), 0, 0, 0, 0, strlen(file.fullName()) + 1, file.fullName(), '\0');
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
int sendDirCPIO(Stream *client, File dir) {
  int outSize = 0;
  while (File entry = dir.openNextFile()) {
    if (entry.isFile())
      // Send the file
      outSize += sendFileCPIO(client, entry);
    else if (entry.isDirectory())
      // Recurse into directory
      outSize += sendDirCPIO(client, entry);
    // Close the file
    entry.close();
  }
  // Return the output size
  return outSize;
}

// Send a simple ascii CPIO archive with card contents
int sendArchCPIO(Stream * client, proto_t proto, char *path) {
  int outSize = 0;
  // Check the path exists
  if (!SD.exists(path)) {
    logErrCode = sendHeader(client, proto, ST_NOTFOUND, "File not found");
    return 0;
  }
  // Start with the header
  logErrCode = sendHeader(client, proto, ST_OK, "application/x-cpio");
  // Open the directory
  File dir = SD.open(path);
  // Send its content
  outSize += sendDirCPIO(client, dir);
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
      len = readLine(file, line, maxLen - 5);
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

// Send the content of a file
int sendFileContent(Stream *client, File *file) {
  int outSize = 0;
  uint8_t fileBuf[512];
  if (file->isFile()) {
    // Send the content
    while (file->available()) {
      int len = file->read(fileBuf, 512);
      client->write(fileBuf, len);
      outSize += len;
    }
  }
  return outSize;
}

// Send a gemini feed
int sendFeed(Stream * client, proto_t proto, char *path, char *pathFS) {
  int outSize = 0;
  int len;
  time_t modTime;
  struct tm* stTime;
  char line[100];
  char *pTitle;
  char *tmpPath;
  File tmpFile;
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

  // Create a temporary path
  tmpPath = new char[strlen(pathFS) + 20];

  // Check if there is a feed header file
  strcpy(tmpPath, pathFS);
  strcat(tmpPath, "/feed-hdr.gmi");
  tmpFile = SD.open(tmpPath, "r");
  outSize += sendFileContent(client, &tmpFile);
  tmpFile.close();

  // Use the 'index.gmi' file to get the feed title if no feed header file
  if (outSize == 0) {
    strcpy(tmpPath, pathFS);
    strcat(tmpPath, "/index.gmi");
    // Read the title
    len = readPageTitle(tmpPath, line);
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
  }

  // List files in the specified filesystem path
  File root = SD.open(pathFS);
  while (tmpFile = root.openNextFile()) {
    // Ignore some items
    if (tmpFile.isDirectory() or                        // directories
        tmpFile.name()[0] == '.' or                     // hidden files
        //strspn(tmpFile.name(), "1234567890") < 2  or    // needs to start with 2 digits
        strncmp(tmpFile.name(), "index.", 6) == 0 or    // index
        strncmp(tmpFile.name(), "gopher.", 7) == 0 or   // gopher map
        strncmp(tmpFile.name(), "feed", 4) == 0)        // feed, feed header and footer
      continue;
    // Get the last modified time
    time_t fileTime = tmpFile.getLastWrite();
    // Get creation time
    //time_t fileTime = tmpFile.getCreationTime();
    stTime = localtime(&fileTime);

    // Read the title
    len = readPageTitle(&tmpFile, line);
    // Check if we got something
    if (len > 0) {
      // Trim its head
      int head = strspn(line, "# \t");
      pTitle = &line[head];
      len -= head;
    }
    else {
      // Just use the file name
      strcpy(line, (char*)tmpFile.name());
      pTitle = &line[0];
    }

    // Different for different protocols
    switch (proto) {
      case GOPHER:
        outSize += client->printf("%04d-%02d-%02d %s\t%s/%s\t%s\t%d\r\n",
                                  stTime->tm_year + 1900, stTime->tm_mon + 1, stTime->tm_mday, pTitle, path, tmpFile.name(), cfgFQDN, 70);
        break;
      case GEMINI:
      case SPARTAN:
      case HTTP:
        outSize += client->printf("=> %s/%s\t%d-%02d-%02d %s\r\n",
                                  path, tmpFile.name(), stTime->tm_year + 1900, stTime->tm_mon + 1, stTime->tm_mday, pTitle);
        break;
    }
    // Close the file
    tmpFile.close();
  }
  // Close the directory
  root.close();

  // Check if there is a feed footer file
  strcpy(tmpPath, pathFS);
  strcat(tmpPath, "/feed-ftr.gmi");
  tmpFile = SD.open(tmpPath, "r");
  outSize += sendFileContent(client, &tmpFile);
  tmpFile.close();

  // Delete the temporary path string
  delete(tmpPath);

  outSize += client->print("\r\n");
  // Restore the path
  pName[0] = '/';
  // Return the feed size
  return outSize;
}

// Send the virtual server status page
int sendStatusPage(Stream *client) {
  int outSize = 0;
  logErrCode = sendHeader(client, GEMINI, ST_OK, "text/gemini");
  outSize += client->print("# Server status\r\n\r\n");
  // Hostname
  outSize += client->print(cfgFQDN);
  outSize += client->print("\t");
  outSize += client->print(cfgHOST);
  outSize += client->print(".local\r\n\r\n");
  // Uptime in seconds and text
  unsigned long ups = 0;
  char upt[32] = "";
  ups = uptime(upt, sizeof(upt));
  outSize += client->print("Uptime: "); outSize += client->print(upt); outSize += client->print("\r\n");
  // SSID
  outSize += client->print("SSID: "); outSize += client->print(WiFi.SSID()); outSize += client->print("\r\n");
  // Get RSSI
  outSize += client->print("Signal: "); outSize += client->print(WiFi.RSSI()); outSize += client->print(" dBm\r\n");
  // IP address
  outSize += client->print("IP address: "); outSize += client->print(WiFi.localIP()); outSize += client->print("\r\n");
  // Free Heap
  outSize += client->print("Free memory: "); outSize += client->print(ESP.getFreeHeap()); outSize += client->print(" bytes\r\n");
  // Read the Vcc (mV)
  outSize += client->print("Voltage: "); outSize += client->print(ESP.getVcc()); outSize += client->print(" mV\r\n");
  // Return the file size
  return outSize;
}

// Receive a file using the titan:// schema and write it to filesystem
int receiveFile(Stream *client, char *pHost, char *pPath, char *plData, int plSize, int bufSize) {
  File file;    // The file handler to test the path
  // Validate the path (.. /./ //)
  if (strstr(pPath, "..") != NULL or
      strstr(pPath, "/./") != NULL or
      strstr(pPath, "//") != NULL) {
    logErrCode = sendHeader(client, GEMINI, ST_INVALID, "Invalid path");
    return 0;
  }
  // Virtual hosting, find the server root directory
  int hostLen = strlen(cfgFQDN);
  // Find the longest host name
  if (pHost != NULL)
    if (hostLen < strlen(pHost))
      hostLen = strlen(pHost);
  // Dinamically create the file path ("/" + host + path (+ "index.gmi"))
  char *filePath = new char[strlen(pPath) + hostLen + 20];
  // Start from root
  strcpy(filePath, "/");
  // Append the host name, as in request, or fall back to FQDN
  if (pHost == NULL)
    // No host in request (Gopher, HTTP/1.0)
    strcat(filePath, cfgFQDN);
  else if (strncmp(cfgHOST, pHost, strlen(cfgHOST)) == 0 and strncmp(&pHost[strlen(cfgHOST)], ".local", 6) == 0)
    // Special case for .local
    strcat(filePath, cfgHOST);
  else {
    // Use the requested host name
    strcat(filePath, pHost);
  }
  // Check the virtual host directory exists
  file = SD.open(filePath, "r");
  if (!file.isDirectory()) {
    // If not, fallback to FQDN
    file.close();
    strcpy(filePath, "/");
    strcat(filePath, cfgFQDN);
  }
  // Append a slash, if needed
  if (filePath[strlen(filePath) - 1] != '/' and pPath[0] != '/')
    strcat(filePath, "/");
  // Append the path
  strcat(filePath, pPath);
  // If directory, return error
  file = SD.open(filePath, "r");
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
  // Archive the existing file
  if (SD.exists(filePath)) {
    char buf[20];
    struct tm* stTime;
    time_t now = time(NULL);
    stTime = localtime(&now);
    // Create a date-time base file name
    sprintf(buf, "/%04d%02d%02d-%02d%02d%02d",
            stTime->tm_year + 1900, stTime->tm_mon + 1, stTime->tm_mday,
            stTime->tm_hour, stTime->tm_min, stTime->tm_sec);
    // Create the archive file path
    char *pthArchive = new char[strlen(filePath) + 30];
    // Start from root
    strcpy(pthArchive, "/archive");
    // Append existing file path
    strcat(pthArchive, filePath);
    // Create a direcory with same name
    SD.mkdir(pthArchive);
    // Append the date-time file name
    strcat(pthArchive, buf);
    // Copy the existing file
    copyFile(filePath, pthArchive);
    // Destroy the file path string
    delete (pthArchive);
  }

  // Move the temporary file
  moveFile("/~titan~.tmp", filePath);

  // Destroy the file path string
  delete (filePath);
  // Return the file size
  return total;
}

// Send file content or generated file
int sendFile(Stream *client, proto_t proto, char *pHost, char *pPath, char *pQuery, const char *pFile) {
  int outSize = 0;  // Total output size
  int dirEnd = 0;   // Index to directory name ending
  int vhostEnd = 0; // Index to vhost name ending
  char *pName;      // The file name part of the path
  char *pExt;       // The file name extension
  File file;        // The file handler to test the path
  // Validate the path (.. /./ //)
  if (strstr(pPath, "..") != NULL or
      strstr(pPath, "/./") != NULL or
      strstr(pPath, "//") != NULL) {
    logErrCode = sendHeader(client, proto, ST_INVALID, "Invalid path");
    return 0;
  }
  // Check if this is the admin host
  bool isAdminHost = (*cfgAdminHost != 0 and strncmp(pHost, cfgAdminHost, strlen(cfgAdminHost)) == 0);
  // Virtual hosting, find the server root directory
  int hostLen = strlen(cfgFQDN);
  // Find the longest host name
  if (pHost != NULL)
    if (hostLen < strlen(pHost))
      hostLen = strlen(pHost);
  // Dinamically create the file path ("/" + host + path (+ "index.gmi"))
  char *filePath = new char[strlen(pPath) + hostLen + 20];
  // Start from root
  strcpy(filePath, "/");
  // Append the host name, as in request, or fall back to FQDN
  if (pHost == NULL)
    // No host in request (HTTP/1.0)
    strcat(filePath, cfgFQDN);
  else if (strncmp(cfgHOST, pHost, strlen(cfgHOST)) == 0 and strncmp(&pHost[strlen(cfgHOST)], ".local", 6) == 0)
    // Special case for .local
    strcat(filePath, cfgHOST);
  else if (isAdminHost)
    // Admin host
    strcat(filePath, cfgFQDN);
  else {
    // Use the requested host name
    strcat(filePath, pHost);
  }
  // Check the virtual host directory exists
  file = SD.open(filePath, "r");
  if (!file.isDirectory()) {
    // If not, fallback to FQDN
    file.close();
    strcpy(filePath, "/");
    strcat(filePath, cfgFQDN);
  }
  // Keep this position
  vhostEnd = strlen(filePath);
  // Append a slash, if needed
  if (filePath[strlen(filePath) - 1] != '/' and pPath[0] != '/')
    strcat(filePath, "/");
  // Append the path
  strcat(filePath, pPath);
  // Check if it's directory requested and append default file name for protocol
  file = SD.open(filePath, "r");
  if (file.isDirectory()) {
    file.close();
    // Redirect to slash-ending path if directory
    if (pPath[strlen(pPath) - 1] != '/') {
      // Moved
      strcat(pPath, "/");
      logErrCode = sendHeader(client, proto, ST_MOVED, pPath);
      // Destroy the file path string
      delete (filePath);
      // Return 0
      return 0;
    }
    // Keep this position, if it was a directory
    dirEnd = strlen(filePath);
    // Append the default file name
    strcat(filePath, pFile);
    file = SD.open(filePath, "r");
  };
  // Find the requested file name in filesystem path
  pName = strrchr(filePath, '/');
  if (pName == NULL)
    // Fallback to end of string
    pName = &filePath[strlen(filePath)];
  else
    // Find the extension
    pExt = strrchr(pName, '.');
  if (pExt == NULL)
    // Fallback to end of string
    pExt = &filePath[strlen(filePath)];
  // Check if the file exists
  if (file.isFile() and strncmp(pQuery, "nofile", 7) != 0) {
    // Keep the file size
    outSize = file.size();
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
    sendFileContent(client, &file);
    file.close();
    // Add admin footer for file if gemini
    if (isAdminHost and strcmp(pExt, "gmi") == 0) {
      client->print("---\r\n=> titan://. Edit page\r\n");
    }
  }
  else if (dirEnd > 0) {
    // The request was for a directory and there is no directory index.
    // Create a file listing
    // Restore the directory path
    filePath[dirEnd] = '\0';
    // Send the response
    switch (proto) {
      case GOPHER:
        outSize += client->printf("iContent of %s\t\tnull\t70\r\n", pPath);
        outSize += client->print("i\t\tnull\t70\r\n");
        break;
      case GEMINI:
      case SPARTAN:
      case HTTP:
        logErrCode = sendHeader(client, proto, ST_OK, "text/gemini");
        outSize += client->print("# Content of ");
        outSize += client->print(pPath);
        outSize += client->print("\r\n\r\n");
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
            if (*pPath != 0 and pPath[strlen(pPath) - 1] != '/')
              strcat(gPath, "/");
            strcat(gPath, entry.name());
            if (entry.isDirectory())
              strcat(gPath, "/");
            // Write the line
            outSize += client->printf("%c%s\t%s\t%s\t%d\r\n",
                                      gType, (char*)entry.name(), gPath, cfgFQDN, 70);

          }
          break;
        case GEMINI:
        case SPARTAN:
        case HTTP:
          outSize += client->print("=> ");
          outSize += client->print(pPath);
          if (*pPath != 0 and pPath[strlen(pPath) - 1] != '/')
            outSize += client->print("/");
          outSize += client->print(entry.name());
          if (entry.isDirectory())
            outSize += client->print("/");
          outSize += client->print("\t");
          outSize += client->print(entry.name());
          outSize += client->print("\r\n");
          break;
      }
    }
    // Add admin footer for directory
    if (isAdminHost) {
      client->print("---\r\n=> /admin/create-directory Create directory\r\n");
    }
  }
  else if (strcmp(pPath, "/status.gmi") == 0 and proto == GEMINI) {
    // Send the server status page
    outSize = sendStatusPage(client);
  }
  else if (strcmp(pPath, "/input.gmi") == 0 and proto == GEMINI) {
    // Send the server status page
    logErrCode = sendHeader(client, proto, ST_PASSWORD, "Password:");
  }
  else if (strcmp(pPath, "/admin/create-directory") == 0 and proto == GEMINI) {
    // Ask for directory name if not specified
    if (*pQuery == 0)
      logErrCode = sendHeader(client, proto, ST_INPUT, "Directory (absolute path):");
    else {
      // Trim to vhost
      filePath[vhostEnd] = '\0';
      // Append a slash, if needed
      if (pQuery[0] != '/')
        strcat(filePath, "/");
      // Append the specified directory name
      strcat(filePath, pQuery);
      SD.mkdir(filePath);
      logErrCode = sendHeader(client, proto, ST_REDIR, &filePath[vhostEnd]);
    }
    // Destroy the file path string
    delete (filePath);
    // Return 0
    return 0;
  }
  else if (strcmp(pPath, "/cpio") == 0) {
    // Redirect to a date-based export URL
    char bufTime[100];
    struct tm* stTime;
    time_t now = time(NULL);
    stTime = localtime(&now);
    sprintf(bufTime, "/%s-%04d%02d%02d-%02d%02d%02d.cpio",
            cfgHOST, (stTime->tm_year) + 1900, (stTime->tm_mon) + 1, stTime->tm_mday, stTime->tm_hour, stTime->tm_min, stTime->tm_sec);
    logErrCode = sendHeader(client, proto, ST_REDIR, bufTime);
    // Destroy the file path string
    delete (filePath);
    // Return 0
    return 0;
  }
  else if (strncmp(pExt, ".cpio", 5) == 0) {
    // The requested virtual file is a CPIO archive. Trim the filepath
    // to the file name and get the parent directory (it can also be a
    // single file). Use it for archive root.
    pName[0] = '\0';
    // Send the archive
    outSize = sendArchCPIO(client, proto, filePath);
    // Restore the filePath
    pName[0] = '/';
  }
  else if (strncmp(pName, "/feed", 5) == 0) {
    // The requested virtual file is a gemini feed
    pName[0] = '\0';
    // Send the feed
    outSize = sendFeed(client, proto, pPath, filePath);
    // Restore the filePath
    pName[0] = '/';
  }
  else
    // File not found
    logErrCode = sendHeader(client, proto, ST_NOTFOUND, "File not found");

  // Destroy the file path string
  delete (filePath);
  // Return the file size
  return outSize;
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
  char *pSchema, *pHost, *pPort, *pPath, *pQuery, *pEOL;
  bool titan = false;
  // Prepare the log
  getLocalTime(&logTime);
  logErrCode = 20;
  // Set a global time out
  unsigned long timeOut = millis() + 5000;
  // Loop as long as connected (and before timed out)
  while (client->connected() and millis() < timeOut) {
    // Read one line from request
    int len = readLine(client, buf);
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
    // Lowercase path
    for (char *p = pPath; *p; ++p)
      *p = tolower(*p);
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
      percentDecode(pQuery);
    }
    else
      pQuery = pEOL;

#ifdef DEBUG
    Serial.println();
    Serial.print(F("Schema: ")); Serial.println(pSchema);
    Serial.print(F("Host  : ")); Serial.println(pHost);
    Serial.print(F("Port  : ")); Serial.println(pPort);
    Serial.print(F("Path  : ")); Serial.println(pPath);
    Serial.print(F("Query : ")); Serial.println(pQuery);
#endif

    // If the protocol is 'titan', we need to read the upcoming data. We will use the same buffer, after pEOL
    if (titan) {
      // Allow titan only for admin host
      if (*cfgAdminHost != 0 and
          strncmp(pHost, cfgAdminHost, strlen(cfgAdminHost)) != 0) {
        logErrCode = sendHeader(client, GEMINI, ST_INVALID, "Titan not allowed for this host");
        break;
      }
      // Quick check the query
      if (*pQuery == 0) {
        logErrCode = sendHeader(client, GEMINI, ST_INVALID, "Invalid parameters for titan");
        break;
      }
      // We need to decompose the query/parameters and get mime, size and token
      char *pKey, *pVal, *pMime, *pToken, *plData;
      long int plSize;
      // Get a fragment from query
      pKey = strtok(pQuery, ";");
      while (pKey != NULL) {
        // Check if it has the form "key=value"
        pVal = strchr(pKey, '=');
        if (pVal != NULL) {
          // The value starts at the next char
          pVal++;
          if      (strncmp(pKey, "mime", 4) == 0)   pMime = pVal;
          else if (strncmp(pKey, "token", 5) == 0)  pToken = pVal;
          else if (strncmp(pKey, "size", 4) == 0)   plSize = strtol(pVal, NULL, 10);
        }
        // Next fragment
        pKey = strtok(NULL, ";");
      }
      // Check the token, if configured
      if (cfgTitanToken != NULL) {
        if (strncmp(cfgTitanToken, pToken, strlen(cfgTitanToken)) != 0) {
          logErrCode = sendHeader(client, GEMINI, ST_INVALID, "Invalid token");
          break;
        }
      }
      // Check if the payload size is greater than zero
      if (plSize <= 0) {
        logErrCode = sendHeader(client, GEMINI, ST_INVALID, "Invalid payload size");
        break;
      }
      int bufSize = 1023 - len;
      // Ensure a minimum buffer size
      if (bufSize > 16) {
        plData = pEOL + 1;
        // Receive the file and write it to filesystem
        outSize = receiveFile(client, pHost, pPath, plData, plSize, bufSize);
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
      // We can now safely break the loop
      break;
    }
    else {
      // Send the requested file or the generated response
      outSize = sendFile(client, GEMINI, pHost, pPath, pQuery, "index.gmi");
      // We can now safely break the loop
      break;
    }
  }
  // Print final log part
  logPrint(logErrCode, outSize);
  // Close connection
  client->flush();
  client->stop();
}

// Handle Spartan protocol
void clSpartan(WiFiClient * client) {
  char *pHost, *pPath, *pQuery, *pLen, *pEOL;
  long int lQuery;
  // Prepare the log
  getLocalTime(&logTime);
  logErrCode = 2;
  // Set a global time out
  unsigned long timeOut = millis() + 5000;
  while (client->connected() and millis() < timeOut) {
    // Read one line from request
    int len = readLine(client, buf);
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

#ifdef DEBUG
    Serial.println();
    Serial.print(F("Host    : ")); Serial.println(pHost);
    Serial.print(F("Path    : ")); Serial.println(pPath);
    Serial.print(F("QueryLen: ")); Serial.println(lQuery);
#endif

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
#ifdef DEBUG
        Serial.print(F("Query   : ")); Serial.println(pQuery);
#endif
      }
      else {
        // Insufficient space
        logErrCode = sendHeader(client, SPARTAN, ST_INVALID, "Query too long");
        break;
      }
    }
    // Send the requested file or the generated response
    outSize = sendFile(client, SPARTAN, pHost, pPath, pQuery, "index.gmi");
    // We can now safely break the loop
    break;
  }
  // Print final log part
  logPrint(logErrCode, outSize);
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
    int len = readLine(client, buf);
    // If zero, there is no data yet; read again
    if (len == 0) continue;
    // If last char is not zero, the line is not complete
    if (buf[len] != '\0') continue;

    char *pPath, *pQuery, *pEOL;
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
    else
      pQuery = pEOL;

#ifdef DEBUG
    Serial.println();
    Serial.print(F("Path : ")); Serial.println(pPath);
    Serial.print(F("Query: ")); Serial.println(pQuery);
#endif

    outSize = sendFile(client, GOPHER, cfgFQDN, pPath, pQuery, "gopher.map");
    client->print("\r\n.\r\n");
    // We can now safely break the loop
    break;
  }
  // Print final log part
  logPrint(logErrCode, outSize);
  // Close connection
  client->flush();
  client->stop();
}

// Handle HTTP protocol
void clHTTP(WiFiClient * client) {
  char *pMethod, *pHost, *pPath, *pQuery, *pProto, *pEOL;
  // Prepare the log
  getLocalTime(&logTime);
  logErrCode = 200;
  // Set a global time out
  unsigned long timeOut = millis() + 5000;
  while (client->connected() and millis() < timeOut) {
    // Read one line from request
    int len = readLine(client, buf);
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
    // For now the host is empty
    pHost = pEOL;

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
      percentDecode(pQuery);
    }
    else
      pQuery = pEOL;

    // Send the requested file or the generated response
    outSize = sendFile(client, HTTP, cfgFQDN, pPath, pQuery, "index.gmi");
    // We can now safely break the loop
    break;
  }
  // Print final log part
  logPrint(logErrCode, outSize);
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



  // Load main configuration
  loadConfig();
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

      // Set up mDNS responder
      if (cfgMDNS) {
        if (!MDNS.begin(cfgHOST)) {
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
      Serial.print(cfgHOST);
      Serial.print(F("\" ... "));
      bool updated = upDuckDNS(cfgHOST, cfgDuckDNS);
      if (updated) Serial.println(F("done."));
      else Serial.println(F("failed."));

      // Set clock
      setClock();

      // Start accepting connections
      if (haveRSAKeyCert) {
        srvGemini.begin();
        Serial.print(F("GMI: Gemini server '"));
        Serial.print(cfgHOST);
        Serial.print(F(".local' started on "));
        Serial.print(WiFi.localIP());
        Serial.print(":");
        Serial.println(1965);
      };
      srvSpartan.begin();
      Serial.print(F("SPN: Spartan server '"));
      Serial.print(cfgHOST);
      Serial.print(F(".local' started on "));
      Serial.print(WiFi.localIP());
      Serial.print(":");
      Serial.println(300);
      srvGopher.begin();
      Serial.print(F("GPH: Gopher server '"));
      Serial.print(cfgHOST);
      Serial.print(F(".local' started on "));
      Serial.print(WiFi.localIP());
      Serial.print(":");
      Serial.println(70);
      srvHTTP.begin();
      Serial.print(F("HTP: HTTP server '"));
      Serial.print(cfgHOST);
      Serial.print(F(".local' started on "));
      Serial.print(WiFi.localIP());
      Serial.print(":");
      Serial.println(80);

      reconnecting = false;
    }

    // Do MDNS stuff
    if (cfgMDNS)
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
    if (cfgMDNS)
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
