package com.example.client;

import android.content.Context;
import android.util.Log;
import org.json.JSONException;
import org.json.JSONObject;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.util.concurrent.ConcurrentHashMap;
import android.util.Base64;
import android.os.Build;

/**
 * Sicherer Authentifizierungsmanager für Client-Server-Kommunikation
 */
public class AuthManager {
    private static final String TAG = "AuthManager";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int CHALLENGE_LENGTH = 32;
    private static final long CHALLENGE_TIMEOUT_MS = 300000; // 5 Minuten
    
    private final SecureConfig config;
    private final CryptoManager cryptoManager;
    private final ConcurrentHashMap<String, Long> activeChallenges;
    private String currentClientId;
    private String currentAuthToken;
    
    public AuthManager(Context context) {
        this.config = SecureConfig.getInstance(context);
        this.cryptoManager = new CryptoManager();
        this.activeChallenges = new ConcurrentHashMap<>();
        this.currentClientId = config.getClientId();
        this.currentAuthToken = config.getAuthToken();
        
        // Generiere Client-ID falls nicht vorhanden
        if (currentClientId == null) {
            generateClientId();
        }
    }
    
    /**
     * Generiert eine eindeutige Client-ID
     */
    private void generateClientId() {
        try {
            currentClientId = cryptoManager.generateRandomString(16);
            config.setClientId(currentClientId);
            Log.d(TAG, "Neue Client-ID generiert");
        } catch (Exception e) {
            Log.e(TAG, "Fehler beim Generieren der Client-ID", e);
            // Fallback zu Android ID
            currentClientId = android.provider.Settings.Secure.getString(
                null, android.provider.Settings.Secure.ANDROID_ID);
            config.setClientId(currentClientId);
        }
    }
    
    /**
     * Startet den Authentifizierungsprozess
     */
    public JSONObject startAuthentication() {
        try {
            JSONObject authRequest = new JSONObject();
            authRequest.put("type", "auth_request");
            authRequest.put("client_id", currentClientId);
            authRequest.put("timestamp", System.currentTimeMillis());
            authRequest.put("version", "2.0");
            
            Log.d(TAG, "Authentifizierungsanfrage gestartet für Client: " + currentClientId);
            return authRequest;
            
        } catch (JSONException e) {
            Log.e(TAG, "Fehler beim Erstellen der Authentifizierungsanfrage", e);
            return null;
        }
    }
    
    /**
     * Verarbeitet Challenge vom Server
     */
    public JSONObject processChallenge(JSONObject challengeData) {
        try {
            String challenge = challengeData.getString("challenge");
            String serverNonce = challengeData.getString("server_nonce");
            long timestamp = challengeData.getLong("timestamp");
            
            // Prüfe Challenge-Gültigkeit
            if (System.currentTimeMillis() - timestamp > CHALLENGE_TIMEOUT_MS) {
                Log.w(TAG, "Challenge-Timeout erreicht");
                return createErrorResponse("Challenge timeout");
            }
            
            // Speichere Challenge
            activeChallenges.put(challenge, System.currentTimeMillis());
            
            // Generiere starken Client-Nonce mit zusätzlicher Entropie
            String clientNonce = cryptoManager.generateRandomString(16);
            String deviceEntropy = getDeviceFingerprint();
            
            // Erstelle kombinierte Challenge-Response mit Timestamp-Validierung
            String timestamp = String.valueOf(System.currentTimeMillis());
            String combinedData = challenge + serverNonce + clientNonce + currentClientId + deviceEntropy + timestamp;
            
            // Erstelle HMAC mit geteiltem Geheimnis
            String sharedSecret = getSharedSecret();
            if (sharedSecret == null) {
                return createErrorResponse("No shared secret available");
            }
            
            String hmacResponse = createHMAC(combinedData, sharedSecret);
            
            // Erstelle Response
            JSONObject response = new JSONObject();
            response.put("type", "auth_response");
            response.put("client_id", currentClientId);
            response.put("challenge", challenge);
            response.put("client_nonce", clientNonce);
            response.put("device_entropy", deviceEntropy);
            response.put("hmac", hmacResponse);
            response.put("timestamp", System.currentTimeMillis());
            
            Log.d(TAG, "Challenge-Response erstellt");
            return response;
            
        } catch (Exception e) {
            Log.e(TAG, "Fehler beim Verarbeiten der Challenge", e);
            return createErrorResponse("Challenge processing failed: " + e.getMessage());
        }
    }
    
    /**
     * Verarbeitet Authentifizierungsergebnis
     */
    public boolean processAuthResult(JSONObject authResult) {
        try {
            String status = authResult.getString("status");
            
            if ("success".equals(status)) {
                String newToken = authResult.optString("auth_token");
                if (newToken != null && !newToken.isEmpty()) {
                    currentAuthToken = newToken;
                    config.setAuthToken(newToken);
                    Log.i(TAG, "Authentifizierung erfolgreich, Token erhalten");
                    return true;
                }
            } else {
                String error = authResult.optString("error", "Unbekannter Fehler");
                Log.w(TAG, "Authentifizierung fehlgeschlagen: " + error);
            }
            
            return false;
            
        } catch (JSONException e) {
            Log.e(TAG, "Fehler beim Verarbeiten des Authentifizierungsergebnisses", e);
            return false;
        }
    }
    
    /**
     * Erstellt authentifizierten Request
     */
    public JSONObject createAuthenticatedRequest(JSONObject originalRequest) {
        try {
            if (currentAuthToken == null) {
                Log.w(TAG, "Kein Authentifizierungstoken verfügbar");
                return originalRequest;
            }
            
            // Füge Authentifizierungsheader hinzu
            originalRequest.put("auth_token", currentAuthToken);
            originalRequest.put("client_id", currentClientId);
            originalRequest.put("timestamp", System.currentTimeMillis());
            
            // Erstelle Request-Signatur
            String requestData = originalRequest.toString();
            String signature = createHMAC(requestData, currentAuthToken);
            originalRequest.put("signature", signature);
            
            return originalRequest;
            
        } catch (Exception e) {
            Log.e(TAG, "Fehler beim Erstellen des authentifizierten Requests", e);
            return originalRequest;
        }
    }
    
    /**
     * Validiert eingehende Server-Response
     */
    public boolean validateServerResponse(JSONObject response) {
        try {
            if (currentAuthToken == null) {
                Log.w(TAG, "Keine Token für Response-Validierung verfügbar");
                return false;
            }
            
            String receivedSignature = response.optString("signature");
            if (receivedSignature == null || receivedSignature.isEmpty()) {
                Log.w(TAG, "Keine Signatur in Server-Response");
                return false;
            }
            
            // Entferne Signatur für Validierung
            JSONObject responseForValidation = new JSONObject(response.toString());
            responseForValidation.remove("signature");
            
            String expectedSignature = createHMAC(responseForValidation.toString(), currentAuthToken);
            
            boolean valid = constantTimeEquals(expectedSignature, receivedSignature);
            if (!valid) {
                Log.w(TAG, "Server-Response-Signatur ungültig");
            }
            
            return valid;
            
        } catch (Exception e) {
            Log.e(TAG, "Fehler bei Response-Validierung", e);
            return false;
        }
    }
    
    /**
     * Erneuert das Authentifizierungstoken
     */
    public void refreshToken() {
        Log.i(TAG, "Token-Erneuerung angefordert");
        currentAuthToken = null;
        config.setAuthToken(null);
    }
    
    /**
     * Prüft ob aktuell authentifiziert
     */
    public boolean isAuthenticated() {
        return currentAuthToken != null && !currentAuthToken.isEmpty();
    }
    
    /**
     * Gibt aktuelle Client-ID zurück
     */
    public String getClientId() {
        return currentClientId;
    }
    
    /**
     * Löscht alle Authentifizierungsdaten
     */
    public void clearAuthentication() {
        currentAuthToken = null;
        activeChallenges.clear();
        config.setAuthToken(null);
        Log.w(TAG, "Authentifizierungsdaten gelöscht");
    }
    
    /**
     * Erstellt HMAC-SHA256-Hash
     */
    private String createHMAC(String data, String key) throws Exception {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
            mac.init(keySpec);
            byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.encodeToString(hash, Base64.NO_WRAP);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new SecurityException("HMAC-Erstellung fehlgeschlagen", e);
        }
    }
    
    /**
     * Timing-sichere String-Vergleichung
     */
    private boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        
        return result == 0;
    }
    
    /**
     * Erstellt Error-Response
     */
    private JSONObject createErrorResponse(String error) {
        try {
            JSONObject errorResponse = new JSONObject();
            errorResponse.put("type", "auth_error");
            errorResponse.put("error", error);
            errorResponse.put("timestamp", System.currentTimeMillis());
            return errorResponse;
        } catch (JSONException e) {
            Log.e(TAG, "Fehler beim Erstellen der Error-Response", e);
            return null;
        }
    }
    
    /**
     * Gibt starkes geteiltes Geheimnis zurück
     */
    private String getSharedSecret() {
        // Check if we have a stored strong secret
        String secret = config.getEncryptionKey();
        if (secret == null || secret.length() < 32) {
            // Generate strong shared secret
            String deviceFingerprint = getDeviceFingerprint();
            String entropy = cryptoManager.generateRandomString(32);
            String combined = currentClientId + deviceFingerprint + entropy + System.currentTimeMillis();
            
            // Hash for consistent length and additional security
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(combined.getBytes(StandardCharsets.UTF_8));
                secret = Base64.encodeToString(hash, Base64.NO_WRAP);
                config.setEncryptionKey(secret);
                Log.i(TAG, "Generated strong shared secret");
            } catch (NoSuchAlgorithmException e) {
                Log.e(TAG, "SHA-256 not available", e);
                // Fallback to secure random
                secret = cryptoManager.generateRandomString(64);
                config.setEncryptionKey(secret);
            }
        }
        return secret;
    }
    
    /**
     * Generate device fingerprint for additional entropy
     */
    private String getDeviceFingerprint() {
        try {
            String deviceInfo = Build.MANUFACTURER + Build.MODEL + Build.SERIAL + 
                               android.provider.Settings.Secure.getString(null, 
                               android.provider.Settings.Secure.ANDROID_ID);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(deviceInfo.getBytes(StandardCharsets.UTF_8));
            return Base64.encodeToString(hash, Base64.NO_WRAP).substring(0, 16);
        } catch (Exception e) {
            Log.w(TAG, "Could not generate device fingerprint", e);
            return "default_fingerprint";
        }
    }
    
    /**
     * Bereinigt alte Challenges
     */
    public void cleanupOldChallenges() {
        long currentTime = System.currentTimeMillis();
        activeChallenges.entrySet().removeIf(entry -> 
            currentTime - entry.getValue() > CHALLENGE_TIMEOUT_MS);
    }
}
