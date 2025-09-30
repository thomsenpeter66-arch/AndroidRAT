package com.example.client;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKeys;
import java.security.GeneralSecurityException;
import java.io.IOException;

/**
 * Sichere Konfigurationsverwaltung mit verschlüsselter Speicherung
 */
public class SecureConfig {
    private static final String TAG = "SecureConfig";
    private static final String PREFS_NAME = "secure_rat_config";
    private static final String DEFAULT_C2_HOST = "secure.c2server.local";
    private static final int DEFAULT_C2_PORT = 8443;
    
    private SharedPreferences encryptedPrefs;
    private static SecureConfig instance;
    
    private SecureConfig(Context context) {
        try {
            String masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC);
            encryptedPrefs = EncryptedSharedPreferences.create(
                PREFS_NAME,
                masterKeyAlias,
                context,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            );
            Log.d(TAG, "Verschlüsselte Konfiguration initialisiert");
        } catch (GeneralSecurityException | IOException e) {
            Log.e(TAG, "Fehler beim Initialisieren der verschlüsselten Konfiguration", e);
            // Fallback zu Standard SharedPreferences (nicht empfohlen für Produktion)
            encryptedPrefs = context.getSharedPreferences(PREFS_NAME + "_fallback", Context.MODE_PRIVATE);
        }
    }
    
    public static synchronized SecureConfig getInstance(Context context) {
        if (instance == null) {
            instance = new SecureConfig(context.getApplicationContext());
        }
        return instance;
    }
    
    public String getC2Host() {
        return encryptedPrefs.getString("c2_host", DEFAULT_C2_HOST);
    }
    
    public void setC2Host(String host) {
        encryptedPrefs.edit().putString("c2_host", host).apply();
    }
    
    public int getC2Port() {
        return encryptedPrefs.getInt("c2_port", DEFAULT_C2_PORT);
    }
    
    public void setC2Port(int port) {
        encryptedPrefs.edit().putInt("c2_port", port).apply();
    }
    
    public String getEncryptionKey() {
        return encryptedPrefs.getString("encryption_key", null);
    }
    
    public void setEncryptionKey(String key) {
        encryptedPrefs.edit().putString("encryption_key", key).apply();
    }
    
    public String getClientId() {
        return encryptedPrefs.getString("client_id", null);
    }
    
    public void setClientId(String clientId) {
        encryptedPrefs.edit().putString("client_id", clientId).apply();
    }
    
    public String getAuthToken() {
        return encryptedPrefs.getString("auth_token", null);
    }
    
    public void setAuthToken(String token) {
        encryptedPrefs.edit().putString("auth_token", token).apply();
    }
    
    public boolean isFirstRun() {
        return encryptedPrefs.getBoolean("first_run", true);
    }
    
    public void setFirstRun(boolean firstRun) {
        encryptedPrefs.edit().putBoolean("first_run", firstRun).apply();
    }
    
    public long getLastKeyExchange() {
        return encryptedPrefs.getLong("last_key_exchange", 0);
    }
    
    public void setLastKeyExchange(long timestamp) {
        encryptedPrefs.edit().putLong("last_key_exchange", timestamp).apply();
    }
    
    public void clearAllData() {
        encryptedPrefs.edit().clear().apply();
        Log.w(TAG, "Alle Konfigurationsdaten gelöscht");
    }
}
