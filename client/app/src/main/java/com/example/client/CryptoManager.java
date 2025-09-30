package com.example.client;

import android.util.Base64;
import android.util.Log;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

/**
 * Erweiterte Kryptographie-Verwaltung mit AES-GCM
 */
public class CryptoManager {
    private static final String TAG = "CryptoManager";
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final int KEY_LENGTH = 256;
    
    private SecretKey secretKey;
    private final SecureRandom secureRandom;
    
    public CryptoManager() {
        this.secureRandom = new SecureRandom();
    }
    
    /**
     * Generiert einen neuen AES-256-Schlüssel
     */
    public void generateNewKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_LENGTH, secureRandom);
        this.secretKey = keyGenerator.generateKey();
        Log.d(TAG, "Neuer AES-256-Schlüssel generiert");
    }
    
    /**
     * Setzt einen vorhandenen Schlüssel
     */
    public void setKey(byte[] keyBytes) {
        if (keyBytes.length != 32) { // 256 bits
            throw new IllegalArgumentException("Schlüssel muss 256 Bit (32 Bytes) lang sein");
        }
        this.secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
        Log.d(TAG, "Verschlüsselungsschlüssel gesetzt");
    }
    
    /**
     * Gibt den aktuellen Schlüssel als Base64-String zurück
     */
    public String getKeyAsBase64() {
        if (secretKey == null) {
            throw new IllegalStateException("Kein Schlüssel verfügbar");
        }
        return Base64.encodeToString(secretKey.getEncoded(), Base64.NO_WRAP);
    }
    
    /**
     * Verschlüsselt Daten mit AES-GCM
     */
    public String encrypt(String plaintext) throws Exception {
        if (secretKey == null) {
            throw new IllegalStateException("Kein Verschlüsselungsschlüssel verfügbar");
        }
        
        try {
            // Generiere zufälligen IV
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);
            
            // Initialisiere Cipher
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
            
            // Verschlüssele Daten
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            
            // Kombiniere IV + Ciphertext
            ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertext.length);
            buffer.put(iv);
            buffer.put(ciphertext);
            
            // Encode als Base64
            String result = Base64.encodeToString(buffer.array(), Base64.NO_WRAP);
            Log.d(TAG, "Daten erfolgreich verschlüsselt, Länge: " + result.length());
            return result;
            
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
            Log.e(TAG, "Verschlüsselung fehlgeschlagen", e);
            throw new SecurityException("Verschlüsselung fehlgeschlagen: " + e.getMessage(), e);
        }
    }
    
    /**
     * Entschlüsselt Daten mit AES-GCM
     */
    public String decrypt(String encryptedData) throws Exception {
        if (secretKey == null) {
            throw new IllegalStateException("Kein Entschlüsselungsschlüssel verfügbar");
        }
        
        try {
            // Decode Base64
            byte[] data = Base64.decode(encryptedData, Base64.NO_WRAP);
            ByteBuffer buffer = ByteBuffer.wrap(data);
            
            // Extrahiere IV
            byte[] iv = new byte[GCM_IV_LENGTH];
            buffer.get(iv);
            
            // Extrahiere Ciphertext
            byte[] ciphertext = new byte[buffer.remaining()];
            buffer.get(ciphertext);
            
            // Initialisiere Cipher für Entschlüsselung
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
            
            // Entschlüssele Daten
            byte[] plaintext = cipher.doFinal(ciphertext);
            
            String result = new String(plaintext, StandardCharsets.UTF_8);
            Log.d(TAG, "Daten erfolgreich entschlüsselt");
            return result;
            
        } catch (Exception e) {
            Log.e(TAG, "Entschlüsselung fehlgeschlagen", e);
            throw new SecurityException("Entschlüsselung fehlgeschlagen: " + e.getMessage(), e);
        }
    }
    
    /**
     * Generiert einen sicheren Zufallsstring
     */
    public String generateRandomString(int length) {
        byte[] randomBytes = new byte[length];
        secureRandom.nextBytes(randomBytes);
        return Base64.encodeToString(randomBytes, Base64.NO_WRAP | Base64.URL_SAFE);
    }
    
    /**
     * Erstellt einen HMAC-SHA256-Hash
     */
    public String createHMAC(String data, String key) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(keySpec);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.encodeToString(hash, Base64.NO_WRAP);
    }
    
    /**
     * Überprüft ob ein Schlüssel verfügbar ist
     */
    public boolean hasKey() {
        return secretKey != null;
    }
    
    /**
     * Löscht den aktuellen Schlüssel sicher
     */
    public void clearKey() {
        secretKey = null;
        Log.w(TAG, "Verschlüsselungsschlüssel gelöscht");
    }
}
