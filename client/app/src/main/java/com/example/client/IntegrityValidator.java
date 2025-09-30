package com.example.client;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Debug;
import android.util.Log;
import com.scottyab.rootbeer.RootBeer;
import java.io.File;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

/**
 * Integritätsprüfung und Anti-Tampering-Schutz
 */
public class IntegrityValidator {
    private static final String TAG = "IntegrityValidator";
    
    // Diese Signatur sollte durch Ihre echte App-Signatur ersetzt werden
    private static final String EXPECTED_SIGNATURE_HASH = "YOUR_REAL_APP_SIGNATURE_HASH_HERE";
    
    // Bekannte Emulator-Indikatoren
    private static final String[] EMULATOR_FILES = {
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props",
        "/dev/socket/qemud",
        "/system/etc/init.goldfish.rc",
        "/system/etc/init.ranchu.rc"
    };
    
    // Bekannte Root-Pfade
    private static final String[] ROOT_PATHS = {
        "/system/app/Superuser.apk",
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/system/bin/.ext/.su",
        "/system/etc/init.d/99SuperSUDaemon",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/local/su"
    };
    
    // Bekannte Hook-Frameworks
    private static final String[] HOOK_PACKAGES = {
        "de.robv.android.xposed.installer",
        "com.saurik.substrate",
        "com.zachspong.temprootremovejb",
        "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree",
        "com.formyhm.hiderootPremium",
        "me.phh.superuser",
        "eu.chainfire.supersu"
    };
    
    private final Context context;
    private final RootBeer rootBeer;
    
    public IntegrityValidator(Context context) {
        this.context = context.getApplicationContext();
        this.rootBeer = new RootBeer(context);
    }
    
    /**
     * Führt eine umfassende Integritätsprüfung durch
     */
    public SecurityCheckResult performSecurityCheck() {
        SecurityCheckResult result = new SecurityCheckResult();
        
        try {
            // App-Signatur prüfen
            result.signatureValid = validateAppSignature();
            
            // Debugging-Status prüfen
            result.debuggingDetected = isDebuggingEnabled();
            
            // Emulator-Erkennung
            result.emulatorDetected = isRunningOnEmulator();
            
            // Root-Erkennung
            result.rootDetected = isDeviceRooted();
            
            // Hook-Framework-Erkennung
            result.hooksDetected = areHooksDetected();
            
            // Xposed-Framework-Erkennung
            result.xposedDetected = isXposedActive();
            
            // Installer-Validierung
            result.installerValid = validateInstaller();
            
            // Zusammenfassung
            result.overallSecure = result.signatureValid && 
                                  !result.debuggingDetected && 
                                  !result.emulatorDetected && 
                                  !result.rootDetected && 
                                  !result.hooksDetected && 
                                  !result.xposedDetected;
            
            Log.i(TAG, "Sicherheitsprüfung abgeschlossen. Sicher: " + result.overallSecure);
            return result;
            
        } catch (Exception e) {
            Log.e(TAG, "Fehler bei Sicherheitsprüfung", e);
            result.error = e.getMessage();
            result.overallSecure = false;
            return result;
        }
    }
    
    private boolean validateAppSignature() {
        try {
            PackageManager pm = context.getPackageManager();
            PackageInfo packageInfo = pm.getPackageInfo(
                context.getPackageName(), 
                PackageManager.GET_SIGNATURES
            );
            
            for (Signature signature : packageInfo.signatures) {
                String currentSigHash = sha256Hash(signature.toByteArray());
                if (EXPECTED_SIGNATURE_HASH.equals(currentSigHash)) {
                    Log.d(TAG, "App-Signatur gültig");
                    return true;
                }
            }
            
            Log.w(TAG, "App-Signatur ungültig oder verändert");
            return false;
            
        } catch (Exception e) {
            Log.e(TAG, "Fehler bei Signaturprüfung", e);
            return false;
        }
    }
    
    private boolean isDebuggingEnabled() {
        // Build-Flag prüfen
        boolean buildDebuggable = (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        
        // Runtime-Debugger prüfen
        boolean runtimeDebugger = Debug.isDebuggerConnected();
        
        // Entwicklermodus prüfen
        boolean developerMode = android.provider.Settings.Global.getInt(
            context.getContentResolver(),
            android.provider.Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
        ) != 0;
        
        boolean debugging = buildDebuggable || runtimeDebugger || developerMode;
        if (debugging) {
            Log.w(TAG, "Debugging erkannt - Build: " + buildDebuggable + 
                      ", Runtime: " + runtimeDebugger + ", DevMode: " + developerMode);
        }
        
        return debugging;
    }
    
    private boolean isRunningOnEmulator() {
        // Build-Properties prüfen
        boolean buildIndicators = Build.FINGERPRINT.contains("generic") ||
                                 Build.FINGERPRINT.contains("unknown") ||
                                 Build.MODEL.contains("google_sdk") ||
                                 Build.MODEL.contains("Emulator") ||
                                 Build.MODEL.contains("Android SDK") ||
                                 Build.MANUFACTURER.contains("Genymotion") ||
                                 Build.HARDWARE.contains("goldfish") ||
                                 Build.HARDWARE.contains("ranchu") ||
                                 Build.PRODUCT.contains("sdk") ||
                                 Build.PRODUCT.contains("google_sdk") ||
                                 Build.PRODUCT.contains("sdk_google") ||
                                 Build.PRODUCT.contains("sdk_gphone") ||
                                 Build.BOARD.contains("goldfish") ||
                                 Build.BOARD.contains("ranchu");
        
        // Emulator-Dateien prüfen
        boolean filesDetected = false;
        for (String file : EMULATOR_FILES) {
            if (new File(file).exists()) {
                filesDetected = true;
                break;
            }
        }
        
        boolean emulator = buildIndicators || filesDetected;
        if (emulator) {
            Log.w(TAG, "Emulator erkannt");
        }
        
        return emulator;
    }
    
    private boolean isDeviceRooted() {
        try {
            // Verwende RootBeer-Library für umfassende Root-Erkennung
            boolean rootBeerDetection = rootBeer.isRooted();
            
            // Zusätzliche manuelle Prüfungen
            boolean manualDetection = checkRootFiles() || checkRootPackages() || checkSuCommand();
            
            boolean rooted = rootBeerDetection || manualDetection;
            if (rooted) {
                Log.w(TAG, "Root-Zugriff erkannt");
            }
            
            return rooted;
            
        } catch (Exception e) {
            Log.e(TAG, "Fehler bei Root-Erkennung", e);
            return true; // Im Zweifel als unsicher betrachten
        }
    }
    
    private boolean checkRootFiles() {
        for (String path : ROOT_PATHS) {
            if (new File(path).exists()) {
                Log.w(TAG, "Root-Datei gefunden: " + path);
                return true;
            }
        }
        return false;
    }
    
    private boolean checkRootPackages() {
        PackageManager pm = context.getPackageManager();
        for (String packageName : HOOK_PACKAGES) {
            try {
                pm.getPackageInfo(packageName, 0);
                Log.w(TAG, "Root/Hook-Paket gefunden: " + packageName);
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // Paket nicht gefunden - gut
            }
        }
        return false;
    }
    
    private boolean checkSuCommand() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"which", "su"});
            int exitCode = process.waitFor();
            if (exitCode == 0) {
                Log.w(TAG, "su-Befehl verfügbar");
                return true;
            }
        } catch (Exception e) {
            // Exception ist hier gut - su nicht verfügbar
        }
        return false;
    }
    
    private boolean areHooksDetected() {
        try {
            // Stack-Trace auf Hook-Frameworks prüfen
            throw new Exception("Stack trace check");
        } catch (Exception e) {
            for (StackTraceElement element : e.getStackTrace()) {
                String className = element.getClassName().toLowerCase();
                if (className.contains("xposed") || 
                    className.contains("substrate") || 
                    className.contains("cydia")) {
                    Log.w(TAG, "Hook-Framework im Stack erkannt: " + className);
                    return true;
                }
            }
        }
        return false;
    }
    
    private boolean isXposedActive() {
        try {
            // Prüfe auf Xposed-spezifische Umgebungsvariablen
            String classpath = System.getProperty("java.class.path");
            if (classpath != null && classpath.contains("XposedBridge")) {
                Log.w(TAG, "Xposed im Classpath erkannt");
                return true;
            }
            
            // Prüfe auf Xposed-Methoden
            try {
                Class.forName("de.robv.android.xposed.XposedHelpers");
                Log.w(TAG, "Xposed-Klassen verfügbar");
                return true;
            } catch (ClassNotFoundException e) {
                // Gut - Xposed nicht gefunden
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Fehler bei Xposed-Erkennung", e);
        }
        return false;
    }
    
    private boolean validateInstaller() {
        try {
            String installer = context.getPackageManager().getInstallerPackageName(context.getPackageName());
            
            // Akzeptierte Installer
            List<String> validInstallers = Arrays.asList(
                "com.android.vending",  // Google Play Store
                "com.amazon.venezia",   // Amazon App Store
                "com.sec.android.app.samsungapps", // Samsung Galaxy Store
                null  // Sideload (für Entwicklung)
            );
            
            boolean valid = validInstallers.contains(installer);
            if (!valid) {
                Log.w(TAG, "Unbekannter Installer: " + installer);
            }
            
            return valid;
            
        } catch (Exception e) {
            Log.e(TAG, "Fehler bei Installer-Validierung", e);
            return false;
        }
    }
    
    private String sha256Hash(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            Log.e(TAG, "Fehler bei SHA-256-Hash", e);
            return "";
        }
    }
    
    /**
     * Ergebnis der Sicherheitsprüfung
     */
    public static class SecurityCheckResult {
        public boolean signatureValid = false;
        public boolean debuggingDetected = false;
        public boolean emulatorDetected = false;
        public boolean rootDetected = false;
        public boolean hooksDetected = false;
        public boolean xposedDetected = false;
        public boolean installerValid = false;
        public boolean overallSecure = false;
        public String error = null;
        
        @Override
        public String toString() {
            return "SecurityCheckResult{" +
                   "signatureValid=" + signatureValid +
                   ", debuggingDetected=" + debuggingDetected +
                   ", emulatorDetected=" + emulatorDetected +
                   ", rootDetected=" + rootDetected +
                   ", hooksDetected=" + hooksDetected +
                   ", xposedDetected=" + xposedDetected +
                   ", installerValid=" + installerValid +
                   ", overallSecure=" + overallSecure +
                   ", error='" + error + '\'' +
                   '}';
        }
    }
}
