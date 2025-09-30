package com.example.client;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

public class ScreenCaptureService extends Service {
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Screen Capture-Initialisierung handhaben
        return START_NOT_STICKY;
    }
}
