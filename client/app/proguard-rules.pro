# AndroidRAT ProGuard Rules - Android 15 Optimiert
# Version 2.0 - September 2025

# ============================================================
# Grundlegende Android-Regeln
# ============================================================

# Android Support & AndroidX
-keep class androidx.** { *; }
-keep interface androidx.** { *; }
-dontwarn androidx.**

# Core Android Komponenten behalten
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.accessibilityservice.AccessibilityService
-keep public class * extends android.service.notification.NotificationListenerService
-keep public class * extends android.app.admin.DeviceAdminReceiver

# ============================================================
# AndroidRAT Spezifische Regeln (KRITISCH!)
# ============================================================

# Alle RAT-Komponenten behalten (keine Obfuskation für Debugging)
-keep class com.example.client.** { *; }
-keepclassmembers class com.example.client.** { *; }

# Reflection-verwendete Klassen schützen
-keepattributes Signature
-keepattributes *Annotation*
-keepattributes EnclosingMethod
-keepattributes InnerClasses

# Native Methods behalten
-keepclasseswithmembernames class * {
    native <methods>;
}

# ============================================================
# Kryptographie & Sicherheit
# ============================================================

# BouncyCastle Kryptographie behalten
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# AndroidX Security
-keep class androidx.security.crypto.** { *; }
-dontwarn androidx.security.crypto.**

# Javax Crypto
-keep class javax.crypto.** { *; }
-keep class javax.security.** { *; }

# ============================================================
# Netzwerk & Kommunikation
# ============================================================

# OkHttp3 & Retrofit
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }
-dontwarn okhttp3.**

-keep class retrofit2.** { *; }
-dontwarn retrofit2.**

# Gson (JSON Serialization)
-keep class com.google.gson.** { *; }
-keepclassmembers,allowobfuscation class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

# ============================================================
# Android 15 Spezifische Regeln
# ============================================================

# Edge-to-Edge UI Support
-keep class androidx.activity.** { *; }
-keep class androidx.core.view.** { *; }

# Foreground Service Types
-keep class android.app.Service { *; }
-keep class android.content.pm.ServiceInfo { *; }

# Scoped Storage
-keep class android.provider.MediaStore { *; }
-keep class androidx.core.content.FileProvider { *; }

# Camera2 API (für Surveillance)
-keep class androidx.camera.** { *; }
-dontwarn androidx.camera.**

# ============================================================
# Anti-Reverse-Engineering (Optional)
# ============================================================

# Source File Namen entfernen
-renamesourcefileattribute SourceFile

# Line Numbers für Stack Traces behalten (debugging)
-keepattributes SourceFile,LineNumberTable

# String-Verschleierung (optional, kann Probleme verursachen)
# -obfuscate

# ============================================================
# Logging entfernen (Release Build)
# ============================================================

# Android Log entfernen
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
}

# Timber Logging entfernen
-assumenosideeffects class timber.log.Timber {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
}

# ============================================================
# Optimization Flags
# ============================================================

# Optimierung aktivieren
-optimizations !code/simplification/arithmetic,!code/simplification/cast,!field/*,!class/merging/*

# Iterations für Optimierung
-optimizationpasses 5

# Attribute für Optimierung behalten
-keepattributes *Annotation*,Signature,Exception

# ============================================================
# Warnings unterdrücken
# ============================================================

-dontwarn javax.annotation.**
-dontwarn org.conscrypt.**
-dontwarn org.openjsse.**

# ============================================================
# ENDE DER PROGUARD RULES
# ============================================================

# Version: 2.0
# Android: 15 (API Level 35)
# Optimiert für: One UI 7
# Letzte Aktualisierung: September 2025