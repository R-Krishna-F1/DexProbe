"""
config.py — Central configuration for APK Security Intelligence Platform
All API keys, constants, and tunable settings live here.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ── API Keys ──────────────────────────────────────────────────────────────────
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
NVD_API_KEY    = os.getenv("NVD_API_KEY", "")   # Optional — raises rate limit from 5 to 50 req/30s

# ── Gemini Settings ───────────────────────────────────────────────────────────
GEMINI_MODEL          = "gemini-2.5-flash-preview-04-17"
GEMINI_MAX_RETRIES    = 3
GEMINI_RETRY_DELAY    = 5       # seconds between retries
GEMINI_RPM_LIMIT      = 10      # requests per minute to stay within free tier

# ── NVD API Settings ──────────────────────────────────────────────────────────
NVD_BASE_URL          = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT_DELAY  = 6       # seconds between requests without API key (5 req/30s)
NVD_RATE_LIMIT_KEYED  = 0.6     # seconds between requests with API key
NVD_MAX_RETRIES       = 3

# ── Cache Settings ────────────────────────────────────────────────────────────
CACHE_DIR             = os.path.join(os.path.dirname(__file__), "cache")
CVE_CACHE_FILE        = os.path.join(CACHE_DIR, "cve_cache.json")

# ── Temp Directory ────────────────────────────────────────────────────────────
TEMP_DIR              = os.path.join(os.path.dirname(__file__), "temp")

# ── Tool Metadata ─────────────────────────────────────────────────────────────
TOOL_NAME             = "APK Intel"
TOOL_VERSION          = "0.1.0"

# ── Severity Levels ───────────────────────────────────────────────────────────
SEVERITY_CRITICAL     = "CRITICAL"
SEVERITY_HIGH         = "HIGH"
SEVERITY_MEDIUM       = "MEDIUM"
SEVERITY_LOW          = "LOW"
SEVERITY_INFO         = "INFO"

SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 4,
    SEVERITY_HIGH:     3,
    SEVERITY_MEDIUM:   2,
    SEVERITY_LOW:      1,
    SEVERITY_INFO:     0,
}

# ── High-Risk Android Permissions ─────────────────────────────────────────────
HIGH_RISK_PERMISSIONS = [
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
]

# ── Suspicious TLDs ───────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw"]

# ── Known Library Package Prefixes ────────────────────────────────────────────
LIBRARY_PACKAGE_MAP = {
    "com.squareup.okhttp3":       "okhttp",
    "com.squareup.okhttp":        "okhttp",
    "com.squareup.retrofit2":     "retrofit",
    "com.google.gson":            "gson",
    "com.google.firebase":        "firebase",
    "com.google.android.gms":     "play-services",
    "io.realm":                   "realm",
    "com.facebook.android":       "facebook-android-sdk",
    "com.amplitude":              "amplitude-android",
    "com.mixpanel.android":       "mixpanel-android",
    "com.jakewharton.timber":     "timber",
    "io.sentry":                  "sentry-android",
    "com.airbnb.android":         "lottie",
    "com.github.bumptech.glide":  "glide",
    "com.squareup.picasso":       "picasso",
    "io.coil-kt":                 "coil",
    "org.bouncycastle":           "bouncycastle",
    "net.sqlcipher":              "sqlcipher-android",
    "com.appsflyer":              "appsflyer-android-sdk",
    "com.adjust.sdk":             "adjust",
    "com.onesignal":              "onesignal-android-sdk",
    "io.grpc":                    "grpc-java",
    "com.google.protobuf":        "protobuf-java",
    "org.jetbrains.kotlin":       "kotlin-stdlib",
    "androidx.room":              "room",
    "androidx.work":              "work-runtime",
    "org.apache.commons":         "commons-lang",
    "com.fasterxml.jackson":      "jackson-databind",
    "io.reactivex":               "rxjava",
}
