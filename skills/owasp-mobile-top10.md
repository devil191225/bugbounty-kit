# OWASP Mobile Top 10 — 2024
> Source: https://owasp.org/www-project-mobile-top-10/ | RAG Knowledge Base | Full detail preserved
> Released: 2024 | Replaces: OWASP Mobile Top 10 2016

---

## Overview — What Changed from 2016 to 2024

| 2016 | 2024 |
|---|---|
| M1 — Improper Platform Usage | M1 — Improper Credential Usage |
| M2 — Insecure Data Storage | M2 — Inadequate Supply Chain Security |
| M3 — Insecure Communication | M3 — Insecure Authentication/Authorization |
| M4 — Insecure Authentication | M4 — Insufficient Input/Output Validation |
| M5 — Insufficient Cryptography | M5 — Insecure Communication |
| M6 — Insecure Authorization | M6 — Inadequate Privacy Controls |
| M7 — Client Code Quality | M7 — Insufficient Binary Protections |
| M8 — Code Tampering | M8 — Security Misconfiguration |
| M9 — Reverse Engineering | M9 — Insecure Data Storage |
| M10 — Extraneous Functionality | M10 — Insufficient Cryptography |

Key changes: Credential management and supply chain elevated; privacy controls added as distinct category; binary protections and misconfiguration clarified.

---

## M1:2024 — Improper Credential Usage

### Description
Misuse of credentials, hardcoded or improperly stored credentials in the mobile application, or insecure transmission of credentials.

### Vulnerability Patterns

**Hardcoded Credentials:**
```java
// Android — hardcoded API key in source
private static final String API_KEY = "sk-prod-AbCdEfGhIjKlMnOp1234";
private static final String DB_PASSWORD = "SuperSecret123!";

// iOS — hardcoded in Swift
let apiKey = "Bearer eyJhbGciOiJSUzI1NiJ9.hardcoded..."
let adminPassword = "admin123"
```

**API Keys in Mobile Bundle:**
```
# Extract from APK
apktool d app.apk
grep -r "api_key\|apikey\|secret\|password\|token" app/ --include="*.xml" --include="*.java"

# Strings extraction
strings app.apk | grep -i "key\|secret\|password\|token\|auth"

# dex2jar + JADX for decompiled Java
jadx -d output/ app.apk
grep -r "SECRET\|API_KEY\|password" output/
```

**Credentials in Shared Preferences (Android — insecure):**
```java
// Storing credentials in plain SharedPreferences
SharedPreferences prefs = getSharedPreferences("auth", MODE_PRIVATE);
prefs.edit().putString("password", userPassword).apply();
// Stored at: /data/data/com.app/shared_prefs/auth.xml
// Readable by root/ADB on rooted device
```

**Keychain Misuse (iOS):**
```swift
// Storing sensitive data WITHOUT kSecAttrAccessible
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "MyApp",
    kSecValueData as String: sensitiveData
    // Missing: kSecAttrAccessible — defaults to after first unlock
    // Should use: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
]
```

**Credential Transmission:**
```
# Credentials in URL parameters (logged by servers/proxies)
GET /api/login?username=user&password=Pass123

# Credentials in HTTP (not HTTPS)
POST http://api.app.com/auth {"password":"secret"}
```

### Testing Methodology
1. Decompile APK with JADX / apktool
2. Search for hardcoded strings: API keys, passwords, tokens
3. Check SharedPreferences / NSUserDefaults for credential storage
4. Inspect Keychain usage for proper access control attributes
5. Proxy traffic (Burp) — check credential transmission
6. Check for credentials in app bundle (check `assets/`, `res/raw/`, config files)

### Bug Bounty Severity: High–Critical

---

## M2:2024 — Inadequate Supply Chain Security

### Description
Vulnerabilities introduced through third-party libraries, SDKs, pre-built components, or through the build and distribution process.

### Vulnerability Patterns

**Vulnerable Third-Party Libraries:**
```
# Android — check build.gradle for outdated dependencies
implementation 'com.squareup.okhttp3:okhttp:3.12.0'  # outdated, CVEs present
implementation 'org.apache.httpcomponents:httpclient:4.3.6'  # ancient

# iOS — check Podfile.lock or Package.resolved
pod 'AFNetworking', '~> 2.0'  # old version with known SSL validation bypass

# Automated check
# Android: dependency-check-gradle plugin
# iOS: cocoapods-pod-linkage
```

**Malicious SDK:**
```
# SDK with hidden data collection behavior
# e.g., ad SDK exfiltrating contacts, location, clipboard contents
# Check: network traffic analysis with Burp/Charles

# Counterfeit SDK
# SDK hosted on attacker-controlled domain
# Check: SDK origin, integrity hash verification
```

**Build Process Tampering:**
```
# CI/CD pipeline compromise
# Attacker injects malicious code into build
# Evidence: check git history for unusual CI changes
# Check: code signing identity, reproducible builds
```

**APK Distribution Outside Store:**
```
# Side-loading from attacker-controlled site
# No Google Play Protect scan
# Check: if app allows Unknown Sources / side-loading
```

### Testing Approach
1. Extract APK and enumerate all included libraries (`META-INF/`)
2. Check library versions against CVE databases
3. Analyze network traffic for unexpected third-party communication
4. Check code for obfuscated/suspicious third-party SDK behaviors
5. Verify APK signature chain

### Bug Bounty Severity: Medium–High

---

## M3:2024 — Insecure Authentication/Authorization

### Description
Insufficient authentication controls (easily bypassed), or improper authorization allowing users to perform unauthorized actions or access unauthorized data.

### Authentication Vulnerabilities

**Weak Local Authentication:**
```
# Biometric bypass (Android)
# App uses onAuthenticationSucceeded but doesn't use CryptoObject
# → Attacker with USB access can inject fake authentication event

# Pattern/PIN bypass via ADB
adb shell input keyevent 82  # unlock
# App doesn't require re-auth after device unlock

# iOS TouchID/FaceID bypass
# App doesn't use LAContext with kSecAttrAccessControl
# Falls back to device passcode without app-level validation
```

**Client-Side Authorization:**
```java
// Authorization check done client-side only
if (user.getRole().equals("admin")) {
    showAdminMenu();
    // enableAdminAPI();  // WRONG: admin endpoints called without server-side check
}
// Attacker: intercept + modify response to set role="admin"
// Gain access to local admin UI — but more critically, server must also check
```

**Missing Session Management:**
```
# No session invalidation on app background
# Token doesn't expire
# No re-authentication for sensitive actions (transfer funds, change password)
# Multiple simultaneous sessions not detected
```

**Insecure Direct Object Reference in Mobile API:**
```
# API endpoint doesn't validate user owns the resource
GET /api/v1/accounts/1234/transactions  # user owns 1234
GET /api/v1/accounts/5678/transactions  # user doesn't own 5678 — but API returns data
```

### Testing Methodology
1. Intercept authentication flow with Burp Suite (configured in mobile proxy settings)
2. Test JWT/token manipulation
3. Check for client-side role/permission checks without server validation
4. Test biometric authentication bypass (Frida scripts for Android/iOS)
5. Test all API endpoints with another user's token
6. Test sensitive actions without re-authentication

### Bug Bounty Severity: High–Critical

---

## M4:2024 — Insufficient Input/Output Validation

### Description
Failure to properly validate, sanitize, or encode input and output data in mobile applications, leading to injection attacks, data corruption, or security control bypass.

### Vulnerability Patterns

**SQL Injection via Mobile API:**
```
# Mobile app sends user input directly to API which passes to DB
POST /api/v1/search
{"query": "'; DROP TABLE users;--"}

# Test: send SQLi payloads through the app's input fields
# Capture with Burp, modify, replay
```

**XSS in WebView:**
```javascript
// Android WebView with JavaScript enabled + loadUrl from user input
webView.getSettings().setJavaScriptEnabled(true);
String userInput = intent.getStringExtra("url");
webView.loadUrl(userInput);  // file:///sdcard/... or javascript: URI

// JavaScript interface exposed to WebView
@JavascriptInterface
public String getToken() { return sessionToken; }
// XSS in WebView → steal sessionToken via window.tokenBridge.getToken()
```

**Deep Link Injection:**
```
# Android deep link without input validation
# AndroidManifest.xml: intent-filter with scheme="myapp"
# myapp://login?redirect=javascript:alert(1)
# Or: myapp://login?redirect=file:///data/data/com.app/

adb shell am start -a android.intent.action.VIEW \
  -d "myapp://login?token=INJECTED&redirect=https://evil.com"
```

**Path Traversal in File Operations:**
```java
// Unvalidated filename from user/server
String filename = intent.getStringExtra("filename");
File f = new File(getFilesDir(), filename);  // ../../../etc/passwd
```

**Log Injection:**
```
# Sensitive data logged (accessible via ADB on debug builds)
Log.d("Auth", "Login attempt: user=" + username + " pass=" + password);

# Extract logs
adb logcat | grep -i "password\|token\|auth\|key"
```

### Testing Methodology
1. Proxy all traffic through Burp, test all parameters with injection payloads
2. Check WebView JavaScript interfaces (search source for `@JavascriptInterface`)
3. Test all deep links for parameter injection
4. Enable ADB logging and check for sensitive data leakage
5. Test file operations with path traversal payloads
6. Check Intent extras for injection in exported Activities

### Bug Bounty Severity: Medium–Critical

---

## M5:2024 — Insecure Communication

### Description
Mobile applications communicating over insecure channels, with improper certificate validation, or without proper transport layer security.

### Vulnerability Patterns

**Missing SSL Pinning:**
```
# Without certificate pinning, Burp/mitmproxy intercepts all traffic trivially
# Setup: 
# 1. Install Burp CA cert on device
# 2. Configure device proxy to Burp
# 3. Traffic intercepted

# Check if app implements pinning:
# Android: look for TrustManager, OkHttp CertificatePinner, network_security_config.xml
# iOS: look for URLSession delegate, TrustKit, Alamofire ServerTrustPolicy
```

**Weak TrustManager (Trust All Certs):**
```java
// INSECURE: accepts any certificate
TrustManager[] trustAllCerts = new TrustManager[]{
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[]{}; }
    }
};
// Effectively disables SSL validation entirely
```

**Hostname Verification Disabled:**
```java
// INSECURE
HttpsURLConnection.setDefaultHostnameVerifier(
    (hostname, session) -> true  // accepts any hostname
);
```

**HTTP Used for Sensitive Endpoints:**
```
# App uses HTTP for:
GET http://api.app.com/user/profile  ← sensitive data over HTTP
POST http://api.app.com/auth/login   ← credentials over HTTP
```

**Mixed Content in WebViews:**
```
# HTTPS page loading HTTP resources
webView.getSettings().setMixedContentMode(
    WebSettings.MIXED_CONTENT_ALWAYS_ALLOW  // insecure
);
```

**Certificate Pinning Bypass (Testing Technique):**
```
# Frida script to bypass OkHttp pinning
frida -U -l okhttp-pinning-bypass.js -f com.target.app

# Universal SSL bypass
frida -U -l ssl-pinning-bypass.js --no-pause -f com.target.app

# Objection (automation)
objection -g com.target.app explore
> android sslpinning disable
> ios sslpinning disable
```

### Testing Methodology
1. Configure device proxy → Burp
2. Attempt traffic interception without bypass (document if pinning is absent)
3. If pinning present, use Frida/Objection to bypass (for research context)
4. Check source for TrustManager implementation and hostname verifier
5. Check `network_security_config.xml` (Android) for cleartext allowed domains
6. Check iOS `NSAppTransportSecurity` exceptions in Info.plist

### Bug Bounty Severity: Medium–High (depends on what data is transmitted)

---

## M6:2024 — Inadequate Privacy Controls

### Description
Apps collecting, storing, or transmitting personal data without appropriate user consent, beyond what's necessary, or without adequate protection.

### Vulnerability Patterns

**Excessive Data Collection:**
```
# App requests permissions beyond what's needed
// AndroidManifest.xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
<uses-permission android:name="android.permission.READ_CALL_LOG"/>
// Flashlight app requesting contacts and call log = excessive

# Data sent to third-party analytics without consent
# Capture traffic: see contact hashes, device ID, IMEI sent to analytics SDK
```

**PII Leaked in Logs:**
```
# Android logcat — accessible without root on debug builds
D/Network: Response: {"user_id":123,"email":"user@example.com","ssn":"123-45-6789"}
D/Auth: Token refresh: Bearer eyJhbGciOiJ...

adb logcat | grep -E "(email|ssn|phone|address|token|password)"
```

**PII in URLs (Logged by Proxies/CDNs):**
```
GET /api/user?email=victim@example.com&phone=5551234567
# Server logs contain PII — regulatory issue (GDPR, CCPA)
```

**Screenshot Protection Missing:**
```java
// Should set FLAG_SECURE to prevent screenshots of sensitive screens
// Vulnerable: missing this flag on payment/account screens
getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);

// iOS equivalent: hide content in app switcher
override func viewWillResignActive(_ animated: Bool) {
    // Should show blur overlay here
}
```

**Clipboard Data Leakage:**
```
# App copies sensitive data to clipboard without clearing
// Paste password → clipboard readable by any app
// iOS 16+ shows clipboard access notification
# Check: passwords, card numbers, tokens copied to clipboard
```

### Testing Methodology
1. Analyze all network traffic for PII transmission
2. Check `adb logcat` output for sensitive data
3. Review permission requests vs. app functionality
4. Test clipboard behavior for sensitive fields
5. Check if sensitive screens have FLAG_SECURE (screenshot blocking)
6. Look for analytics SDK beaconing PII

### Bug Bounty Severity: Medium–High (regulatory implications = High)

---

## M7:2024 — Insufficient Binary Protections

### Description
Lack of obfuscation, anti-tamper, anti-debug, anti-emulator, or integrity checking mechanisms that allow attackers to reverse engineer, patch, or tamper with the app.

### Vulnerability Patterns

**No Code Obfuscation:**
```
# Android — no ProGuard/R8 obfuscation
# JADX decompiles to near-original Java with readable class/method names
# Reveals business logic, API endpoints, algorithm implementations

# iOS — no bitcode optimization, symbols not stripped
# IDA Pro / Ghidra shows full function names
nm -gU BinaryName | grep -v " U " | sort
```

**No Root/Jailbreak Detection:**
```java
// App doesn't check for root — allows dynamic analysis tools
// Frida, Xposed, Magisk work without any obstacle

// Check: does app detect and refuse to run on rooted device?
// Bypass: frida -U -l root-bypass.js -f com.app
```

**Debuggable in Production:**
```xml
<!-- AndroidManifest.xml — CRITICAL issue in prod builds -->
<application android:debuggable="true">

<!-- Allows:
adb jdwp  → list debuggable processes
adb forward tcp:1234 jdwp:PID
jdb -attach localhost:1234  → full debugger access
-->
```

**No Integrity Check:**
```
# App doesn't verify its own signature → can be repacked with malicious code
# No root-of-trust from server → any modified APK works

# Check signing certificate
apksigner verify --verbose --print-certs app.apk
# Repackaged apps will show different signing key
```

**Sensitive Logic in Client:**
```
# License check done client-side
if (hasLicenseKey(key)) { unlockPremiumFeatures(); }
# Patch: change conditional to always return true

# Pin verification on client
if (validatePin(entered, stored)) { authenticate(); }
# Shows pin validation algorithm — may reveal timing attack
```

### Testing Methodology
1. Decompile APK (JADX) — assess obfuscation level
2. Check `android:debuggable` flag in manifest
3. Run on rooted device — check if app detects and exits
4. Use Frida without bypass — check if app detects it
5. Look for business-critical logic implemented client-side
6. Check certificate pinning, root detection, integrity checks

### Bug Bounty Severity: Low–Medium (enables other attacks)

---

## M8:2024 — Security Misconfiguration

### Description
Insecure default configurations, incomplete or ad-hoc configurations, open cloud storage, misconfigured HTTP headers, unnecessary services or features enabled.

### Vulnerability Patterns

**Backup Enabled (Android):**
```xml
<!-- AndroidManifest.xml -->
<application android:allowBackup="true">
<!-- Allows: adb backup -f backup.ab com.target.app
     Extracts: databases, shared preferences, files
     adb backup creates backup.ab → unpack with:
     dd if=backup.ab bs=24 skip=1 | python -c "import zlib,sys;sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))" | tar xv
-->
```

**Exported Components Without Auth (Android):**
```xml
<!-- Activity exported without permission requirement -->
<activity android:name=".AdminActivity" android:exported="true">
<!-- Any app can start this activity:
     adb shell am start -n com.target.app/.AdminActivity
     → admin UI without authentication
-->

<!-- Content provider exported without read permission -->
<provider android:name=".UserProvider" 
          android:exported="true"
          android:readPermission="">
<!-- adb shell content query --uri content://com.target.app.provider/users -->
```

**Firebase/Cloud Storage Misconfiguration:**
```
# Firebase — no auth rules
GET https://target-app.firebaseio.com/.json
# Returns entire database if rules are: {"rules": {".read": true, ".write": true}}

# S3 bucket — public read
aws s3 ls s3://target-app-user-data/ --no-sign-request
# Lists all files without authentication

# GCS bucket
gsutil ls -r gs://target-app-backups/
```

**Debug Features in Production:**
```
# WebView with remote debugging enabled
WebView.setWebContentsDebuggingEnabled(true);
# Connect via chrome://inspect → full JavaScript console access to WebView

# StrictMode in production
StrictMode.setThreadPolicy(...)  # performance, not security, but indicates debug config
```

**Network Security Config (Android):**
```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
    <!-- Allows HTTP for all domains — insecure -->
    
    <domain-config>
        <domain>internal.target.com</domain>
        <trust-anchors>
            <certificates src="@raw/debug_cert"/>  <!-- trusting custom cert in prod -->
        </trust-anchors>
    </domain-config>
</network-security-config>
```

### Testing Methodology
1. Check manifest for `android:debuggable="true"`, `android:allowBackup="true"`
2. Enumerate exported components: `apktool d app.apk; grep "exported=\"true\"" AndroidManifest.xml`
3. Test exported activities/providers/receivers with ADB
4. Check Firebase database URL: `https://[app-id].firebaseio.com/.json`
5. Search for S3/GCS bucket names in APK strings, test public access
6. Check `network_security_config.xml` for cleartext permissions

### Bug Bounty Severity: Medium–Critical

---

## M9:2024 — Insecure Data Storage

### Description
Sensitive data stored insecurely on the device, accessible to other apps, adb, or physical device access.

### Vulnerability Patterns

**SQLite Database — Plaintext:**
```
# App stores sensitive data in SQLite without encryption
# Location: /data/data/com.app/databases/
adb shell
run-as com.target.app
cat databases/users.db | strings | grep -i "password\|token\|card"

# Extract DB
adb exec-out run-as com.target.app cat databases/app.db > app.db
sqlite3 app.db .dump
```

**SharedPreferences — Plaintext:**
```xml
<!-- /data/data/com.app/shared_prefs/auth_prefs.xml -->
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="session_token">eyJhbGciOiJSUzI1NiJ9....</string>
    <string name="user_password">MyP@ssw0rd!</string>
    <int name="user_id" value="12345" />
</map>
```

**External Storage (World-Readable):**
```java
// Writing to external storage — any app can read
File file = new File(Environment.getExternalStorageDirectory(), "user_data.json");
// /sdcard/user_data.json — readable without permissions on older Android
```

**iOS — Insecure File Storage:**
```swift
// Files in Documents directory — backed up to iCloud
let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
let tokenFile = documentsPath.appendingPathComponent("auth_token.txt")
try! token.write(to: tokenFile, atomically: true, encoding: .utf8)
// iCloud backup exposes auth tokens
// Should use: FileProtection.completeUnlessOpen + excluded from backup
```

**Keystore/Keychain Misuse:**
```kotlin
// Android Keystore without StrongBox or user authentication
val keyGenParameterSpec = KeyGenParameterSpec.Builder(
    "my_key",
    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
)
// Missing: .setUserAuthenticationRequired(true)
// Missing: .setIsStrongBoxBacked(true)
// Key extractable without user presence
```

**Log Files with Sensitive Data:**
```
# Crash logs / analytics logs contain sensitive data
/data/data/com.app/files/logs/app.log
# Contents: user IDs, tokens, request bodies with PII
```

### Testing Methodology
1. Root device or use run-as for debug apps → inspect all storage locations
2. Check SharedPreferences XML files
3. Dump SQLite databases, run `.dump` on each
4. Check external storage for app-created files
5. Use ADB backup to extract app data
6. iOS: use iMazing or iPhone Backup Extractor to examine backup data
7. Check iOS Keychain with Keychain Dumper (jailbroken)

### Bug Bounty Severity: High–Critical (PII storage = regulatory + High)

---

## M10:2024 — Insufficient Cryptography

### Description
Use of weak, broken, or improperly implemented cryptographic algorithms that can be defeated to expose sensitive data.

### Vulnerability Patterns

**Weak Algorithms:**
```java
// MD5 for password hashing (broken — no salt, fast to crack)
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes());

// SHA1 for sensitive hashing (deprecated)
MessageDigest sha = MessageDigest.getInstance("SHA-1");

// DES encryption (key too short, broken)
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
// ECB mode: identical plaintext blocks → identical ciphertext blocks (pattern leakage)

// ECB mode even with AES (penguin attack)
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
```

**Hardcoded Encryption Keys:**
```java
// Key hardcoded in source — easily extracted from APK
private static final String AES_KEY = "1234567890123456";
private static final byte[] IV = new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
// Attacker extracts APK, finds key, decrypts all encrypted data
```

**Insufficient Key Size:**
```
# RSA key size
RSA-1024: BROKEN (factorable with modern hardware)
RSA-2048: Minimum acceptable
RSA-4096: Recommended for long-lived keys

# AES key size
AES-128: Acceptable
AES-256: Recommended
```

**No Integrity Protection:**
```
# Data encrypted but not authenticated (no MAC)
# AES-CBC without HMAC → bit-flipping attack
# Should use: AES-GCM (authenticated encryption)
Cipher.getInstance("AES/GCM/NoPadding")  // correct
Cipher.getInstance("AES/CBC/PKCS5Padding")  // no integrity check
```

**Random Number Generation:**
```java
// Weak PRNG — predictable
Random rand = new Random();  // predictable from seed
// Should use: SecureRandom
SecureRandom rand = new SecureRandom();
```

### Testing Methodology
1. Search source/decompiled code for cryptographic algorithm names
2. Look for hardcoded keys, IVs, salts
3. Check algorithm choices (MD5, SHA1, DES, ECB mode = red flags)
4. Test if encrypted data has integrity protection
5. Check key derivation (PBKDF2 > bcrypt > scrypt; MD5(password) = fail)
6. Assess key storage (in source = fail, in Keystore = pass)

### Bug Bounty Severity: High (broken crypto often means data at risk)

---

## OWASP Mobile Top 10 — Quick Reference

| # | Category | Primary Issue | Testing Tool | Severity |
|---|---|---|---|---|
| M1 | Improper Credential Usage | Hardcoded keys, insecure storage | JADX, grep, Burp | Critical |
| M2 | Supply Chain Security | Vulnerable SDKs, malicious libraries | dependency-check, traffic analysis | Medium–High |
| M3 | Insecure Auth/Authorization | Biometric bypass, IDOR in API | Frida, Burp, ADB | High–Critical |
| M4 | Insufficient Input Validation | SQLi, XSS in WebView, deep link injection | Burp, ADB intent | Medium–Critical |
| M5 | Insecure Communication | Missing SSL pinning, trust-all certs | Burp, Objection | Medium–High |
| M6 | Inadequate Privacy Controls | PII in logs, excessive permissions | adb logcat, traffic analysis | Medium–High |
| M7 | Insufficient Binary Protections | No obfuscation, debuggable prod build | JADX, ADB, Frida | Low–Medium |
| M8 | Security Misconfiguration | Exported components, Firebase open | ADB, apktool | Medium–Critical |
| M9 | Insecure Data Storage | Plaintext SQLite, SharedPrefs | ADB, adb backup | High–Critical |
| M10 | Insufficient Cryptography | MD5 passwords, hardcoded keys | JADX, grep, hashcat | High |

---

## Mobile App Testing Toolchain

```bash
# Android APK Analysis
apktool d app.apk -o decompiled/          # decode resources + manifest
jadx -d jadx-output/ app.apk              # decompile to Java
dex2jar app.apk                           # convert dex to jar (for JD-GUI)

# Static Analysis
grep -r "password\|secret\|api_key\|token" jadx-output/ --include="*.java"
grep -r "http://" jadx-output/ --include="*.java"  # cleartext HTTP
grep -r "debuggable\|allowBackup" decompiled/AndroidManifest.xml

# Dynamic Analysis
adb logcat -c && adb logcat | grep -i "password\|token\|auth\|secret"
adb shell run-as com.target.app ls /data/data/com.target.app/
adb shell run-as com.target.app cat shared_prefs/*.xml

# Network Analysis
# Configure Android proxy → Burp
# Android 7+: install user CA cert (may need Magisk for system cert)

# Frida
frida -U -l ssl-bypass.js -f com.target.app --no-pause
frida -U -l root-detection-bypass.js com.target.app

# Objection
objection -g com.target.app explore
> android sslpinning disable
> android root disable
> android hooking list activities
> android intent launch_activity com.target.app.AdminActivity

# iOS
iproxy 2222 22          # USB SSH via Cydia
ssh -p 2222 root@localhost
cycript -p AppName      # dynamic patching
# Frida iOS
frida -U -l ios-ssl-bypass.js -f com.target.app
```

---

## Mobile Bug Bounty Focus Areas

### High-Value Targets
1. **API endpoint discovery** — mobile apps often have undocumented API versions
2. **Hardcoded secrets** — frequent in mobile bundles even at large companies
3. **IDOR via mobile API** — mobile often hits different backend with weaker checks
4. **Deep link injection** — exported activities/custom URL schemes
5. **Firebase misconfiguration** — open databases still common
6. **Exported components** — unprotected Activities with admin functionality

### Recon for Mobile
```
# Find APK
https://apkpure.com/
https://apkcombo.com/

# Find older APK versions (may have more vulns)
https://apkmirror.com/

# iOS IPA (requires jailbroken device or Apple Developer account)
Frida iOS dump: frida-ios-dump

# App store metadata
https://play.google.com/store/apps/details?id=com.target.app
# Review history, permissions, last update date
```
