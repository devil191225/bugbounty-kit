# SKILL: Mobile App Analysis (APK / IPA)
**Mobile apps often have weaker security than the web API. Same backend, worse client.**

---

## ANDROID APK ANALYSIS

### Setup
```bash
# Required tools
pip3 install apkleaks jadx-gui  # or brew install jadx
gem install apkid

# Pull APK from device (if you have the app installed)
adb shell pm list packages | grep {target}
adb shell pm path com.target.app
adb pull /data/app/com.target.app-1/base.apk target.apk

# Or download from APKPure/APKMirror for public apps
```

### Static Analysis
```bash
# Decompile APK
jadx -d output/ target.apk

# Search for hardcoded secrets
grep -r "api_key\|apikey\|secret\|password\|token\|Bearer\|private_key" output/ | grep -v ".class"

# Find all API endpoints
grep -r "http[s]\?://" output/ | grep -oP "https?://[^\"\s']+" | sort -u > endpoints.txt

# Find Firebase config (often leaks DB URL and API key)
grep -r "firebaseio\|firebase\|google-services" output/

# Find AWS config
grep -r "amazonaws\|AKIA\|aws_access" output/

# Deep secret scan
apkleaks -f target.apk -o apkleaks-output.json

# Check for exported activities (can be called without auth)
grep -r "exported.*true\|android:exported" output/AndroidManifest.xml
```

### Runtime Analysis
```bash
# Intercept HTTPS traffic with Burp
# 1. Set up Burp as proxy on same network
# 2. Install Burp cert on device
# 3. For apps with certificate pinning, use Frida to bypass:

# Frida certificate pinning bypass
frida --codeshare akabe1/frida-multiple-unpinning -f com.target.app -U

# General SSL kill
frida -U -f com.target.app -l scripts/ssl-kill-switch.js --no-pause

# Then route traffic through Burp normally
```

### Common Mobile Findings
```bash
# 1. Hardcoded API keys/credentials in APK
# 2. Insecure data storage (SharedPreferences, SQLite in /data/)
# 3. Exported activities/providers without permissions
# 4. Insecure deeplink handling (redirect, XSS via deeplink)
# 5. Weak/no certificate pinning (already have web findings? this amplifies them)
# 6. Debug mode enabled in production build
# 7. API keys different (and weaker) than web — different attack surface

# Check shared preferences (on rooted device)
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml

# Check SQLite databases
adb shell run-as com.target.app find /data/data/com.target.app -name "*.db"
adb shell run-as com.target.app sqlite3 /data/data/com.target.app/databases/app.db .dump
```

---

## iOS IPA ANALYSIS

### Static Analysis
```bash
# Install tools
pip3 install ipa-analyzer
brew install class-dump

# Extract IPA
unzip target.ipa -d target-ipa/
cd target-ipa/Payload/TargetApp.app/

# Strings analysis
strings TargetApp | grep -iE "api[_\s]?key|secret|password|token|Bearer|http"

# Binary analysis with class-dump
class-dump TargetApp > classes.h
grep -i "api\|auth\|secret\|key\|token\|network" classes.h

# Check Info.plist for interesting data
cat Info.plist | grep -iA2 "url\|key\|secret\|api\|scheme"
```

### iOS Certificate Pinning Bypass
```bash
# Using Frida (jailbroken device)
frida -U -f com.target.app -l ssl-kill-switch2.js

# Or objection framework (easiest)
objection -g com.target.app explore
# Then in objection shell:
ios sslpinning disable
```

---

## API MAPPING FROM MOBILE APPS

The mobile app often calls APIs that the web app doesn't expose.
After getting traffic through Burp:

```bash
# Export all unique API calls from Burp history
# Then analyze for:
# 1. Endpoints not in the web app's JS
# 2. Parameters not visible in web UI
# 3. Debug/internal endpoints (?debug=true, /internal/, /v0/)
# 4. Different auth flows (device tokens, refresh tokens)
# 5. Batch endpoints that allow mass operations
```
