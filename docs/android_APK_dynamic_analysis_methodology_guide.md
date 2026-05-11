# Android APK Dynamic Analysis Methodology Guide

## Context

This guide is a companion to the static analysis pentest previously performed on the **Malaysia Truly Asia (MOTAC)** application (`my.com.itmax.motac`). The static analysis identified 3 Critical, 8 High, 7 Medium, and 6+ Low findings across 248 checklist items and 28 categories. Dynamic analysis is the next step to validate those findings at runtime and uncover issues that only manifest when the application is running.

---

## 1. Lab Environment Setup

### 1.1 Emulator Options

| Option | Pros | Cons |
|--------|------|------|
| Genymotion | Fast, root by default, good ARM translation | Paid for commercial use |
| Android Studio AVD | Free, official Google images | Slower, harder to root |
| Corellium | Cloud-based, jailbroken by default, ARM-native | Expensive |
| Physical Device (rooted) | Most realistic, full hardware access | Requires actual device + rooting |

**Recommended:** Genymotion with a Google Pixel image (Android 11–13) or a rooted physical device running Magisk.

### 1.2 Required Tools

**On the analysis workstation:**

- Burp Suite Professional (or OWASP ZAP) — HTTP/S traffic interception
- Frida (latest) — Runtime instrumentation framework
- Objection — Frida-powered mobile exploration toolkit
- jadx / apktool — For reference during dynamic testing
- adb (Android Debug Bridge) — Device communication
- Wireshark — Low-level packet capture
- mitmproxy — Alternative/supplementary proxy

**On the device/emulator:**

- Frida server (matching your Frida version)
- Magisk (if physical device) — Root and MagiskTrustUserCerts module
- Proxydroid or manual proxy settings
- Certificate installed as system-level CA

### 1.3 Network Configuration

```
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│   Android    │──────▶│  Burp Suite  │──────▶│   Internet   │
│   Device     │ proxy │  (Listener)  │       │   / Backend  │
│  10.0.2.15   │       │ 192.168.x.x  │       │              │
└──────────────┘       │   :8080      │       └──────────────┘
                       └──────────────┘
```

**Steps:**
1. Configure the device/emulator Wi-Fi proxy to point at your Burp listener IP and port.
2. Export Burp's CA certificate, push it to the device, and install it as a trusted CA.
3. For Android 7+, you will also need to patch the APK's `network_security_config.xml` or install the cert at the system level (Magisk module or emulator writable system).

---

## 2. Dynamic Analysis Phases

### Phase 1: Runtime Reconnaissance

**Objective:** Understand the app's behavior, network calls, and data storage at runtime.

#### 2.1 Install and Launch

```bash
# Install the APK
adb install Malaysia_Truly_Asia.apk

# Launch the app
adb shell am start -n my.com.itmax.motac/.MainActivity

# Monitor logs in real-time
adb logcat | grep -i "motac\|firebase\|api\|token\|error\|exception"
```

#### 2.2 Logcat Analysis

Watch for:
- Hardcoded API keys or tokens printed to logs
- Firebase authentication tokens
- Stack traces revealing internal architecture
- Debug messages left in production builds
- PII (emails, phone numbers, user IDs) in log output

```bash
# Save full logcat during testing session
adb logcat -v threadtime > logcat_motac_session.txt

# Filter for sensitive patterns
grep -iE "key|token|secret|password|auth|bearer|firebase|api_key" logcat_motac_session.txt
```

#### 2.3 Process and Memory Inspection

```bash
# List running processes
adb shell ps | grep motac

# Check open files and network sockets
adb shell run-as my.com.itmax.motac ls -la /data/data/my.com.itmax.motac/
```

---

### Phase 2: Network Traffic Analysis

**Objective:** Intercept, inspect, and manipulate all network communications.

#### 3.1 HTTP/S Traffic Interception (Burp Suite)

**What to look for:**

- API endpoints and their authentication mechanisms
- Bearer tokens, session cookies, API keys in headers
- Sensitive data transmitted in request/response bodies
- Missing security headers on API responses (HSTS, Content-Security-Policy, etc.)
- HTTP (non-HTTPS) endpoints
- Verbose error messages from the backend

**Key tests:**

| Test | Method |
|------|--------|
| Auth token reuse | Capture a token, close the app, replay it hours later |
| IDOR | Change user IDs / resource IDs in API calls |
| Privilege escalation | Use a low-privilege token on admin endpoints |
| Input validation | Send malformed/oversized data to API fields |
| Rate limiting | Replay login or OTP requests rapidly |
| Session fixation | Check if session tokens rotate after login |

#### 3.2 SSL/TLS Pinning Bypass

If the app implements certificate pinning, traffic interception will fail until you bypass it.

**Method 1 — Frida + Objection (recommended):**

```bash
# Start Frida server on device
adb shell "su -c '/data/local/tmp/frida-server &'"

# Launch with Objection
objection -g my.com.itmax.motac explore

# Inside Objection
android sslpinning disable
```

**Method 2 — Frida script (manual):**

```javascript
// ssl_pinning_bypass.js
Java.perform(function () {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain,
        host, clientAuth, ocspData, tlsSctData) {
        console.log('[+] SSL Pinning Bypassed for: ' + host);
        return untrustedChain;
    };
});
```

```bash
frida -U -f my.com.itmax.motac -l ssl_pinning_bypass.js --no-pause
```

**Method 3 — Patch the APK:**
1. Decompile with apktool
2. Edit `res/xml/network_security_config.xml` to trust user CAs
3. Rebuild and re-sign the APK

#### 3.3 Firebase-Specific Testing

Since the static analysis found a **Firebase Admin SDK private key** exposed in assets, validate:

```bash
# Check if the Firebase key is actually functional
# Test Firebase Realtime Database access
curl https://<project-id>.firebaseio.com/.json?auth=<leaked-token>

# Test Firestore access
# Test Cloud Storage bucket listing
# Test Firebase Auth admin operations (list users, create users)
```

**This is critical** — if the key works, an attacker can read/write the entire Firebase backend, access all user data, and potentially pivot to other GCP resources.

---

### Phase 3: Runtime Instrumentation with Frida

**Objective:** Hook into the app's functions to observe and modify behavior at runtime.

#### 4.1 Common Frida Hooks

**Hooking Crypto Operations:**

```javascript
Java.perform(function () {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function (input) {
        console.log('[Cipher.doFinal] Input: ' + bytesToHex(input));
        var result = this.doFinal(input);
        console.log('[Cipher.doFinal] Output: ' + bytesToHex(result));
        return result;
    };
});
```

**Hooking SharedPreferences (local storage):**

```javascript
Java.perform(function () {
    var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    SharedPreferencesImpl.putString.implementation = function (key, value) {
        console.log('[SharedPrefs] PUT ' + key + ' = ' + value);
        return this.putString(key, value);
    };
});
```

**Hooking Network Requests (OkHttp):**

```javascript
Java.perform(function () {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Interceptor = Java.use('okhttp3.Interceptor');

    console.log('[+] Hooking OkHttp requests...');

    var RequestBuilder = Java.use('okhttp3.Request$Builder');
    RequestBuilder.build.implementation = function () {
        var request = this.build();
        console.log('[OkHttp] ' + request.method() + ' ' + request.url().toString());
        var headers = request.headers();
        for (var i = 0; i < headers.size(); i++) {
            console.log('  Header: ' + headers.name(i) + ': ' + headers.value(i));
        }
        return request;
    };
});
```

**Hooking Root Detection (bypass):**

```javascript
Java.perform(function () {
    // Common root detection classes
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function () {
        console.log('[+] Root detection bypassed');
        return false;
    };
});
```

#### 4.2 Objection Quick Reference

```bash
# Environment exploration
objection -g my.com.itmax.motac explore

# Inside Objection shell:
env                                    # App directories and paths
android hooking list activities        # List all activities
android hooking list services          # List all services
android hooking list receivers         # List broadcast receivers

# Data storage
android keystore list                  # Keystore entries
android clipboard monitor             # Monitor clipboard

# Bypass protections
android sslpinning disable            # Bypass SSL pinning
android root disable                  # Bypass root detection

# Hook classes
android hooking watch class <classname> --dump-args --dump-return
```

---

### Phase 4: Local Data Storage Analysis

**Objective:** Check what sensitive data the app stores on the device and how it's protected.

#### 5.1 Filesystem Inspection

```bash
# Access app's private directory
adb shell run-as my.com.itmax.motac

# Or with root
adb shell su -c "ls -laR /data/data/my.com.itmax.motac/"
```

**Check these locations:**

| Location | What to look for |
|----------|-----------------|
| `shared_prefs/` | Auth tokens, user data, API keys in XML files |
| `databases/` | SQLite DBs with user data, credentials, cached responses |
| `cache/` | Cached API responses, images with metadata |
| `files/` | Downloaded content, configuration files |
| `app_webview/` | WebView cookies, local storage, cached pages |
| External storage | Any files written to SD card (world-readable) |

#### 5.2 Database Extraction and Analysis

```bash
# Pull SQLite databases
adb shell su -c "cp /data/data/my.com.itmax.motac/databases/*.db /sdcard/"
adb pull /sdcard/*.db ./

# Analyze with sqlite3
sqlite3 app_database.db
.tables
.schema
SELECT * FROM users;
SELECT * FROM tokens;
```

#### 5.3 Shared Preferences Review

```bash
# Pull and read SharedPreferences XML files
adb shell su -c "cat /data/data/my.com.itmax.motac/shared_prefs/*.xml"
```

Look for tokens, passwords, PII, or encryption keys stored in plaintext.

---

### Phase 5: Component Testing

**Objective:** Test exported Activities, Services, Broadcast Receivers, and Content Providers.

#### 6.1 Activity Testing

```bash
# Launch exported activities directly
adb shell am start -n my.com.itmax.motac/.admin.AdminPanelActivity
adb shell am start -n my.com.itmax.motac/.debug.DebugActivity

# Launch with intent extras
adb shell am start -n my.com.itmax.motac/.DeepLinkActivity \
    -d "motac://admin?role=superuser"
```

#### 6.2 Content Provider Testing

```bash
# Query exported content providers
adb shell content query --uri content://my.com.itmax.motac.provider/users
adb shell content query --uri content://my.com.itmax.motac.provider/data

# Test for SQL injection in content providers
adb shell content query --uri "content://my.com.itmax.motac.provider/users" \
    --where "1=1) OR 1=1--"
```

#### 6.3 Broadcast Receiver Testing

```bash
# Send broadcasts to exported receivers
adb shell am broadcast -a my.com.itmax.motac.ACTION_UPDATE \
    --es "command" "dump_data"
```

#### 6.4 Deep Link / Intent URI Testing

```bash
# Test deep links for authentication bypass
adb shell am start -W -a android.intent.action.VIEW \
    -d "motac://profile/other_user_id" my.com.itmax.motac

# Test for intent redirection
adb shell am start -a android.intent.action.VIEW \
    -d "https://malicious.site" my.com.itmax.motac
```

---

### Phase 6: WebView Security Testing

**Objective:** If the app uses WebViews, test for JavaScript injection and data leakage.

#### 6.1 WebView Configuration Check

Hook with Frida to inspect WebView settings:

```javascript
Java.perform(function () {
    var WebView = Java.use('android.webkit.WebView');
    WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
        console.log('[WebView] Loading: ' + url);
        var settings = this.getSettings();
        console.log('  JavaScript: ' + settings.getJavaScriptEnabled());
        console.log('  File Access: ' + settings.getAllowFileAccess());
        console.log('  Universal File Access: ' + settings.getAllowUniversalAccessFromFileURLs());
        this.loadUrl(url);
    };
});
```

#### 6.2 JavaScript Bridge Exploitation

If `addJavascriptInterface` is used, test for exposed methods that could leak data or perform privileged operations.

---

## 3. Validating Static Analysis Findings

Map each static finding to a dynamic test:

| Static Finding | Dynamic Validation |
|----------------|-------------------|
| Firebase Admin SDK key in assets | Attempt to authenticate with the key against Firebase APIs |
| Hardcoded API keys | Use the keys in API calls; check scope and permissions |
| Insecure network config | Verify if HTTP is used at runtime; test pinning |
| Weak cryptography | Hook crypto classes with Frida; verify algorithms and key sizes |
| Exported components | Launch each component via adb; test for auth bypass |
| Insecure data storage | Inspect filesystem after app usage; check for plaintext secrets |
| Debug flags enabled | Check if `android:debuggable=true` allows debugger attachment |
| Missing root detection | Run on rooted device; observe app behavior |
| Clipboard data leakage | Copy sensitive fields; check clipboard contents |
| Logging sensitive data | Review logcat during authentication and data entry flows |

---

## 4. Reporting Template for Dynamic Findings

For each finding, document:

1. **Title** — e.g., "Bearer Token Persists After Logout"
2. **Severity** — Critical / High / Medium / Low / Informational
3. **OWASP MASTG Reference** — e.g., MSTG-AUTH-004
4. **Description** — What was found at runtime
5. **Steps to Reproduce** — Exact commands, Frida scripts, or Burp actions
6. **Evidence** — Screenshots, logcat output, Burp request/response, Frida console output
7. **Impact** — What an attacker can achieve
8. **Remediation** — Specific fix recommendation

---

## 5. Tool Installation Quick Reference

```bash
# Frida (on workstation)
pip install frida-tools

# Frida server (on device) — match versions
wget https://github.com/frida/frida/releases/download/X.X.X/frida-server-X.X.X-android-arm64.xz
unxz frida-server-*.xz
adb push frida-server-* /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c '/data/local/tmp/frida-server &'"

# Objection
pip install objection

# Verify connection
frida-ps -U    # Should list device processes
```

---

## 6. Checklist Summary

- [ ] Lab environment configured (emulator or rooted device)
- [ ] Burp Suite proxy configured and CA certificate installed
- [ ] Frida server running on device
- [ ] SSL pinning bypassed (if applicable)
- [ ] HTTP/S traffic captured and analyzed
- [ ] Firebase Admin SDK key validated against live backend
- [ ] API authentication and authorization tested (IDOR, privilege escalation)
- [ ] Local data storage inspected (SharedPrefs, SQLite, files)
- [ ] Exported components tested (Activities, Providers, Receivers)
- [ ] Deep links and intent URIs tested
- [ ] WebView security assessed
- [ ] Root detection and tamper detection bypass tested
- [ ] Crypto operations hooked and reviewed
- [ ] Logcat reviewed for sensitive data leakage
- [ ] Session management tested (logout, token expiry, rotation)
- [ ] All static findings validated dynamically
- [ ] Evidence collected and documented

---

*Generated by ThreatLens — Companion guide to MOTAC APK Static Analysis (Session: 31e09e5e-4a85-4d1a-9a67-e67bdba692f7)*
