# Mitigation Techniques - Defensive Strategies

## Overview

This document outlines comprehensive mitigation strategies for defending against Android persistence attacks. Mitigations are categorized by implementation approach and effectiveness.

## 1. Detection-Based Mitigations

### 1.1 Static Analysis - Manifest Scanning

**Objective**: Identify suspicious component declarations

**Implementation**:
```bash
# Scan for BOOT_COMPLETED receivers
grep -r "BOOT_COMPLETED" AndroidManifest.xml

# Identify exported services
grep -A2 "service" AndroidManifest.xml | grep "exported=\"true\""

# Find suspicious permissions
grep "RECEIVE_BOOT_COMPLETED\|RESTART_PACKAGES" AndroidManifest.xml
```

**Tools**:
- APKTool (decompile APK)
- AXMLPrinter2 (XML parsing)
- Androguard (automated analysis)

**Effectiveness**: 70% (misses runtime modifications)

### 1.2 Dynamic Analysis - Runtime Monitoring

**Objective**: Detect suspicious runtime behavior

**Implementation Method**:
```java
// Monitor service starts
public class ServiceMonitor {
    public void monitorServiceExecution(String serviceName) {
        // Log when service starts
        logEvent("SERVICE_START", serviceName);
        
        // Monitor execution time
        long startTime = System.currentTimeMillis();
        // ... service execution ...
        long duration = System.currentTimeMillis() - startTime;
        
        if (duration > EXPECTED_DURATION) {
            logAnomaly("ABNORMAL_SERVICE_DURATION", serviceName);
        }
    }
}
```

**Signature-Based Detection**:
- Long-running background services
- Receiver invocation frequency anomalies
- Unexpected process creation patterns
- Memory leak indicators

**Effectiveness**: 65-85% (depends on monitoring comprehensiveness)

### 1.3 Behavioral Analysis

**Metrics Monitored**:
1. **CPU Usage**: Sustained high usage suspicious
2. **Battery Drain**: Unexpected power consumption
3. **Network Activity**: Unusual data transmission patterns
4. **Memory Growth**: Memory leaks indicating active persistence
5. **Wakelock Patterns**: Excessive wake lock acquisitions

**Threshold Example**:
```
- Normal app: 5-15% CPU usage (periodic)
- Suspicious: >40% sustained CPU usage
- Alerts: Multiple wakelock acquisitions per minute
```

## 2. Prevention-Based Mitigations

### 2.1 Explicit Intent Enforcement

**Best Practice**: Always use explicit intents for component targeting

**Pattern**:
```java
// WRONG - Implicit intent
Intent intent = new Intent("com.example.ACTION");
startActivity(intent);

// CORRECT - Explicit intent
Intent intent = new Intent(this, TargetActivity.class);
startActivity(intent);
```

**Implementation in Application Class**:
```java
public class SecurityAwareApp extends Application {
    @Override
    public void startActivity(Intent intent) {
        if (intent.getComponent() == null) {
            // Force explicit intent
            throw new IllegalArgumentException("Must use explicit intents");
        }
        super.startActivity(intent);
    }
}
```

**Effectiveness**: 95% (eliminates implicit intent hijacking)

### 2.2 Permission-Based Access Control

**Manifest Declaration**:
```xml
<!-- Define custom permission -->
<permission android:name="com.example.INTERNAL_SERVICE"
    android:protectionLevel="signature"/>

<!-- Apply to service -->
<service android:name=".InternalService"
    android:permission="com.example.INTERNAL_SERVICE">
</service>
```

**Signature-level Protection**:
```xml
<!-- Ensures only apps signed with same certificate access -->
<permission android:name="com.example.SECURE_ACTION"
    android:protectionLevel="signatureOrSystem"/>
```

**Effectiveness**: 85% (requires careful implementation)

### 2.3 Disable Auto-Start Where Unnecessary

**Implementation**:
```xml
<!-- Disable auto-start receiver -->
<receiver android:name=".AutoStartReceiver"
    android:enabled="false">  <!-- Start disabled -->
    <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
    </intent-filter>
</receiver>
```

**Runtime Toggle**:
```java
PackageManager pm = context.getPackageManager();
pm.setComponentEnabledSetting(
    new ComponentName(this, AutoStartReceiver.class),
    PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
    PackageManager.DONT_KILL_APP
);
```

**Effectiveness**: 90% (eliminates unnecessary persistence)

## 3. Hardening Strategies

### 3.1 Service Lifecycle Management

**Proper Implementation**:
```java
public class WellBehavedService extends Service {
    
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Perform work
        doWork();
        
        // Stop immediately after work (don't use START_STICKY)
        stopSelf(startId);
        
        // Return NOT_STICKY to prevent restart
        return START_NOT_STICKY;
    }
    
    @Override
    public void onDestroy() {
        super.onDestroy();
        // Clean up resources immediately
        cleanup();
    }
}
```

**Work Manager Alternative** (Recommended):
```java
// Much better approach for scheduled work
PeriodicWorkRequest backupRequest = 
    new PeriodicWorkRequest.Builder(
        BackupWorker.class,
        15,  // Minimum 15 minutes
        TimeUnit.MINUTES
    )
    .addTag("backup")
    .build();

WorkManager.getInstance(context)
    .enqueueUniquePeriodicWork(
        "backup_work",
        ExistingPeriodicWorkPolicy.KEEP,
        backupRequest
    );
```

**Effectiveness**: 85% (system-enforced constraints)

### 3.2 SELinux Policy Enforcement

**Enable Strict Enforcement**:
```bash
# Check current SELinux mode
getenforce

# Enable enforcing mode (persistent)
setenforce 1

# Set to enforcing in /etc/selinux/config
SELINUX=enforcing
```

**Policy for App Isolation**:
```
# Deny native code from accessing kernel directly
neverallow app_native_t kernel_t:capability sys_ptrace;

# Deny memory manipulation
neverallow app_native_t device_t:chr_file write;

# Restrict file access to app directories only
allow app_native_t app_data_t:file { read write };
```

**Effectiveness**: 90% (kernel-level enforcement)

### 3.3 Address Space Layout Randomization (ASLR)

**Verification**:
```bash
# Check ASLR status (should be 2 for full ASLR)
cat /proc/sys/kernel/randomize_va_space
# Output: 2 = Full ASLR enabled

# Enable if needed
echo 2 > /proc/sys/kernel/randomize_va_space
```

**Impact**: Prevents memory-based exploits and injection

**Effectiveness**: 85% (makes memory-based attacks unreliable)

### 3.4 Code Integrity Verification

**Implementation**:
```java
public class IntegrityChecker {
    
    public static boolean verifyAPKSignature(Context context) {
        try {
            PackageInfo packageInfo = context.getPackageManager()
                .getPackageInfo(context.getPackageName(), 
                    PackageManager.GET_SIGNATURES);
            
            for (Signature signature : packageInfo.signatures) {
                byte[] signatureBytes = signature.toByteArray();
                
                // Compare with expected signature
                String sha256 = calculateSHA256(signatureBytes);
                return sha256.equals(EXPECTED_SIGNATURE_SHA256);
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }
    
    private static String calculateSHA256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }
}
```

**Effectiveness**: 75% (detects tampering, not always preventive)

## 4. Monitoring and Response Strategies

### 4.1 Anomaly Detection System

**Metrics Tracked**:
```java
public class AnomalyDetector {
    private static final int BOOT_RECEIVER_INVOCATION_THRESHOLD = 5;
    private static final int SERVICE_RESTART_THRESHOLD = 10;
    private static final long WAKELOCK_DURATION_THRESHOLD = 60000; // 1 minute
    
    public void analyzeApp(AppMetrics metrics) {
        if (metrics.bootReceiverInvocations > BOOT_RECEIVER_INVOCATION_THRESHOLD) {
            alert("ABNORMAL_BOOT_RECEIVER_INVOCATION");
        }
        
        if (metrics.serviceRestarts > SERVICE_RESTART_THRESHOLD) {
            alert("ABNORMAL_SERVICE_RESTART");
        }
        
        if (metrics.averageWakelockDuration > WAKELOCK_DURATION_THRESHOLD) {
            alert("EXCESSIVE_WAKELOCK");
        }
    }
}
```

**Effectiveness**: 70-80% (detection rather than prevention)

### 4.2 Automated Response Actions

**Escalation Levels**:
```
Level 1 (Low Risk): Log and monitor
Level 2 (Medium Risk): Restrict background execution
Level 3 (High Risk): Quarantine app
Level 4 (Critical): Isolate and notify user
```

**Implementation Example**:
```java
public void respondToAnomalies(String appName, int threatLevel) {
    switch (threatLevel) {
        case CRITICAL:
            // Kill app and disable
            killApp(appName);
            disableApp(appName);
            notifyUser(appName, "Security threat detected");
            break;
            
        case HIGH:
            // Restrict background execution
            restrictBackgroundExecution(appName);
            logIncident(appName, "high_risk_behavior");
            break;
    }
}
```

## Mitigation Effectiveness Summary

| Mitigation | Effectiveness | Difficulty | Coverage |
|-----------|---------------|-----------|----------|
| Static Analysis | 70% | Low | Code only |
| Dynamic Monitoring | 75% | Medium | Runtime behavior |
| Explicit Intents | 95% | Low | Intent hijacking |
| Permission Controls | 85% | Medium | Component access |
| Service Lifecycle | 85% | Medium | Service persistence |
| SELinux Policy | 90% | High | Kernel-level |
| ASLR | 85% | Low | Memory attacks |
| Anomaly Detection | 75% | High | Behavioral patterns |

## Recommended Defense Strategy

**Layered Approach**:
1. **Detection Layer**: Static + Dynamic analysis
2. **Prevention Layer**: Permission controls, explicit intents
3. **Hardening Layer**: SELinux, ASLR, service lifecycle management
4. **Response Layer**: Anomaly detection and automated response

This multi-layered strategy provides defense-in-depth against Android persistence attacks.
