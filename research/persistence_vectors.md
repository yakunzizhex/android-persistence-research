# Android Persistence Vectors - Technical Analysis

## Overview

This document provides detailed technical analysis of Android persistence attack vectors, including implementation methods, detection signatures, and impact assessment.

## 1. Broadcast Receiver Persistence Vectors

### 1.1 BOOT_COMPLETED Vector

**Action**: `android.intent.action.BOOT_COMPLETED`

**Manifest Declaration**:
```xml
<receiver android:name=".BootReceiver" android:exported="false">
    <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED" />
    </intent-filter>
</receiver>
```

**Implementation**:
```java
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        // Executes on every device startup
        startPersistentService(context);
    }
}
```

**Detection Signature**: `android.intent.action.BOOT_COMPLETED`
**Effectiveness**: 95% (guaranteed execution on boot)
**Bypass Difficulty**: Hard (requires system-level intervention)
**Detectability**: Easy (static analysis)

### 1.2 CONNECTIVITY_CHANGE Vector

**Action**: `android.net.conn.CONNECTIVITY_CHANGE`

**Trigger Points**:
- WiFi connects/disconnects
- Mobile data activation
- Network state transitions

**Implementation Pattern**:
```java
public class NetworkReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (isNetworkAvailable(context)) {
            startBackgroundSync();
        }
    }
}
```

**Risk Level**: Medium (execution only on network changes)

### 1.3 SCREEN_ON/OFF Vector

**Actions**: `android.intent.action.SCREEN_ON`, `android.intent.action.SCREEN_OFF`

**Trigger Frequency**: Multiple times per hour
**Impact**: High battery drain
**Detection**: Medium (may appear as battery usage anomaly)

## 2. Service-Based Persistence Vectors

### 2.1 START_STICKY Service

**Characteristic**: System automatically restarts service if killed

**Code Pattern**:
```java
@Override
public int onStartCommand(Intent intent, int flags, int startId) {
    startPersistentWork();
    return START_STICKY;  // Critical: Ensures restart
}
```

**Restart Delay**: 5-10 seconds
**System Behavior**: Service persists across force-stop (with limitations)

### 2.2 Foreground Service Vector (Android 8.0+)

**Requirement**: Must display notification (user-visible)

**Implementation**:
```java
private void startForegroundService() {
    Intent notificationIntent = new Intent(this, MainActivity.class);
    PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, 
        notificationIntent, 0);
    
    Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
        .setContentTitle("Service Running")
        .setSmallIcon(R.drawable.ic_notification)
        .setContentIntent(pendingIntent)
        .build();
    
    startForeground(NOTIFICATION_ID, notification);
}
```

**Android 12+ Restrictions**:
- Service must be stopped within 5 minutes if not granted foreground permission
- Notification mandatory
- Battery optimization awareness required

### 2.3 Bound Service Persistence

**Mechanism**: Service persists while clients remain bound

**Vulnerability Pattern**:
```java
// Service stays alive as long as bindings exist
class PersistentService extends Service {
    private final IBinder binder = new LocalBinder();
    
    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }
}
```

## 3. Job Scheduler & Work Manager Vectors

### 3.1 JobScheduler Persistence

**API Level**: 21+
**System Constraints**: Enforced by system power management

**Minimal Constraint Implementation**:
```java
JobInfo job = new JobInfo.Builder(JOB_ID, componentName)
    .setPeriodic(15 * 60 * 1000)  // 15 minutes minimum
    .setPersisted(true)  // Survives reboot
    .build();
```

**Effective Period**: ~15 minutes minimum
**Detection**: Easy (visible in Job Scheduler database)

### 3.2 WorkManager Modern Approach

**Features**:
- Backward compatible (API 14+)
- Chain-able tasks
- Built-in backoff policies
- Device state awareness

**Security Advantages**:
- System-enforced constraints
- Rate limiting
- Power awareness
- Transparent API

## 4. Native Library Persistence Vectors

### 4.1 System Call Hooking (ptrace)

**Implementation**:
```c
// In native library
#include <sys/ptrace.h>

void hook_system_calls() {
    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        // Execute target process
    } else {
        // Monitor and intercept calls
        ptrace(PTRACE_SYSCALL, child, 0, 0);
    }
}
```

**Severity**: CRITICAL
**Detection**: Hard (kernel-level)
**Bypass Method**: SELinux policy enforcement, LSM (Linux Security Module)

### 4.2 Memory Injection (mmap)

**Technique**: Map malicious code into process memory

```c
int fd = open("/proc/self/mem", O_RDWR);
void *addr = mmap(NULL, page_size, PROT_EXEC | PROT_READ | PROT_WRITE,
    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
memcpy(addr, shellcode, shellcode_size);
((void (*)())addr)();  // Execute injected code
```

**Prevention**: 
- ASLR (Address Space Layout Randomization)
- DEP/NX (Data Execution Prevention)
- SELinux enforcing mode

### 4.3 Process Replacement (execve)

**Concept**: Replace current process with another executable

```c
execve("/system/bin/app_process", argv, envp);
```

**Use Case**: Hide malicious process by replacing with legitimate binary
**Detection**: Difficult without monitoring

## 5. Intent Filter Exploitation

### 5.1 Implicit Intent Hijacking

**Vulnerable Pattern**:
```xml
<activity android:name=".HijackableActivity">
    <intent-filter>
        <action android:name="com.example.CUSTOM_ACTION"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>
```

**Attack Vector**:
```java
Intent intent = new Intent("com.example.CUSTOM_ACTION");
intent.putExtra("sensitive_data", value);
startActivity(intent);  // Could be hijacked by malicious app
```

**Mitigation**:
```java
// Use explicit intent instead
Intent intent = new Intent(this, TargetActivity.class);
startActivity(intent);
```

## 6. Content Provider Vulnerabilities

### 6.1 Unrestricted Provider Access

**Vulnerable Implementation**:
```xml
<provider android:name=".SensitiveProvider"
    android:authorities="com.example.provider"
    android:exported="true"/>  <!-- Dangerous! -->
```

**Query Example**:
```java
Uri uri = Uri.parse("content://com.example.provider/sensitive_data");
Cursor cursor = context.getContentResolver().query(uri, null, null, null, null);
// Access all data without permission check
```

**Attack Scenario**: Leak contacts, messages, location data

### 6.2 SQL Injection in Content Providers

**Vulnerable Code**:
```java
String selection = "name = '" + userInput + "'";  // DANGEROUS!
Cursor cursor = db.query("users", null, selection, null, null, null, null);
```

**Impact**: Unauthorized data access or modification

## Persistence Effectiveness Rating

### High Effectiveness (>80%)
- BOOT_COMPLETED receiver: 95%
- START_STICKY service: 90%
- Native library hooks: 85% (varies by Android version)

### Medium Effectiveness (40-80%)
- JobScheduler: 70% (limited by system constraints)
- WorkManager: 65% (limited by system constraints)
- CONNECTIVITY_CHANGE: 75%

### Lower Effectiveness (<40%)
- Content Provider abuse: 25% (limited usefulness)
- Intent Filter hijacking: 30% (requires specific app targeting)

## Detection Difficulty

| Vector | Static Analysis | Dynamic Analysis | Runtime Detection |
|--------|-----------------|------------------|-------------------|
| Boot Receiver | Very Easy | Easy | Easy |
| Sticky Service | Easy | Medium | Medium |
| JobScheduler | Easy | Easy | Hard |
| Native Hooks | Hard | Medium | Very Hard |
| Intent Filter | Easy | Medium | Easy |
| Content Provider | Easy | Medium | Medium |

## Conclusion

Android persistence vectors vary significantly in effectiveness, detectability, and implementation complexity. Native library-based persistence represents the most dangerous vector due to kernel-level access, while broadcast receivers represent the most commonly exploited mechanism due to ease of implementation.
