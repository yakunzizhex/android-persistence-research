"""
Defensive Mitigations - Mitigation strategies and defensive recommendations.

Provides comprehensive mitigation strategies for Android persistence mechanisms
and security vulnerabilities. Includes defensive techniques for system hardening.

DISCLAIMER: These mitigations are intended for defensive purposes on authorized
systems only. Improper implementation may affect system functionality.

Author: Security Research Team
License: Apache-2.0
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum


class MitigationType(Enum):
    """Types of mitigation strategies."""
    DETECTION = "detection"
    PREVENTION = "prevention"
    HARDENING = "hardening"
    MONITORING = "monitoring"
    RESPONSE = "response"


@dataclass
class Mitigation:
    """Single mitigation strategy."""
    name: str
    description: str
    mitigation_type: MitigationType
    implementation: str
    effectiveness: int  # 0-100
    difficulty: int  # 0-100 (implementation difficulty)
    references: List[str] = None


class MitigationStrategies:
    """
    Central repository of defensive mitigation strategies.
    
    Provides tailored recommendations based on detected persistence mechanisms
    and threat profiles.
    
    Example:
        >>> mitigations = MitigationStrategies()
        >>> strategies = mitigations.get_mitigations_for_threat('broadcast_receiver')
    """

    def __init__(self):
        """Initialize mitigation strategies database."""
        self.mitigations = self._load_mitigations()

    def _load_mitigations(self) -> Dict[str, List[Mitigation]]:
        """
        Load comprehensive mitigation strategies database.
        
        Returns:
            Dictionary mapping threat types to mitigation lists
        """
        return {
            'broadcast_receiver': [
                Mitigation(
                    name="Explicit Intent Usage",
                    description="Replace implicit broadcasts with explicit intents",
                    mitigation_type=MitigationType.PREVENTION,
                    implementation="""
// Instead of implicit broadcast:
// Intent i = new Intent("com.example.ACTION");

// Use explicit broadcast:
Intent intent = new Intent(context, MyReceiver.class);
intent.setAction("com.example.ACTION");
context.sendBroadcast(intent);
                    """,
                    effectiveness=95,
                    difficulty=30,
                ),
                Mitigation(
                    name="Permission-Based Access Control",
                    description="Restrict receiver access with signature-level permissions",
                    mitigation_type=MitigationType.PREVENTION,
                    implementation="""
<receiver android:name=".MyReceiver"
    android:permission="com.example.permission.RECEIVE_EVENT">
    <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
    </intent-filter>
</receiver>

<!-- In another app that needs to send: -->
<uses-permission android:name="com.example.permission.RECEIVE_EVENT"/>
                    """,
                    effectiveness=80,
                    difficulty=25,
                ),
                Mitigation(
                    name="Context-Aware Receiver Registration",
                    description="Register receivers dynamically only when needed",
                    mitigation_type=MitigationType.HARDENING,
                    implementation="""
// Register in onCreate:
IntentFilter filter = new IntentFilter();
filter.addAction(Intent.ACTION_BOOT_COMPLETED);
registerReceiver(myReceiver, filter);

// Unregister in onDestroy:
unregisterReceiver(myReceiver);
                    """,
                    effectiveness=85,
                    difficulty=40,
                ),
            ],
            'service': [
                Mitigation(
                    name="Implement StartId Management",
                    description="Properly handle service stopSelf() with correct startId",
                    mitigation_type=MitigationType.HARDENING,
                    implementation="""
@Override
public int onStartCommand(Intent intent, int flags, int startId) {
    // Do work
    
    // Only stop if this is the latest request
    if (shouldStop) {
        stopSelf(startId);
    }
    
    return START_NOT_STICKY;  // Don't restart
}
                    """,
                    effectiveness=90,
                    difficulty=20,
                ),
                Mitigation(
                    name="Background Service Limitations",
                    description="Use WorkManager or JobScheduler with constraints",
                    mitigation_type=MitigationType.HARDENING,
                    implementation="""
// Use WorkManager instead of Service:
PeriodicWorkRequest workRequest =
    new PeriodicWorkRequest.Builder(
        MyWorker.class,
        15,  // minimum interval
        TimeUnit.MINUTES)
    .addTag("background_work")
    .build();

WorkManager.getInstance(context)
    .enqueueUniquePeriodicWork(
        "work_name",
        ExistingPeriodicWorkPolicy.REPLACE,
        workRequest);
                    """,
                    effectiveness=85,
                    difficulty=35,
                ),
                Mitigation(
                    name="Service Permission Declaration",
                    description="Declare services with explicit permissions",
                    mitigation_type=MitigationType.PREVENTION,
                    implementation="""
<service android:name=".MyService"
    android:permission="com.example.INTERNAL_SERVICE">
    <intent-filter>
        <action android:name="com.example.MY_ACTION"/>
    </intent-filter>
</service>
                    """,
                    effectiveness=80,
                    difficulty=15,
                ),
            ],
            'native_library': [
                Mitigation(
                    name="Native Code Validation",
                    description="Use runtime code integrity verification for native libs",
                    mitigation_type=MitigationType.DETECTION,
                    implementation="""
// Compute hash of loaded native library
public boolean verifyNativeLibrary(String libName) {
    try {
        System.loadLibrary(libName);
        String libPath = findLoadedLibraryPath(libName);
        String hash = calculateFileHash(libPath);
        return hash.equals(expectedHash);
    } catch (Exception e) {
        return false;
    }
}
                    """,
                    effectiveness=75,
                    difficulty=60,
                ),
                Mitigation(
                    name="Selinux Policy Enforcement",
                    description="Implement strict SELinux policy for native code",
                    mitigation_type=MitigationType.HARDENING,
                    implementation="""
# SELinux policy for native library access
type app_native_t;
type app_data_t;

allow app_native_t app_data_t:file { read write };
deny app_native_t kernel_t:capability sys_ptrace;
neverallow app_native_t device_t:chr_file write;
                    """,
                    effectiveness=90,
                    difficulty=80,
                ),
                Mitigation(
                    name="Address Space Layout Randomization (ASLR)",
                    description="Enable ASLR to prevent memory exploitation",
                    mitigation_type=MitigationType.HARDENING,
                    implementation="""
# ASLR is enabled by default on modern Android
# Verify via:
adb shell cat /proc/sys/kernel/randomize_va_space
# Should output: 2 (full ASLR)
                    """,
                    effectiveness=85,
                    difficulty=5,
                ),
            ],
            'job_scheduler': [
                Mitigation(
                    name="Job Constraints Implementation",
                    description="Enforce strict constraints on scheduled jobs",
                    mitigation_type=MitigationType.HARDENING,
                    implementation="""
JobInfo job = new JobInfo.Builder(JOB_ID, componentName)
    .setRequiresDeviceIdle(true)
    .setRequiresCharging(true)
    .setRequiredNetworkType(JobInfo.NETWORK_TYPE_UNMETERED)
    .setPeriodic(24 * 60 * 60 * 1000)  // 24 hours minimum
    .build();
                    """,
                    effectiveness=80,
                    difficulty=25,
                ),
                Mitigation(
                    name="Job Execution Monitoring",
                    description="Monitor and log all job executions",
                    mitigation_type=MitigationType.MONITORING,
                    implementation="""
public class MonitoredJobService extends JobService {
    @Override
    public boolean onStartJob(JobParameters params) {
        logJobExecution("started", params.getJobId());
        doWork();
        logJobExecution("completed", params.getJobId());
        return false;
    }
}
                    """,
                    effectiveness=70,
                    difficulty=30,
                ),
            ],
            'intent_filter': [
                Mitigation(
                    name="Explicit Component Targeting",
                    description="Always use explicit intents instead of implicit",
                    mitigation_type=MitigationType.PREVENTION,
                    implementation="""
// Bad: implicit intent
Intent intent = new Intent("com.example.ACTION");
startActivity(intent);

// Good: explicit intent
Intent intent = new Intent(this, TargetActivity.class);
startActivity(intent);
                    """,
                    effectiveness=95,
                    difficulty=20,
                ),
                Mitigation(
                    name="Intent Filter Export Control",
                    description="Carefully control intent filter export attribute",
                    mitigation_type=MitigationType.HARDENING,
                    implementation="""
<!-- Only export if truly necessary -->
<activity android:name=".PublicActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
    </intent-filter>
</activity>

<!-- Default: not exported -->
<activity android:name=".PrivateActivity">
</activity>
                    """,
                    effectiveness=85,
                    difficulty=15,
                ),
            ],
        }

    def get_mitigations_for_threat(self, threat_type: str) -> List[Mitigation]:
        """
        Get mitigations for specific threat type.
        
        Args:
            threat_type: Type of threat (e.g., 'broadcast_receiver')
            
        Returns:
            List of applicable mitigations
        """
        threat_type = threat_type.lower().replace(' ', '_')
        return self.mitigations.get(threat_type, [])

    def get_mitigations_by_type(self, mitigation_type: MitigationType) -> List[Mitigation]:
        """
        Get all mitigations of specific type.
        
        Args:
            mitigation_type: Type of mitigation to filter by
            
        Returns:
            List of mitigations
        """
        results = []
        for mitigations in self.mitigations.values():
            results.extend([m for m in mitigations if m.mitigation_type == mitigation_type])
        return results

    def get_highest_effectiveness_mitigation(
        self,
        threat_type: str
    ) -> Optional[Mitigation]:
        """Get most effective mitigation for threat."""
        mitigations = self.get_mitigations_for_threat(threat_type)
        if not mitigations:
            return None
        return max(mitigations, key=lambda m: m.effectiveness)

    def get_easiest_mitigations(self, threat_type: str, count: int = 3) -> List[Mitigation]:
        """Get easiest-to-implement mitigations."""
        mitigations = self.get_mitigations_for_threat(threat_type)
        sorted_mitigations = sorted(mitigations, key=lambda m: m.difficulty)
        return sorted_mitigations[:count]

    def generate_mitigation_report(self, threats: List[str]) -> str:
        """
        Generate mitigation recommendations report.
        
        Args:
            threats: List of detected threat types
            
        Returns:
            Formatted mitigation report
        """
        lines = ["MITIGATION RECOMMENDATIONS REPORT", "=" * 70]
        lines.append("")
        
        all_mitigations: Set[str] = set()
        
        for threat in threats:
            mitigations = self.get_mitigations_for_threat(threat)
            if mitigations:
                lines.append(f"\n{threat.upper()}")
                lines.append("-" * 50)
                
                for mitigation in mitigations:
                    lines.append(f"\n  {mitigation.name}")
                    lines.append(f"    Type: {mitigation.mitigation_type.value}")
                    lines.append(f"    Effectiveness: {mitigation.effectiveness}%")
                    lines.append(f"    Difficulty: {mitigation.difficulty}/100")
                    lines.append(f"    Description: {mitigation.description}")
                    all_mitigations.add(mitigation.name)
        
        lines.append("\n" + "=" * 70)
        lines.append(f"Total Unique Mitigations: {len(all_mitigations)}")
        
        return "\n".join(lines)
