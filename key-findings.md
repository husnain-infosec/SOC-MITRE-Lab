# SOC Home Lab — Key Findings Summary
**Muhammad Husnain | SOC Analyst | Lahore, Pakistan | April 2026**
**Tools: Wazuh 4.7.5 | Kali Linux | Windows 7 | VirtualBox**

---

## Detection Results (MITRE ATT&CK)

| Technique | Name | Method | Events | Event ID | Result |
|-----------|------|--------|--------|----------|--------|
| T1078 | Valid Accounts | Created local attacker account, logged in via runas | 8 | 4624 | Detected ✅ |
| T1098 | Account Manipulation | Added attacker account to Administrators group | 4 | 4728 | Detected ✅ |
| T1484 | Domain Policy Modification | Modified local group membership | 3 | 4732 | Detected ✅ Level 12 |
| T1562.001 | Impair Defenses | Stopped and restarted Wazuh agent service | 2 | N/A | Detected ✅ High |
| T1059 | Command Execution | PowerShell recon commands | 0 | 4688 | Not Detected ❌ |
| T1110 | Brute Force | Hydra SMB wordlist attack | 4,752 | 4625 | Initially Not Detected → Detected After Fix ✅ Level 10 |

**Overall Detection Rate: 5/6 techniques — 83%**

---

## Key Findings

### Finding 1 — Windows Audit Policy is Disabled by Default
Zero security events were captured before manually enabling audit 
policies. Without this configuration step, the SIEM receives no 
meaningful data regardless of how well detection rules are written.

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
gpupdate /force
```

This is not optional. It is the foundation of endpoint visibility.
Every SOC deployment on Windows must validate this before 
assuming any detection is functional.

---

### Finding 2 — T1562.001 is the Most Reliably Detected Technique
Stopping the Wazuh agent generated an immediate high-severity alert.
Attackers cannot silently disable endpoint monitoring without 
being flagged — as long as the SIEM connection is active.

Critical limitation: If an attacker stops the agent AND clears 
Windows event logs simultaneously, this detection layer collapses.
Centralized log backup is essential for resilience.

---

### Finding 3 — T1484 Generated the Highest Severity Alert (Level 12)
Adding accounts to the local Administrators group triggered a 
Level 12 alert — the highest observed across all six techniques.

In a production SOC environment, a Level 12 alert should trigger 
immediate analyst response and escalation — not just passive logging.
Alert severity must be mapped to response procedures, not just dashboards.

---

### Finding 4 — T1059 Exposed a Critical Telemetry Gap
This was the most important and most valuable finding in the lab.

The attack was executed correctly.
Audit policy was enabled and confirmed.
Wazuh ossec.conf was updated.
Services were restarted.
Simulation was repeated.
Result: Zero alerts.

Root cause: Windows 7 does not forward process creation events 
(Event ID 4688) through the Security event channel reliably.
This is an OS-level limitation — not a Wazuh misconfiguration.

Real-world impact:
Windows 10 + Splunk  →  T1059 generated 114 events  ✅
Windows 7  + Wazuh   →  T1059 generated   0 events  ❌

Same attack. Same intent. Completely different visibility.
This gap would remain invisible to any analyst who assumes 
their detection rules are working without validating the 
underlying log source first.

---

### Finding 5 — T1078 is the Hardest to Distinguish from Legitimate Activity
Wazuh detected the logon event and correctly mapped it to T1078.
But Event ID 4624 (logon success) looks identical whether the 
login is malicious or legitimate.

Single-event detection for T1078 is insufficient. Effective 
detection requires:
- First-time logon baselining per account
- Off-hours access alerting
- Correlation with account creation events (T1098)
- Source IP anomaly detection

Without these layers, T1078 generates true positives that are 
indistinguishable from normal administrative activity.

---

### Finding 6 — T1110 Brute Force: Audit Policy Was the Missing Layer
Hydra executed thousands of SMB password attempts against 
Windows 7. Initially zero alerts were generated in Wazuh.

Root cause: Audit policy for logon events was disabled by default.
Event ID 4625 (failed logon) was not being generated at the OS 
level — so Wazuh had nothing to receive or correlate.

Fix applied:
```bash
auditpol /set /subcategory:"Logon" /failure:enable
```

Result after fix:
- 4,752 Event ID 4625 entries generated
- Wazuh flagged T1110 — Brute Force — Level 10
- 477 pages of correlated alerts

The SIEM was never broken. The OS was simply not logging.
This finding reinforces the core lesson of this lab: validate 
your log sources before assuming your detection is functional.

---

## Wazuh Detection Reference

| Technique | Filter | Status |
|-----------|--------|--------|
| T1078 — Valid Accounts | rule.mitre.id: T1078 + EventID: 4624 | Active ✅ |
| T1098 — Account Manipulation | rule.mitre.id: T1098 + EventID: 4728 | Active ✅ |
| T1484 — Policy Modification | rule.mitre.id: T1484 + Level: 12 | Active ✅ |
| T1562.001 — Impair Defenses | rule.mitre.id: T1562.001 | Active ✅ |
| T1059 — Command Execution | EventID: 4688 | Not Available on Windows 7 ❌ |
| T1110 — Brute Force | EventID: 4625 + threshold rule | Active after audit policy fix ✅ |

---

## Critical Gaps Identified

| Gap | Impact | Recommended Fix |
|-----|--------|----------------|
| Windows 7 process creation logging | T1059 undetectable — zero visibility | Upgrade to Windows 10+ or deploy Sysmon |
| Default audit policy disabled | Brute force and logon failures invisible until manually enabled | Enable audit policy as first step in any SOC deployment |
| No behavioral baselining | T1078 indistinguishable from normal logins | Implement user behavior analytics |
| Single agent monitoring point | Agent stop creates blind spot | Deploy backup telemetry and centralized log storage |

---

## Cross-Tool Comparison: Wazuh + Windows 7 vs Splunk + Windows 10

| Factor | This Lab | Parallel Lab (Wilfred Amimo) |
|--------|----------|------------------------------|
| SIEM | Wazuh 4.7.5 | Splunk Enterprise |
| Target OS | Windows 7 | Windows 10 |
| Hypervisor | VirtualBox | KVM |
| T1059 Events | 0 | 114 |
| T1110 Events | 4,752 (after audit fix) | 2 |
| T1078 Events | 8 | 8 |
| Techniques Tested | 6 | 3 |
| Techniques Detected | 5/6 (83%) | 3/3 (100%) |
| Detection Gaps Documented | 1 permanent gap + 1 resolved | Not documented |
| Key Advantage | Gap analysis + OS telemetry tracing | Higher event volume on modern OS |

**Conclusion:** Detection capability is not determined by tool 
selection alone. OS version, audit policy configuration, and 
log source integrity determine what a SIEM can and cannot see —
regardless of how powerful the platform is.

---

## Final Statement

This lab demonstrated that a correctly configured SIEM can still 
fail to detect real attacks — not because of tool limitations, 
but because of gaps in the underlying telemetry pipeline.

Five out of six MITRE ATT&CK techniques were successfully detected.
One was not — and tracing the root cause of that failure 
produced more actionable insight than the successful detections.

The real SOC skill is not generating alerts.
It is knowing exactly why alerts are missing — and documenting it.
