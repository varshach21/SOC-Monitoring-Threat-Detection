# SOC Monitoring & Threat Detection: Adversary Simulation and Custom SIEM Rule Engineering

## Executive Summary

This project demonstrates an end-to-end Security Operations Center (SOC) detection engineering workflow — from SIEM deployment and endpoint instrumentation through adversary emulation, detection gap analysis, and custom rule development. The target technique, MITRE ATT&CK T1053.005 (Scheduled Task/Job: Scheduled Task), was selected for its prevalence in real-world intrusion campaigns as a persistence mechanism. A custom Wazuh detection rule was authored to discriminate between benign scheduled task activity and adversary-indicative behavior, achieving a 3x severity escalation over the platform's default detection logic and a 100% detection rate across controlled adversary simulations.

## Objective

To design, deploy, and validate a detection pipeline capable of identifying scheduled-task-based persistence on a Windows endpoint, using open-source tooling representative of enterprise SOC environments. The project emphasizes detection engineering methodology — not merely confirming that alerts fire, but refining detection fidelity to reduce analyst fatigue and surface high-confidence indicators of compromise.

## Lab Architecture

| Component | Specification |
|-----------|--------------|
| SIEM Platform | Wazuh 4.9.2 (unified manager, indexer, and dashboard deployment) on Ubuntu Server |
| Monitored Endpoint | Windows 11 Enterprise with Wazuh agent (v4.9.2), reporting via EventChannel |
| Adversary Emulation | Atomic Red Team v2.3.0 (Invoke-AtomicRedTeam), executing MITRE ATT&CK-mapped test cases |
| Network Topology | Isolated VirtualBox environment with bridged networking for inter-VM communication |
| Log Sources | Windows Security Event Log (EventChannel), configured for Object Access auditing |

## Threat Model

**MITRE ATT&CK Mapping:**

| Field | Value |
|-------|-------|
| Technique | [T1053.005 — Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) |
| Tactics | Execution, Persistence, Privilege Escalation |
| Platforms | Windows |
| Data Sources | Windows Event ID 4698 (Scheduled Task Created), Sysmon Process Creation |
| Adversary Use Cases | APT29 (Cozy Bear), FIN7, Lazarus Group — documented use of scheduled tasks for post-exploitation persistence |

**Attack Narrative:** An adversary with initial access creates a scheduled task configured to execute `cmd.exe`, establishing a persistent foothold that survives system reboots. This technique is favored in real-world campaigns for its low visibility in default Windows audit configurations and its ability to execute arbitrary payloads at attacker-defined intervals.

**Atomic Test Executed:** T1053.005-2 (Scheduled Task Local) — invokes `schtasks.exe /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10`, replicating a minimal but operationally representative persistence implant.

## Detection Engineering Methodology

### Phase 1: Baseline Detection Assessment

The default Wazuh ruleset includes Rule ID 60228 (level 4), which generates a low-severity informational alert on any Windows Event ID 4698 occurrence:

```xml
<rule id="60228" level="4">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4698$</field>
    <description>A scheduled task was created</description>
    <options>no_full_log</options>
    <mitre>
        <id>T1053</id>
    </mitre>
</rule>
```

**Assessment:** This rule lacks specificity — it fires identically for legitimate administrative task creation (e.g., Windows Update, IT automation) and adversary-crafted persistence mechanisms. In a production environment, this generates significant alert noise and contributes to analyst fatigue without providing actionable discrimination between benign and malicious activity.

### Phase 2: Custom Rule Development

A targeted detection rule (ID 100002) was authored to chain on the baseline rule and apply content-level inspection of the scheduled task payload:

```xml
<rule id="100002" level="12">
    <if_sid>60228</if_sid>
    <field name="win.eventdata.taskContent">cmd.exe</field>
    <description>ATT&amp;CK T1053.005: Suspicious scheduled task spawning cmd.exe (possible persistence)</description>
    <mitre>
        <id>T1053.005</id>
    </mitre>
    <group>persistence,attack,</group>
</rule>
```

**Design rationale:**
- **Chained evaluation (`if_sid: 60228`):** The custom rule only evaluates when the baseline rule has already matched, avoiding redundant log parsing and maintaining rule hierarchy.
- **Content inspection (`win.eventdata.taskContent`):** Rather than alerting on task creation generically, the rule examines the task's XML payload for `cmd.exe` — a strong indicator of adversary tooling when present in a newly created scheduled task.
- **Severity escalation (level 4 → level 12):** Elevates the alert from informational to high severity, ensuring it surfaces in analyst triage queues ahead of routine operational noise.
- **Granular MITRE mapping (T1053.005):** Tags the alert at the sub-technique level rather than the parent technique, enabling precise ATT&CK Navigator coverage reporting.

Deployed to `/var/ossec/etc/rules/local_rules.xml` on the Wazuh manager.

### Phase 3: Validation

The adversary simulation was re-executed post-deployment to confirm the custom rule fires correctly. Alert data was extracted from `/var/ossec/logs/alerts/alerts.json` and validated against expected field values.

## Results

| Metric | Value |
|--------|-------|
| Detection Rate | 100% — all simulated T1053.005 executions detected post-audit-policy configuration |
| Baseline Alert Severity | Level 4 (informational) |
| Custom Rule Alert Severity | Level 12 (high) |
| Severity Escalation Factor | 3x |
| MITRE Tactics Covered | Execution, Persistence, Privilege Escalation |
| MITRE Sub-Technique Precision | T1053.005 (sub-technique level, not parent T1053) |
| False Positive Reduction | Scoped from all Event ID 4698 occurrences to only those containing cmd.exe in task payload |

## Infrastructure Challenges & Remediation

The deployment surfaced four distinct issues requiring diagnosis and resolution — representative of the operational complexity encountered in production SIEM deployments:

### 1. Endpoint Script Execution Policy Restriction
**Symptom:** `UnauthorizedAccess` error on Atomic Red Team module import.
**Root Cause:** Windows PowerShell execution policy defaulted to `Restricted` across all scopes, preventing unsigned module scripts from loading.
**Remediation:** Applied `RemoteSigned` policy at `CurrentUser` scope via `Set-ExecutionPolicy`, balancing operational flexibility with security posture.

### 2. Atomic Red Team Tooling Architecture Misunderstanding
**Symptom:** `Install-AtomicRedTeam` command not recognized despite module installation.
**Root Cause:** The `Install-AtomicRedTeam` function is not exported by the `invoke-atomicredteam` PowerShell Gallery module — it is defined in a separate bootstrap script (`install-atomicredteam.ps1`) hosted on GitHub, requiring in-memory execution via `IEX (Invoke-WebRequest ...)` each session.
**Remediation:** Executed the upstream installer script directly, then proceeded with atomics library download.

### 3. Endpoint Protection Interference with Adversary Simulation
**Symptom:** `Install-AtomicRedTeam -getAtomics` failed with "Operation did not complete successfully because the file contains a virus or potentially unwanted software."
**Root Cause:** Windows Defender correctly identified atomic test payloads as potentially malicious (expected behavior for attack simulation content).
**Remediation:** Added `C:\AtomicRedTeam` as a Defender exclusion path via `Add-MpPreference`. This is standard practice for controlled adversary simulation environments and was scoped exclusively to the test directory.

### 4. Default Windows Audit Policy Gap
**Symptom:** Event ID 4698 not generated in Windows Security log despite successful scheduled task creation.
**Root Cause:** The "Audit Other Object Access Events" subcategory — required for Event ID 4698 generation — is **disabled by default** in fresh Windows installations. This is a well-documented gap in default Windows audit configurations and a common finding during SOC sensor validation.
**Remediation:** Enabled via `auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable`. Verified with `auditpol /get` and confirmed event generation in Windows Event Viewer prior to SIEM-level validation.

**Key Takeaway:** The audit policy gap (Issue 4) represents a detection blind spot that exists in many production environments. Identifying and remediating it is a core SOC engineering responsibility and underscores the importance of validating detection coverage through adversary simulation rather than assuming default configurations are sufficient.

## Evidence Artifacts

| Artifact | Location | Description |
|----------|----------|-------------|
| Baseline Alert (JSON) | [`evidence/T1053.005-baseline-alert.json`](evidence/T1053.005-baseline-alert.json) | Wazuh alert from built-in Rule 60228 (level 4) — generic scheduled task creation detection |
| Custom Rule Alert (JSON) | [`evidence/T1053.005-custom-rule-alert.json`](evidence/T1053.005-custom-rule-alert.json) | Wazuh alert from custom Rule 100002 (level 12) — targeted cmd.exe persistence detection |
| Custom Rule Definition | [`rules/local_rules.xml`](rules/local_rules.xml) | The custom detection rule as deployed on the Wazuh manager |
| Screenshots | [`evidence/screenshots/`](evidence/screenshots/) | Visual documentation of each project phase |

## Tools & Technologies

- **[Wazuh](https://wazuh.com/)** — Open-source SIEM, XDR, and compliance platform
- **[Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam)** — MITRE ATT&CK-mapped adversary simulation framework by Red Canary
- **[MITRE ATT&CK Framework](https://attack.mitre.org/)** — Adversary tactics, techniques, and procedures knowledge base
- **Windows Event Logging** — Native Windows audit infrastructure (Security EventChannel, `auditpol`)
- **Oracle VirtualBox** — Type-2 hypervisor for isolated lab virtualization

## Future Work

- **Sysmon integration:** Deploy Sysmon with a SwiftOnSecurity-based configuration to capture process-level telemetry (process creation, network connections, file creation timestamps) alongside Windows Security events, enabling correlation-based detection rules.
- **Expanded T1053.005 coverage:** Author additional rules for PowerShell cmdlet-based task creation (T1053.005-4), WMI-based scheduling (T1053.005-6), and registry-based "ghost tasks" (T1053.005-10) to broaden detection surface across all sub-test variants.
- **Cross-technique detection:** Extend the custom ruleset to cover additional persistence mechanisms including T1547.001 (Registry Run Keys/Startup Folder), T1136.001 (Local Account Creation), and T1059.001 (PowerShell Execution).
- **Automated response:** Implement Wazuh active response modules to trigger automated containment actions (e.g., endpoint isolation, task deletion) on level 12+ alerts, reducing mean time to respond (MTTR).
- **Multi-endpoint deployment:** Add a Linux endpoint to demonstrate cross-platform detection capability and SIEM scalability.
- **Detection-as-Code pipeline:** Version-control all custom rules in a Git repository with CI/CD validation (XML linting, rule syntax checks) prior to production deployment, following detection engineering best practices.

