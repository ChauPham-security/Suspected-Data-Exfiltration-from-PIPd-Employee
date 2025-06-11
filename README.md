
<img width="898" alt="Screenshot 2025-06-11 at 11 23 33 AM" src="https://github.com/user-attachments/assets/4fe39882-5cd9-4488-9aa4-d0ba5dece980" />

# 🕵️‍♂️ Suspected Data Exfiltration from PIPd Employee

This threat hunt investigates a potentially malicious insider (John Doe), who was recently placed on a Performance Improvement Plan (PIP). Due to behavioral red flags and elevated access, I assessed his device for any signs of data archiving or exfiltration activity. The investigation was performed using Microsoft Defender for Endpoint (MDE).

---

## 🧭 Scenario Overview

### 🎯 Goal
After being placed on a PIP, John Doe, an employee in a sensitive department, showed signs of distress. Leadership feared he may attempt to steal proprietary company data before resigning. The objective was to determine if any suspicious activity had occurred on his corporate machine (`windows-target-1`).

### 🧠 Hypothesis
John has administrator rights on his device and can use any application he chooses. He may try to compress and archive sensitive data and potentially upload it to an external location.

---

## 🛠️ Threat Hunting Process

### 1. Preparation
- Focus: File archiving, compression, and potential exfiltration from John's device.
- Considerations:
  - PowerShell is not restricted on the system.
  - Exfiltration may occur via browser, network transfer, or external drive.

### 2. Data Collection
- Data sources used:
  - `DeviceFileEvents`
  - `DeviceProcessEvents`
  - `DeviceNetworkEvents`

### 3. Data Analysis

#### 📦 Discovery of Archive Activity

```kql
DeviceFileEvents
| where DeviceName == 'windows-target-1'
| where FileName endswith ".zip"
| order by Timestamp desc
```

- Discovered frequent creation of `.zip` files.
- Files were being moved into a folder named `"backup"`.

#### 🛠️ PowerShell Automation of Archiving: From the multiple ZIP file creation events, I selected one instance and used its timestamp to search the DeviceProcessEvents table for any related activity occurring one minute before and after. This led me to discover a PowerShell script that quietly installed 7-Zip and used it to compress employee data.

```kql
let specificTime = datetime(2025-06-02T04:50:02.9781696Z);
let VMName = "windows-target-1";
DeviceProcessEvents
| where Timestamp between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```

- Found that a PowerShell script silently installed **7-Zip**, then used it to compress employee files.
- It looks like the archiving was scheduled or scripted to run over and over.
  
  <img width="654" alt="Screenshot 2025-06-11 at 11 12 44 AM" src="https://github.com/user-attachments/assets/01b327ec-0cd5-4e71-bd4e-96aea41210d0" />


#### 🌐 Search for Exfiltration (No Evidence Found): I looked at the same timeframe for signs of data being sent out over the network but didn’t find any logs to confirm that.

```kql
let specificTime = datetime(2025-06-02T04:50:02.9781696Z);
let VMName = "windows-target-1";
DeviceNetworkEvents
| where Timestamp between ((specificTime - 4m) .. (specificTime + 4m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType
```

- No corresponding network events showing file transfer or exfiltration during the window of concern.

---

## 📋 Investigation Summary

- Archiving behavior was detected and verified.
- A PowerShell script installed and executed **7-Zip** without user interaction.
- Compressed files were regularly stored in a `backup` folder.
- No network-based data transfer was observed during or after these actions.

---

## 🧩 MITRE ATT&CK Mapping

| Tactic | Technique ID | Description |
|--------|--------------|-------------|
| Execution | **T1059.001** | PowerShell used to silently install and execute 7-Zip |
| Collection | **T1560.001** | Archive via Utility - Usage of 7-Zip to compress files |
| Defense Evasion | **T1036.005** | Masquerading — Storing files in a benign-looking `"backup"` folder |

---

## 🛡️ Response

- 🛑 **Isolated the device** immediately after detecting suspicious archiving behavior.
- 📣 **Reported findings** to John’s manager with log evidence of repeated archive creation.
- 🔍 **No signs of exfiltration**, but due to potential intent, escalated for further monitoring.
- ⏳ Awaiting further instructions from management on disciplinary or technical actions.

---

## 📘 Lessons Learned & Recommendations

### What We Learned
- Insider threats don’t always involve immediate exfiltration.
- Even basic PowerShell scripts can silently automate data collection.
- Hiding files in a folder named `"backup"` is a common trick that can slip past basic checks.

### How We Can Improve
- Implement logging and alerting for scripting that installs new software (e.g., 7-Zip).
- Monitor repeated archive creation and set thresholds to trigger alerts.
- Limited advanced scripting capabilities for non-technical staff to reduce the risk of misuse.

---

## ✅ Summary

A potentially disgruntled employee used PowerShell to install 7-Zip and archive internal data, possibly preparing it for exfiltration. While no data was transmitted outside the network, the activity was unusual and elevated. The system was isolated, reported, and will remain under review by security and management.
