# SOC Home Lab – Active Directory & SIEM Detection

This repository documents my practical learning projects focusing on Windows authentication monitoring, Active Directory behavior, and SIEM-based detection.  
The purpose of this lab is to strengthen my technical foundation for SOC analyst roles through hands-on experimentation, structured analysis, and continuous improvement.

---

##  Lab 01 – Active Directory Brute Force Detection

**Objective**  
Simulate a brute-force attack against a domain account and observe how authentication events propagate from endpoint → domain controller → SIEM.

**Key learning outcomes:**

- Understanding Windows logon events (4624 / 4625)
- Observing Kerberos and NTLM failures (4768 / 4771 / 4776)
- Analyzing authentication workflows across systems
- Reviewing SIEM correlation and MITRE ATT&CK mapping
- Practicing SOC-style documentation and investigation methodology

**Main report:**  
 [`report.md`](./labs/lab-01-bruteforce-ad/report.md)

**Evidence dataset:**  
 [`evidence/`](./labs/lab-01-bruteforce-ad/evidence)

 ## Lab 02 — Lateral Movement Detection (SMB / NTLM)

**Objective:**  
Analyze and detect NTLM-based lateral movement attempts in an Active Directory environment using Domain Controller logs and SIEM correlation.

**Key points:**
- SMB authentication attempt from an attacker machine
- NTLM credential validation on the Domain Controller (Event ID 4776)
- Identification of a SIEM visibility gap
- Remediation of Windows Security log access (wevtutil)
- Successful ingestion and normalization in Wazuh

**Skills demonstrated:**
- Windows authentication log analysis (NTLM)
- Active Directory Domain Controller monitoring
- SIEM troubleshooting and log ingestion validation
- SOC-style investigation and documentation

 **Main Report:**  
[`report.md`](./labs/lab-02-lateral-movement/report.md)

**Evidence dataset:**  
[`evidence/`](./labs/lab-02-lateral-movement/evidence/)

---

##  Environment Overview

| Component | Hostname | Role |
|----------|----------|------|
| Windows 10 Endpoint | WIN-CLIENT | Generates authentication logs (4624/4625) |
| Windows Server 2019 | DC01 | Domain Controller (Kerberos & NTLM events) |
| Kali Linux | KALI | Attacker machine for brute-force attempts |
| Ubuntu Server | WAZUH-MANAGER | SIEM collecting and correlating logs |

**Network:** Isolated internal network (192.168.100.0/24)

---

##  Project Goals

- Improve SOC investigation skills  
- Gain practical experience with Windows & AD authentication flows  
- Learn log correlation and MITRE-based detection  
- Build a documented security lab aligned with real SOC workflows  
- Develop a consistent and methodical approach to incident analysis  

---

### Lab 03 — Suspicious PowerShell Encoded Command Detection

**Environment Overview**

| Component        | Hostname        | Role                     | Description |
|------------------|-----------------|--------------------------|-------------|
| Windows Endpoint | WIN-CLIENT      | Monitored workstation    | Windows 10 endpoint where an encoded PowerShell command is executed and logged |
| Domain Controller| DC01            | Active Directory         | Windows Server 2019 domain controller (not directly involved in this scenario) |
| SIEM             | WAZUH-MANAGER   | Log collection & analysis| Centralized log collection, correlation, and alerting via Wazuh SIEM |

**Project Goals**

- Detect obfuscated PowerShell execution using encoded commands  
- Validate endpoint visibility through PowerShell Script Block Logging and Sysmon  
- Correlate endpoint telemetry at the SIEM level  
- Map suspicious activity to MITRE ATT&CK techniques  
- Demonstrate SOC-level analysis of suspicious scripting behavior  

- [`report.md`](./labs/lab-03-suspicious-powershell/report.md)
- [`evidence/`](./labs/lab-03-suspicious-powershell/evidence)

---

## Lab 04 — Scheduled Task Persistence Detection

**Environment Overview**

| Component        | Hostname      | Role                     | Description |
|------------------|---------------|--------------------------|-------------|
| Windows Endpoint | WIN-CLIENT    | Monitored workstation    | Windows 10 endpoint where a scheduled task is created for persistence |
| Domain Controller| DC01          | Active Directory         | Windows Server 2019 domain controller (not directly involved in this scenario) |
| SIEM             | WAZUH-MANAGER | Log collection & analysis| Centralized log collection and analysis via Wazuh SIEM |

**Project Goals**

- Identify persistence through scheduled task creation  
- Observe native Windows logging of task scheduler activity  
- Validate process execution visibility using Windows Security logs and Sysmon  
- Assess SIEM-level visibility and detection limitations  
- Map persistence behavior to MITRE ATT&CK techniques  
- Demonstrate realistic SOC analysis of task scheduler abuse  

- [`report.md`](./labs/lab-04-scheduled-task-persistence/report.md)
- [`evidence/`](./labs/lab-04-scheduled-task-persistence/evidence)

##  Repository Structure

/
├── labs/
│ ├── lab-01-bruteforce-ad/
│ │ ├── report.md
│ │ ├── evidence/
│ │ └── notes.md (if needed for future use)
| ├── lab-02-lateral-movement/
| | ├── report.md
│ │ ├── evidence/
| ├── lab-03-suspicious-powershell
| | ├── report.md
| | ├── evidence/
| ├── lab-04-suspicious-scheduled-task/
| | ├── report.md
| | ├── evidence/
└── README.md

---

### Lab 05 — Registry Run Key Persistence Detection

**Environment Overview**

| Component        | Hostname      | Role                     | Description |
|------------------|---------------|--------------------------|-------------|
| Windows Endpoint | WIN-CLIENT    | Monitored workstation    | Windows 10 endpoint where registry Run key persistence is created |
| Domain Controller| DC01          | Active Directory         | Windows Server 2019 domain controller (not directly involved in this scenario) |
| SIEM             | WAZUH-MANAGER | Log collection & analysis| Centralized log collection, correlation, and alerting via Wazuh SIEM |

**Project Goals**

- Detect user-level persistence through Windows Registry Run keys  
- Validate endpoint visibility using Sysmon registry telemetry  
- Assess SIEM visibility through PowerShell Script Block Logging  
- Correlate endpoint activity at the SIEM level  
- Map persistence behavior to MITRE ATT&CK techniques  
- Demonstrate realistic SOC analysis of registry-based persistence  

- [`report.md`](./labs/lab-05-registry-run-persistence/report.md)
- [`evidence/`](./labs/lab-05-registry-run-persistence/evidence)

---

##  Future Work

This repository will grow progressively with new SOC-oriented labs:
   
- Lab 05: Network-based detection scenarios  
- Additional SIEM or EDR integrations

Each lab includes a structured investigation report and annotated evidence.

---

##  Japan Career Interest (Optional Note)

In addition to applying for SOC roles internationally, I am also preparing for potential opportunities in Japan.  
I appreciate the emphasis on structured workflows, attention to detail, and continuous improvement often found in Japanese security teams.  
This project is part of my step-by-step effort to strengthen my technical foundation before joining a professional environment.

(*This note does not imply Japanese language proficiency; it only reflects my professional and personnal interest in the region.*)

---

##  Feedback & Continuous Improvement

I am continuously improving this lab and welcome constructive feedback.  
My goal is to build strong investigation habits, deepen my understanding of security monitoring, and progress steadily toward SOC responsibilities.

Thank you for viewing this project.
