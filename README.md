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

---

##  Environment Overview

| Component | Hostname | Role |
|----------|----------|------|
| Windows 11 Endpoint | WIN-CLIENT | Generates authentication logs (4624/4625) |
| Windows Server 2022 | DC01 | Domain Controller (Kerberos & NTLM events) |
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

##  Repository Structure

/
├── labs/
│ ├── lab-01-bruteforce-ad/
│ │ ├── report.md
│ │ ├── evidence/
│ │ └── notes.md (if needed for future use)
└── README.md


---

##  Future Work

This repository will grow progressively with new SOC-oriented labs:

- Lab 02: Lateral movement detection  
- Lab 03: Suspicious process execution  
- Lab 04: Wazuh rule tuning  
- Lab 05: Network-based detection scenarios  
- Additional SIEM or EDR integrations

Each lab will include a structured investigation report and annotated evidence.

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
