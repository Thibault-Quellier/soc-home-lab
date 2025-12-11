# Lab 01 — Evidence (Active Directory Brute Force Detection)

This folder contains all annotated screenshots used as evidence for "Lab 01 — Detecting a brute-force attack against an Active Directory environment".

Each image corresponds to a key step in the authentication chain:

> WIN-CLIENT → DC01 (Domain Controller) → Wazuh SIEM

These artifacts are referenced in the main SOC report (`report.md`) and demonstrate the end-to-end detection pipeline.

---

 1. Windows Events on WIN-CLIENT

# `4624_WIN-CLIENT.jpg`
Windows Event "4624 (successful logon)" on WIN-CLIENT.  
Used as a "baseline" to compare legitimate logons against failed attempts (4625).

# `4624_WIN-CLIENT_Details.jpg`
Detailed view of the 4624 event.  
Shows the internal structure of a normal authentication event.

# `4625_WIN-CLIENT.jpg`
Overview of multiple **4625 (failed logon)** events.  
Visual proof of repeated authentication failures consistent with brute-force activity.

# `4625_WIN-CLIENT_Details.jpg`
Detailed view of a 4625 event.  
Contains:
- "Failure Reason: Unknown user name or bad password"  
- Status codes: `0xC000006D` / `0xC000006A`  
- Logon Type 2 (interactive logon attempt)

These fields are essential for understanding Windows authentication failures.

---

 2. Active Directory Events on DC01

# `4768_DC01.jpg`
Event "4768 — Kerberos TGT Request".  
Shows the Kerberos ticket request initiated before authentication validation.

# `4771_DC01.jpg`
Event **4771 — Kerberos pre-authentication failed**.  
The error code `0x18` confirms an incorrect password for account `user-low`.  
This is a strong indicator of brute-force attempts against Kerberos.

# `4776_DC01.jpg`
Event "4776 — NTLM credential validation".  
Shows NTLM authentication attempts coming from workstation "KALI", clearly linking the brute-force source (an other one, KALI → WIN-CLIENT) to the attacking machine.

# `Event_DC01.jpg`
Consolidated view of 4768 / 4771 / 4776 events during the attack.  
Illustrates the authentication failure pattern across the domain controller.

---

 3. Wazuh SIEM Detection

# `Wazuh.jpg`
Wazuh alerts generated from failed logons on WIN-CLIENT.  
Shows:
- Agent: `WIN-CLIENT`
- Rule ID: `60122`
- MITRE ATT&CK mappings: `T1078` (Valid Accounts), `T1531` (Account Access Manipulation)

This demonstrates rule correlation and SIEM detection capability.

# `Wazuh_Details_Event.jpg`
Detailed normalized event as processed by Wazuh.  
Displays:
- Windows Event ID: 4625  
- Target user: `user-low`  
- Host: `WIN-CLIENT.soc.local`  
- Full Windows failure data (failure reason, status codes, logon type)

This file is essential for understanding how Wazuh parses and enriches Windows logs.

---

 4. Purpose in the Portfolio

These evidence files demonstrate:

- A fully operational home SOC lab with Windows + AD + SIEM.
- Strong understanding of Windows authentication logs (4624 / 4625 / 4768 / 4771 / 4776).
- Ability to correlate activity across multiple systems (client → domain controller → SIEM).
- SOC-level analysis skills, using MITRE ATT&CK, error codes, and authentication flows.
- Practically documented incident analysis suitable for SOC / DFIR / detection engineering roles.

This evidence is part of a complete SOC investigation example designed to showcase technical readiness for "security analyst roles in Japan or internationally".
