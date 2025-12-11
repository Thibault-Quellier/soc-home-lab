 Lab 01 — Active Directory Brute Force Detection
 1. Executive Summary

This report documents the investigation of a simulated "brute-force attack" performed inside a controlled home SOC laboratory designed for security analyst training.

The goal of this lab was to:

- validate the visibility of Windows authentication events across the environment,  
- detect authentication failures on the endpoint (WIN-CLIENT),  
- observe Kerberos and NTLM behavior on the domain controller (DC01),  
- confirm that Wazuh SIEM correlates and alerts based on failed logons.

The attack consisted of repeated authentication attempts against the domain account `user-low`.  
Logs were collected from:

- "WIN-CLIENT" (local authentication failures)  
- "DC01" (Kerberos and NTLM validation events)  
- "Wazuh SIEM" (central detection and MITRE ATT&CK mapping)

 2. Environment Overview

This lab was built to replicate a realistic enterprise authentication flow involving:

- a Windows endpoint (WIN-CLIENT),
- a domain controller (DC01),
- an attacker machine (KALI),
- and a central SIEM (Wazuh).

The environment allows observing authentication events as they propagate through an actual Active Directory domain and into a monitoring system.

 2.1 Infrastructure Components

| Component | Hostname | Role | Description |

- Windows 11 Endpoint | WIN-CLIENT | Victim workstation | Generates 4624 / 4625 authentication events
- Windows Server 2022 | DC01 | Domain Controller | Handles Kerberos (4768, 4771) and NTLM (4776) authentication 
- Kali Linux | KALI | Attacker machine | Executes brute-force attempts against `user-low` 
- Ubuntu Server | WAZUH-MANAGER | SIEM | Collects and normalizes Windows logs, triggers MITRE-based alerts

 2.2 Network Topology

The laboratory environment operates on a single isolated internal network using the subnet "192.168.100.0/24".  
All machines communicate directly within this segment without routing to external networks.

"Network layout summary":

- "WIN-CLIENT"  
  - IP: 192.168.100.10  
  - Role: Windows endpoint targeted by the brute-force attempt  
  - Connected directly to DC01 and Wazuh Manager

- "DC01 (Domain Controller)"  
  - IP: 192.168.100.20  
  - Role: Active Directory Domain Services, Kerberos & NTLM authentication  
  - Receives authentication traffic from WIN-CLIENT and KALI

- "KALI (Attacker machine)"  
  - IP: 192.168.100.30  
  - Role: Used to perform brute-force attempts against the domain account `user-low`  
  - Sends authentication attempts to WIN-CLIENT and DC01

- "WAZUH-MANAGER (SIEM)"  
  - IP: 192.168.100.50  
  - Role: Central log collection, normalization, rule processing  
  - Receives logs from the Wazuh agent deployed on WIN-CLIENT

"Traffic flow summary":

1. The attacker (KALI) sends repeated authentication attempts toward the domain account `user-low`.
2. WIN-CLIENT generates local failed logon events (Event ID 4625).
3. DC01 processes Kerberos and NTLM authentication attempts and logs events (4768, 4771, 4776).
4. Wazuh collects and correlates logs from WIN-CLIENT, enabling SIEM-level detection.

This topology provides clear visibility across endpoint, domain controller, and SIEM, enabling realistic detection and analysis of authentication-based attacks.

 3. Attack Scenario Description

The objective of this lab was to simulate an authentication-based intrusion attempt against an Active Directory environment.  
The attack targeted the domain user account `user-low` and was executed from the KALI machine using brute-force techniques.

 3.1 Target User

- "Username": `user-low`  
- "Role": Low-privilege domain user  
- "Reason for selection:"  
  Low-privilege accounts are commonly targeted during brute-force attacks due to predictable naming conventions and lower monitoring sensitivity.

 3.2 Attack Method

The attacker machine "KALI" attempted to authenticate repeatedly using incorrect passwords, simulating a brute-force attempt (using Hydra).

Two methods were used:

1. "Local brute-force simulation on WIN-CLIENT"  
   - Triggered Event ID "4625" (Failed Logon) repeatedly  
   - Demonstrated detection at the endpoint level

2. "Network-based brute-force from KALI""  
   - Authentication attempts sent toward DC01  
   - Triggered:
     - "4768" (Kerberos TGT Request)  
     - "4771" (Kerberos Pre-authentication Failed — wrong password)  
     - "4776" (NTLM Validation)

 3.3 Attack Outcome

The brute-force attempts failed, producing a complete and analyzable sequence of authentication errors:

- WIN-CLIENT logged multiple "4625" events  
- DC01 generated Kerberos ("4768", "4771") and NTLM ("4776") failures  
- Wazuh SIEM raised alerts based on:
  - Rule ID "60122"
  - MITRE ATT&CK techniques **T1078** (Valid Accounts) and **T1531** (Account Access Manipulation)

This scenario reflects typical authentication patterns that may be encountered in enterprise SOC environments.

 4. Evidence Collection

All evidence used in this investigation was collected directly from the three main components of the environment:

- "WIN-CLIENT" (endpoint logs)
- "DC01" (Kerberos and NTLM authentication logs)
- "Wazuh SIEM" (normalized events and alerts)

Screenshots were captured at each stage of the authentication chain and stored in:

labs/lab-01-bruteforce-ad/evidence/

The evidence set includes:

1. Windows event logs showing successful (4624) and failed (4625) authentication attempts  
2. Kerberos (4768, 4771) and NTLM (4776) events generated by DC01  
3. Wazuh alerts and detailed SIEM-normalized event data  

Each screenshot is annotated to highlight relevant fields such as:
- usernames involved
- authentication type
- error codes
- timestamps
- hostnames
- MITRE ATT&CK mappings

This evidence supports the analysis presented in the following sections and demonstrates clear visibility across endpoint, domain controller, and SIEM layers.

 5. Log Analysis

This section provides a detailed analysis of the authentication events generated during the brute-force attack.  
The objective is to demonstrate how failed logon attempts propagate through Windows, Active Directory, and into the SIEM.

 5.1 Authentication Events on WIN-CLIENT

The brute-force attempts first generated multiple **Event ID 4625 (Failed Logon)** records on the Windows endpoint.

Key observations:

- The target account was `user-low`, a low-privilege domain user.
- The "Failure Reason" was *Unknown user name or bad password*.
- Status codes "0xC000006D" and "0xC000006A" confirm repeated incorrect password attempts.
- "Logon Type 2" (interactive) indicates the attempts were processed locally on WIN-CLIENT.
- Timestamps show rapid, repeated failures consistent with automated brute-force behavior.

A baseline "4624 (Successful Logon)" event was also reviewed to contrast normal and abnormal authentication flows.

 5.2 Kerberos Events on DC01

Each authentication attempt sent by WIN-CLIENT was forwarded to the domain controller (DC01).  
DC01 produced several events that describe how Kerberos handled the invalid credentials.

 "Event ID 4768 — Kerberos TGT Request"
DC01 received ticket requests for `user-low`.  
These requests are normal in the authentication workflow, even if the credentials are invalid.

 "Event ID 4771 — Kerberos Pre-Authentication Failed"
This event confirms that DC01 rejected the authentication attempt due to an incorrect password.

- Error Code "0x18" explicitly indicates "pre-authentication failure".
- The event ties the failed authentication to the exact user (`user-low`) and hostname (WIN-CLIENT).

 "Event ID 4776 — NTLM Validation"
DC01 also generated NTLM validation events.  
One key entry shows:

- "Source Workstation: KALI"

This is critical because it directly links the brute-force activity to the attacking machine.

 5.3 Correlation of Events Across WIN-CLIENT and DC01

The timeline of events shows:

1. WIN-CLIENT generates 4625 (failed logon).  
2. DC01 processes the same attempt, generating:
   - 4768 (TGT Request)
   - 4771 (Pre-auth failed)
   - 4776 (NTLM Validation)

The events share consistent:

- timestamps,
- usernames,
- machine names,
- error codes.

This confirms the integrity of the authentication flow across the environment.

 5.4 Wazuh SIEM Detection

Wazuh correctly received Windows logs via its agent on WIN-CLIENT and triggered alerts based on failed authentication activity.

Key detection elements:

- Rule ID "60122" raised alerts for repeated logon failures.
- The affected user (`user-low`) and machine (`WIN-CLIENT`) were correctly identified.
- MITRE ATT&CK techniques applied automatically:
  - "T1078 — Valid Accounts"
  - "T1531 — Account Access Manipulation"

The detailed Wazuh event view shows full normalization of the original Windows event, allowing structured analysis of authentication failures.

 5.5 Detection Summary

The logs demonstrate a complete detection chain:

- "Endpoint layer": failed logons visible (4625)  
- "Domain layer": Kerberos and NTLM processing visible (4768, 4771, 4776)  
- "SIEM layer": correlation and alerting operational  

This confirms that the environment provides full visibility for SOC-level monitoring of authentication-based attacks.

 6. MITRE ATT&CK Mapping & Detection Logic

This section maps the observed events and SIEM detections to the corresponding MITRE ATT&CK techniques.  
The purpose is to demonstrate how brute-force authentication activity aligns with adversarial behaviors documented in the ATT&CK framework.

 6.1 Mapped MITRE Techniques

Wazuh automatically associated the failed authentication events with the following techniques:

| Technique ID | Name | Description |
|--------------|------|-------------|
| "T1078" | Valid Accounts | Adversaries attempt to obtain or guess legitimate credentials to gain access. |
| "T1531" | Account Access Manipulation | Repeated authentication attempts or manipulation of account access states. |

These mappings are consistent with brute-force behavior and are commonly used in SOC detection triage.

 6.2 Detection Logic (Windows Layer)

"Event ID 4625 (Failed Logon)" on WIN-CLIENT indicates repeated failed attempts against `user-low`.

Key indicators:

- Incorrect password status codes (`0xC000006D`, `0xC000006A`)
- Rapid repeated failures
- Interactive logon type (2)
- Same target username across attempts

These elements match the adversary behavior described in ATT&CK T1078.

 6.3 Detection Logic (Domain Controller Layer)

DC01 generated:

- "4768" (Kerberos TGT Requests)  
- "4771" (Kerberos Pre-authentication Failures)  
- "4776" (NTLM Validation)

These events show:

- Credential validation failures across Kerberos and NTLM  
- Repeated authentication attempts from both WIN-CLIENT and KALI  
- Error code `0x18` confirming wrong password in Kerberos  
- A clear authentication failure pattern tied to the same user account

This strengthens the mapping to T1078 and T1531 by showing central authentication service failures.

 6.4 Detection Logic (SIEM Layer)

Wazuh raised alerts using:

- "Rule 60122" (Failed logon detection)
- MITRE mapping: "T1078", "T1531"

The SIEM successfully:

1. Normalized the Windows logs into structured fields  
2. Identified repeated authentication attempts  
3. Mapped the activity to known adversarial techniques  
4. Generated alerts with sufficient context for SOC triage  

This demonstrates that the SIEM layer effectively correlates endpoint-level failures and domain controller events.

 6.5 Summary

The brute-force attack clearly aligns with MITRE ATT&CK techniques:

- "T1078: Valid Accounts"  
  Attempt to guess or obtain valid credentials.

- "T1531: Account Access Manipulation"  
  Repeated failed logon attempts designed to compromise a domain account.

The detection logic across Windows, Active Directory, and Wazuh validates a complete monitoring pipeline.

 7. Conclusion

This laboratory exercise successfully demonstrated the detection and analysis of a brute-force authentication attack across a full Active Directory environment.

Key outcomes:

- "WIN-CLIENT" correctly generated failed authentication events (4625) during the brute-force attempt.
- "DC01" provided deeper visibility through Kerberos and NTLM events (4768, 4771, 4776), confirming password failures from both WIN-CLIENT and the attacker machine (KALI).
- "Wazuh SIEM" collected, normalized, and correlated logs, generating alerts aligned with MITRE ATT&CK techniques (T1078 and T1531).
- The evidence illustrates a complete and realistic detection pipeline:
  - Endpoint → Domain Controller → SIEM.

This lab validates that the monitoring stack is functioning correctly and that authentication-based attacks can be effectively detected and analyzed.  

This investigation demonstrates readiness for SOC roles involving:
- Windows log analysis,
- Active Directory authentication flow understanding,
- detection engineering fundamentals,
- SIEM triage and correlation.

This lab was an opportunity to strengthen my understanding of authentication flows and improve my SOC analytical methodology. I look forward to continuing to develop these skills in a professional environment.

 8. Appendix — Evidence References

All annotated screenshots used in this report are stored in the following directory:

labs/lab-01-bruteforce-ad/evidence/


The evidence set includes:

- Successful logon event (4624)
- Failed logon events (4625)
- Kerberos events from DC01 (4768, 4771)
- NTLM validation events (4776)
- Consolidated authentication timeline from DC01
- Wazuh alert overview and normalized event details

These artifacts provide the visual and technical support for the log analysis and MITRE ATT&CK mapping presented in this investigation.
