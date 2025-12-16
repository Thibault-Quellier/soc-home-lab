 Lab 02 — Lateral Movement Detection (SMB / NTLM)
 
 1. Executive Summary

This lab documents the detection and analysis of a simulated lateral movement attempt within a controlled Active Directory environment.

The objective was to observe how a remote authentication attempt using SMB and NTLM is processed by a Domain Controller, and to evaluate the visibility of such activity across endpoint logs, domain controller logs, and the SIEM platform.

During the exercise, an attacker machine attempted to authenticate remotely to the Domain Controller using a low-privilege domain account. Although the authentication attempt failed and no access was obtained, the activity generated relevant security events that could be analyzed and correlated.

The investigation highlights:
- how NTLM authentication attempts are logged on a Domain Controller,
- how failed lateral movement can still be detected,
- and how SIEM visibility gaps can be identified and remediated.

This lab emphasizes a realistic SOC workflow, including log analysis, identification of detection blind spots, and remediation to restore full monitoring coverage.

 2. Environment Overview

This lab was conducted within a controlled home SOC environment designed to replicate a small Active Directory infrastructure.

The environment allows observation of authentication activity across endpoints, the Domain Controller, and the SIEM platform, providing end-to-end visibility of lateral movement attempts.

 2.1 Infrastructure Components

| Component | Hostname | Role | Description |
|---------|----------|------|-------------|
| Windows 11 | WIN-CLIENT | Domain workstation | Generates outbound authentication activity 
| Windows Server 2022 | DC01 | Domain Controller | Processes Kerberos and NTLM authentication 
| Kali Linux | KALI | Attacker machine | Initiates lateral movement attempts 
| Ubuntu Server | WAZUH-MANAGER | SIEM | Centralized log collection and analysis 

 2.2 Network Topology

All systems are connected to a single isolated internal network using the subnet "192.168.100.0/24".

- "WIN-CLIENT" and "DC01" are joined to the same Active Directory domain.
- "KALI" resides on the same internal network and is used to simulate attacker activity.
- "WAZUH-MANAGER" receives logs from Wazuh agents deployed on Windows systems.

This topology enables direct observation of authentication flows between endpoints, the Domain Controller, and the SIEM without external network dependencies.

3. Attack Scenario Description

This lab simulates a "lateral movement attempt" within an Active Directory environment. The attack targeted the low-privilege domain account `user-low` and was executed from the attacker machine "KALI" using "SMB" and "NTLM" authentication protocols.

The objective of the exercise was to validate the ability to detect failed lateral movement attempts across the environment. This involved:
- sending remote authentication attempts via SMB from "KALI" to "DC01", 
- using "NTLM" authentication (typically less secure than Kerberos), 
- targeting a low-privilege domain account.

 3.1 Initial Access Context

- "Username": `user-low`
- "Role": Low-privilege domain user
- "Reason for selection": Low-privilege accounts are often targeted in brute-force and lateral movement attacks due to their predictable usernames and lower scrutiny from security teams.

 3.2 Lateral Movement Attempt

The attacker machine "KALI" attempted to authenticate multiple times to "DC01" using the credentials of the low-privilege account `user-low`.

The SMB authentication was initiated as a network logon (Logon Type 3), and failed attempts were logged on both the endpoint "WIN-CLIENT" and the "Domain Controller (DC01)". Despite these failures, the event logs generated during the attempt are critical for identifying the attack pattern and understanding the behavior of the attack.

Wazuh, acting as the SIEM, collected and processed the event data, but failed to correlate certain NTLM authentication failures (Event ID 4776) due to initial configuration issues. The visibility gap was identified and remediated by adjusting the agent configuration to enable the full capture of Event ID 4776 on "DC01".

 4. Evidence Collection

Evidence for this lab was collected from multiple points in the environment to ensure full visibility of the lateral movement attempt.

The following systems were used as evidence sources:

- "DC01 (Domain Controller)"  
  Security event logs were reviewed to identify NTLM authentication attempts related to lateral movement activity. Event ID "4776" was the primary indicator used to confirm remote authentication attempts originating from the attacker machine.

- "WIN-CLIENT (Domain Workstation)"  
  Endpoint security logs were reviewed to verify whether outbound network authentication events were generated during the lateral movement attempt. No reliable Logon Type 3 events were observed on the endpoint, which is consistent with this attack scenario.

- "Wazuh SIEM"  
  Wazuh was used to centralize and analyze security events. Initial investigation revealed that NTLM authentication events from the Domain Controller were not ingested due to restricted access to the Security log. This visibility gap was later resolved, allowing Event ID 4776 to be successfully collected and analyzed within the SIEM.

All screenshots were captured immediately after the attack activity and are stored in the following directory:

`labs/lab-02-lateral-movement/evidence/`

Each capture highlights relevant timestamps, usernames, source systems, and authentication details necessary for SOC-level investigation.


 5. Log Analysis

This section analyzes the authentication events generated during the SMB-based lateral movement attempt performed from the attacker machine (KALI) against the Active Directory environment.

The objective is to demonstrate:
- which authentication logs are generated on the Domain Controller (DC01),
- which logs are (or are not) generated on the endpoint (WIN-CLIENT),
- and how these events are collected and correlated by Wazuh.


 5.1 Authentication Behavior Overview

The attacker machine (KALI) attempted to access an SMB resource using the low-privilege domain account `user-low`.

The attempt resulted in:
- successful network connectivity (ICMP and TCP/445),
- an SMB authentication attempt,
- access denial due to insufficient privileges (`NT_STATUS_ACCESS_DENIED`).

Although access was denied, credential validation still occurred at the domain level.

 5.2 Domain Controller Log Analysis (DC01)

During the attack timeframe, DC01 generated the following key event:

#### Event ID 4776 — NTLM Authentication

This event indicates that the Domain Controller attempted to validate the credentials provided during the SMB authentication attempt.

Observed fields:
- Account Name: `user-low`
- Source Workstation: `KALI`
- Authentication Package: NTLM

This event confirms:
- that the credentials were processed by the Domain Controller,
- that the authentication originated from the attacker machine,
- and that this activity represents a potential lateral movement attempt.

 5.3 Endpoint Log Analysis (WIN-CLIENT)

On the target endpoint WIN-CLIENT, the following observations were made:

- No Event ID 4624 (Type 3 — Network Logon) was generated.
- No local authentication session was established.

This behavior is expected because:
- the SMB authentication failed before any resource access,
- credential validation was handled directly by DC01,
- and the endpoint did not create a logon session.

This highlights an important SOC concept:
"lateral movement attempts may be visible on the Domain Controller but not on the target endpoint."


 5.4 Wazuh Log Visibility

Initially, Event ID 4776 was visible on DC01 but not ingested by Wazuh.

After adjusting Windows Security log configuration and restarting the Wazuh agent:
- Event ID 4776 became visible in Wazuh
- the event was normalized correctly
- the attacker workstation `KALI` and target account `user-low` were clearly identified.

This confirms that Wazuh is capable of detecting NTLM-based lateral movement attempts when log collection is properly configured.

 5.5 Analysis Summary

The log analysis shows:

- Successful NTLM authentication validation attempts logged on DC01,
- Absence of corresponding logon events on the endpoint,
- Correct SIEM ingestion after configuration adjustment.

This scenario reflects a realistic SOC challenge, where:
- authentication attempts may not generate endpoint logs,
- Domain Controller logs become the primary detection source,
- and SIEM configuration directly impacts detection capability.
 

 6. MITRE ATT&CK Mapping & Detection Logic

This section maps the observed authentication activity to the MITRE ATT&CK framework and explains the detection logic applied across the Domain Controller and SIEM layers.

The objective is to demonstrate how an SMB-based lateral movement attempt can be identified through authentication artifacts rather than successful access.

 6.1 Mapped MITRE ATT&CK Techniques

The activity observed during this lab aligns with the following MITRE ATT&CK technique:

| Technique ID | Name | Description |
|--------------|------|-------------|
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Adversaries attempt to move laterally by accessing SMB shares on remote systems using valid or guessed credentials. 

This technique applies even when access is denied, as credential validation still occurs.

 6.2 Detection Logic — Domain Controller Layer

The primary detection signal for this lab is **Event ID 4776 (NTLM authentication)** on DC01.

Detection indicators:
- Repeated or suspicious NTLM authentication attempts
- Low-privilege domain account (`user-low`)
- Source workstation identified as `KALI`
- Authentication attempts outside normal administrative behavior

Although the authentication failed, the presence of these indicators is sufficient to flag potential lateral movement.

 6.3 Detection Logic — Endpoint Layer

No corresponding "Event ID 4624 (Type 3 — Network Logon)" was generated on WIN-CLIENT.

This is a critical detection insight:

- Lateral movement attempts may fail before resource access
- Endpoints may generate no authentication logs
- Relying solely on endpoint logs can lead to missed detections

SOC analysts must therefore prioritize Domain Controller logs when investigating lateral movement.

 6.4 Detection Logic — SIEM Layer (Wazuh)

Once Event ID 4776 was ingested by Wazuh, the SIEM provided:

- Centralized visibility of NTLM authentication attempts
- Normalized fields identifying:
  - target user (`user-low`)
  - source workstation (`KALI`)
  - authentication method (NTLM)
- A timeline correlating authentication attempts with attack activity

This demonstrates the importance of:
- collecting Domain Controller security logs
- validating SIEM ingestion paths
- and verifying detection coverage beyond endpoints

 6.5 Detection Summary

The detection logic for this lab is based on:

- "Authentication validation events", not successful access
- "Domain-level visibility", not endpoint-only logs
- "Contextual analysis", combining account, source host, and protocol

This approach reflects real-world SOC detection strategies for lateral movement in Active Directory environments.

 7. Conclusion

This lab demonstrated the detection and analysis of a failed lateral movement attempt within an Active Directory environment.

Although the SMB authentication attempt did not result in successful access, the activity generated meaningful authentication artifacts at the Domain Controller level. Event ID 4776 provided clear evidence of NTLM credential validation originating from the attacker machine, highlighting the importance of domain-level visibility when investigating lateral movement.

The investigation also revealed a SIEM visibility gap caused by restricted access to the Windows Security log on the Domain Controller. Identifying and remediating this issue reinforced a key SOC lesson: detection effectiveness depends not only on log generation, but also on proper log collection and ingestion by the SIEM.

This lab emphasizes several important SOC concepts:
- lateral movement attempts may fail yet still be detectable,
- Domain Controller logs are critical for authentication-based detections,
- SIEM configuration must be validated to ensure complete coverage.

Overall, this exercise reflects a realistic SOC workflow involving log analysis, detection gap identification, and remediation, and reinforces the importance of careful monitoring of authentication activity in Active Directory environments.

 8. Evidence References

This section documents all evidence collected during **Lab 02 – Lateral Movement Detection**.
Each artifact supports a specific observation made during the investigation and confirms
visibility at both the **Domain Controller (DC01)** and **SIEM (Wazuh)** levels.

All evidence files are stored in:

labs/lab-02-lateral-movement/evidence/

 Evidence 1 — DC01 NTLM Credential Validation (Event ID 4776)

File:
4776_DC01_NTLM_Details.jpg

Description:
Windows Security Event ID 4776 recorded on DC01, showing a credential validation attempt.

Visible elements:
- Event ID: 4776
- Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
- Target user: user-low
- Source workstation: KALI
- Status code: 0xC000006A

Why it matters:
This event confirms that the Domain Controller processed an authentication attempt
originating from the attacker machine and rejected it due to invalid credentials.

 Evidence 2 — NTLM Validation Without Explicit NTLM Label

File:
4776_DC01_NTLM_Details_2.jpg

Description:
Additional Event ID 4776 log showing credential validation activity on DC01.

Visible elements:
- Event ID: 4776
- Authentication package information
- User account: user-low
- Source workstation: KALI

Why it matters:
This evidence demonstrates that NTLM authentication is identified through
Event ID 4776 and authentication package fields, even when the "NTLM" string
is not explicitly displayed in the Event Viewer UI.

 Evidence 3 — Wazuh Security Events Overview

File:
Wazuh_4776_Overview.jpg

Description:
Wazuh dashboard overview displaying Windows security audit failures collected from DC01.

Visible elements:
- Windows audit failure alerts
- Rule group: windows_security
- Alert level: 5

Why it matters:
This view confirms that authentication failures from the Domain Controller
are successfully ingested and categorized by the SIEM.

 Evidence 4 — Wazuh Filtered View (Event ID 4776)

File:
Wazuh_4776_Overview2.jpg

Description:
Wazuh event view filtered specifically on Event ID 4776.

Visible elements:
- Event ID filter: 4776
- Agent: DC01
- Total events: 1

Why it matters:
This evidence confirms that NTLM credential validation events from DC01
are indexed and searchable within Wazuh.

 Evidence 5 — Wazuh Normalized Event Details (Event ID 4776)

File:
Wazuh_4776_Event_Details.jpg

Description:
Detailed Wazuh event showing normalized fields extracted from the original Windows log.

Visible elements:
- Agent name: DC01
- Target user: user-low
- Source workstation: KALI
- Event ID: 4776
- Status code: 0xC000006A
- Original Windows message

Why it matters:
This evidence demonstrates that Wazuh correctly parses and normalizes
NTLM authentication events, enabling structured SOC analysis.

 Evidence 6 — DC01 Security Log ACL Configuration (After Fix)

File:
DC01_Security_Log_ACL_After.jpg

Description:
PowerShell output showing updated ACL permissions on the Security event log
and a restart of the Wazuh service.

Visible elements:
- Updated channelAccess configuration
- wevtutil command applied to the Security log
- Wazuh service restarted and running

Why it matters:
This evidence explains the remediation step that allowed Event ID 4776
to become visible in Wazuh, validating the troubleshooting process.

 Evidence Summary

The evidence collected demonstrates a complete detection chain:

- Authentication attempts originating from KALI
- Credential validation performed by DC01 (Event ID 4776)
- Log collection and normalization by Wazuh
- Successful SIEM visibility after correcting log permissions

This evidence set supports the findings presented in this report and
confirms effective monitoring of NTLM-based lateral movement activity.
