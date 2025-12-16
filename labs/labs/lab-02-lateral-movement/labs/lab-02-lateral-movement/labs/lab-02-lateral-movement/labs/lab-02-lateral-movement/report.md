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
 5.1 Domain Controller Analysis (DC01)
 5.2 Endpoint Perspective (WIN-CLIENT)
 5.3 SIEM Visibility (Wazuh)

 6. Detection Gaps & Remediation
 6.1 Identified Visibility Gap
 6.2 Root Cause Analysis
 6.3 Remediation Actions

 7. MITRE ATT&CK Mapping

 8. Conclusion

 9. Appendix — Evidence References
