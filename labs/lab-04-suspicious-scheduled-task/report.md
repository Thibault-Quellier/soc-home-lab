# Lab 04 — Suspicious Scheduled Task (Persistence Detection)

## 1. Executive Summary

This lab documents the analysis of a scheduled task persistence technique executed on a Windows endpoint.

The objective was to observe how scheduled task creation is logged at the operating system level, validate process execution through Sysmon, and assess SIEM visibility using Wazuh.
The investigation demonstrates that while Windows and Sysmon provide reliable local evidence of scheduled task creation, SIEM-level correlation may require additional detection logic to surface this activity effectively.

## 2. Environment Overview

This lab was conducted in a controlled home SOC environment designed to simulate endpoint-level persistence techniques and their detection.
The environment consists of the following components:

| Component        | Hostname     | Role                          | Description |
|------------------|--------------|-------------------------------|-------------|
| Windows Endpoint | WIN-CLIENT   | Target system                 | Windows workstation where the scheduled task was created |
| Domain Controller| DC01         | Active Directory services     | Authentication and domain management (not directly involved in this lab) |
| SIEM             | WAZUH        | Central log collection        | Collects endpoint telemetry and enables SOC-level analysis |

All systems are deployed within an isolated internal network to allow controlled testing of attack and detection scenarios.

## 3. Attack Scenario Description

The attack scenario simulated in this lab focuses on persistence through the creation of a scheduled task on a Windows endpoint.
An attacker operating under a low-privilege user context executed native Windows tooling to create a scheduled task designed to maintain execution on the system.
This technique is commonly used by adversaries to achieve persistence while blending into legitimate system activity, as scheduled tasks are widely used for administrative and maintenance purposes.

## 4. Detection Configuration

Evidence for this lab was collected directly from the Windows endpoint involved in the attack scenario.
Three independent log sources were used to validate the activity:

- Windows Security Event Logs, providing visibility into scheduled task creation and process execution.
- Sysmon Operational Logs, offering detailed process creation telemetry including command-line arguments.
- Manual correlation of timestamps and user context across logs.

All evidence was captured after the execution of the attack and stored in the following directory:

labs/lab-04-scheduled-task-persistence/evidence/

Each screenshot was annotated to highlight relevant technical fields and to support the analysis presented in later sections.

## 5. Log Analysis

This section analyzes the logs generated during the scheduled task persistence attempt, focusing on how the activity is recorded across different telemetry sources.

 5.1 Scheduled Task Creation (Windows Security — Event ID 4698)

The creation of a new scheduled task was recorded in the Windows Security log under Event ID 4698.
This event confirms that a scheduled task was successfully created on the endpoint, providing details such as the task name, the user account responsible for the action, and the timestamp of creation.
This log serves as the primary indicator of persistence through task scheduling at the operating system level.

 5.2 Process Creation (Windows Security — Event ID 4688)

Process creation related to the scheduled task was logged as Event ID 4688 in the Windows Security log.
The event confirms the execution of "schtasks.exe" under the same user context observed in the task creation event. However, command-line arguments were not visible in this event, which is a known limitation when command-line auditing is not explicitly enabled in Windows Security policies.
Despite this limitation, the temporal correlation between Events 4688 and 4698 confirms that the scheduled task was created using native Windows tooling.

 5.3 Process Creation Details (Sysmon — Event ID 1)

Sysmon provided detailed process creation telemetry through Event ID 1.
Unlike the Windows Security log, Sysmon captured the full command line used to execute "schtasks.exe", including task creation parameters. This event offers high-fidelity confirmation of the persistence mechanism and compensates for the lack of command-line visibility in native Windows logs.

## 6. SIEM Correlation & MITRE ATT&CK Mapping

This lab highlights important differences in detection coverage between endpoint-level telemetry and SIEM-level visibility.
While Windows Security logs and Sysmon successfully recorded scheduled task creation and process execution locally, SIEM-level detection was limited without dedicated correlation rules.

Specifically:
- Windows Security Event IDs 4698 and 4688 confirmed the creation of a scheduled task and the execution of schtasks.exe.
- Sysmon Event ID 1 provided high-fidelity process creation data, including command-line arguments.
- However, no high-confidence alert or explicit correlation related to scheduled task persistence was observed in Wazuh without custom detection rules.

This reflects a realistic SOC scenario where certain persistence techniques may remain visible only at the endpoint level unless additional detection engineering is performed.

## 7. Conclusion

The activity observed in this lab aligns with known adversary techniques documented in the MITRE ATT&CK framework.
The creation of a scheduled task for persistence maps to the following technique:

- "T1053.005 – Scheduled Task / Job: Scheduled Task"

This technique is commonly used by adversaries to establish persistence by leveraging legitimate Windows functionality. The use of native tools such as "schtasks.exe" allows malicious activity to blend with normal administrative behavior, making detection more challenging without dedicated monitoring and correlation.
The lab demonstrates how endpoint telemetry can reveal this technique even when SIEM-level alerting is not explicitly configured to detect it.

## 8. Appendix — Evidence References

This lab demonstrated how scheduled task persistence can be reliably identified at the endpoint level using native Windows logs and Sysmon telemetry.
Key takeaways from this investigation include:

- Windows Security Event ID 4698 provides direct evidence of scheduled task creation but does not always offer full execution context.
- Windows Security Event ID 4688 confirms process execution but may lack command-line visibility depending on audit policy configuration.
- Sysmon Event ID 1 compensates for these limitations by capturing detailed process creation data, including command-line arguments.
- SIEM-level visibility depends heavily on detection logic and correlation rules; without custom rules, scheduled task persistence may not generate high-confidence alerts.

Overall, this lab reflects a realistic SOC scenario where effective detection relies on combining multiple telemetry sources and understanding their respective strengths and limitations. The results highlight the importance of endpoint visibility and detection engineering when monitoring persistence techniques in Windows environments.
