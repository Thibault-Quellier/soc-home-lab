 Lab 03 — Suspicious PowerShell Encoded Command Detection

 1. Executive Summary
 
This lab documents the detection and analysis of a suspicious PowerShell execution using an encoded command within a controlled home SOC environment.
The objective of this exercise was to validate endpoint visibility and SIEM detection capabilities for obfuscated PowerShell activity, a technique commonly observed during post-compromise or execution phases of attacks.
The scenario focuses on the execution of a PowerShell command using the `-EncodedCommand` parameter combined with `ExecutionPolicy Bypass` on a Windows endpoint. Native Windows logging (PowerShell Script Block Logging), Sysmon process creation telemetry, and centralized collection through Wazuh SIEM were used to observe and correlate the activity.
This lab demonstrates how endpoint-level telemetry and SIEM correlation provide analysts with actionable visibility into suspicious scripting behavior, even when command content is obfuscated.


 2. Environment Overview
 
 The laboratory environment is a controlled home SOC setup designed to simulate realistic enterprise Windows monitoring scenarios. The environment consists of the following components:

- "WIN-CLIENT"
  - Operating System: Windows 10
  - Role: Endpoint workstation
  - Purpose: Execution of the PowerShell encoded command and generation of endpoint telemetry

- "DC01"
  - Operating System: Windows Server 2019
  - Role: Active Directory Domain Controller
  - Purpose: Domain authentication services (not directly involved in this scenario)

- "WAZUH-MANAGER"
  - Operating System: Ubuntu Server
  - Role: SIEM
  - Purpose: Centralized log collection, normalization, correlation, and alerting

The endpoint WIN-CLIENT is instrumented with native Windows logging and Sysmon, and monitored by a Wazuh agent to ensure full visibility into process creation and PowerShell activity.


 3. Attack Scenario Description
 
 The scenario simulated in this lab focuses on the execution of an obfuscated PowerShell command on a Windows endpoint. A standard domain user account (`user-low`) executed a PowerShell process using the `-EncodedCommand` parameter in combination with `ExecutionPolicy Bypass`. This technique is frequently observed in real-world attacks to obscure command content and bypass basic script execution controls. 
The encoded command itself was intentionally benign and used solely to validate detection capabilities. The purpose of the scenario was not to achieve persistence or privilege escalation, but to generate realistic telemetry associated with suspicious PowerShell execution. 
This activity represents a common execution technique that SOC analysts are expected to identify and triage during incident investigation.


 4. Detection Configuration
 
 To ensure proper visibility into PowerShell execution and process activity, multiple detection mechanisms were enabled on the Windows endpoint. PowerShell Script Block Logging was configured to capture detailed execution content, allowing visibility into PowerShell commands even when obfuscation techniques such as encoded commands are used. Sysmon was deployed on the endpoint to provide low-level process creation telemetry. 
This includes information such as process image paths, command-line arguments, execution context, and parent-child process relationships. 
A Wazuh agent was installed on the endpoint to collect Windows and Sysmon events and forward them to the Wazuh SIEM. This enabled centralized analysis, correlation, and alerting based on the collected telemetry. This layered detection approach ensures that suspicious PowerShell execution can be observed at both the endpoint and SIEM levels.


 5. Log Analysis
 
 The execution of the encoded PowerShell command generated multiple observable events at the endpoint level, providing clear indicators of suspicious activity.

 5.1 PowerShell Script Block Logging (Event ID 4104)

PowerShell Script Block Logging recorded the execution of a command containing the `-EncodedCommand` parameter. This event captures the logical content of the PowerShell execution and provides visibility into obfuscated command usage. 
The presence of an encoded command combined with execution policy bypass is a strong indicator of suspicious scripting behavior and is commonly associated with attacker tradecraft.

 5.2 Process Creation Telemetry

Process creation telemetry captured the launch of `powershell.exe` under a standard domain user context. The recorded command-line arguments show the use of `ExecutionPolicy Bypass` and an encoded command, confirming the execution behavior observed in the Script Block logs.
This process-level visibility allows analysts to identify suspicious execution even when the script content itself is not immediately readable.

 5.3 Correlation Across Telemetry Sources

The correlation of Script Block Logging and process creation events provides a consistent view of the activity. Both data sources reference the same execution timeframe, user context, and PowerShell invocation, enabling confident identification of suspicious behavior.
This layered visibility is essential for accurate detection and triage of PowerShell-based execution techniques.


 6. SIEM Correlation & MITRE ATT&CK Mapping
 
 The collected endpoint telemetry was successfully centralized and analyzed by the Wazuh SIEM, enabling correlation and contextual detection of the suspicious PowerShell activity.
Wazuh correlated the process creation event associated with the PowerShell execution and generated a high-severity alert. The alert description explicitly referenced the execution of a Base64-encoded PowerShell command, providing clear context for SOC analysts.
Based on the observed behavior, the activity was mapped to the following MITRE ATT&CK technique:

- "T1059.001 — Command and Scripting Interpreter: PowerShell"

This technique aligns with the execution of PowerShell commands used to run scripts or commands, including those employing obfuscation techniques such as encoded commands.
The SIEM-level correlation and MITRE mapping demonstrate how centralized monitoring enhances analyst visibility and enables consistent classification of suspicious execution behavior.


 7. Conclusion
 
 This lab demonstrated the detection and analysis of an obfuscated PowerShell execution using an encoded command within a monitored Windows environment.
By combining PowerShell Script Block Logging, process creation telemetry, and centralized SIEM correlation, the activity was clearly observable despite the use of basic obfuscation techniques. The execution context, command-line parameters, and detection metadata provided sufficient information for effective SOC triage.
This scenario highlights the importance of layered visibility and centralized analysis when monitoring scripting activity on Windows endpoints. It also illustrates how commonly used attacker techniques can be detected and contextualized using standard defensive controls.


 8. Appendix — Evidence References
 
 All evidence collected during this lab is stored in the following directory:

- [`evidence/`](./evidence)

The evidence set includes:

- "01_WIN-CLIENT_4104_EncodedCommand.jpg"  
  PowerShell Script Block Logging event capturing the execution of an encoded PowerShell command.

- "02_WIN-CLIENT_Sysmon_EventID1_ProcessCreate.jpg"  
  Process creation event showing PowerShell execution with encoded command parameters.

- "03_Wazuh_Overview_PowerShell_Activity.jpg"  
  Wazuh SIEM overview displaying centralized visibility of PowerShell-related activity on the endpoint.

- "04_Wazuh_Sysmon_EventID1_Details_A.jpg"  
  Detailed SIEM view of the PowerShell process execution event.

- "05_Wazuh_Sysmon_EventID1_Details_B.jpg"  
  Wazuh alert details including detection metadata and MITRE ATT&CK classification.

