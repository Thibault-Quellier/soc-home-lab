# Lab 06 – Kerberoasting Detection

## 1. Executive Summary

This lab demonstrates how Kerberos Service Ticket (TGS) requests can be monitored in an Active Directory environment to support the detection of Kerberoasting activity.

A dedicated service account (`svc_sql`) was configured with a Service Principal Name (SPN). A Kerberos TGS request was generated from a domain workstation using native Windows functionality, producing Windows Security Event ID 4769 on the Domain Controller.

The generated telemetry was validated locally through Windows Event Viewer and compared with the events collected by Wazuh. During the investigation, it was observed that the Windows Security event was successfully generated on the Domain Controller, while the corresponding event was not converted into a Wazuh alert under the default ruleset. This highlights the importance of validating detections both at the log source and within the SIEM pipeline.

**MITRE ATT&CK**

- **T1558.003 – Kerberoasting**
- **TA0006 – Credential Access**
