# LAB 01 – Active Directory Brute Force Detection

# Objective
Detect multiple failed authentication attempts on a domain user.

# Attack Simulation
- Tool: Kali Linux or manual attempts
- Target: WIN-CLIENT
- User: user-low
- Domain: soc.local

# Detection
- SIEM: Wazuh
- Event type: failed logon attempts

# Analysis
Correlation of repeated failed logons from the same source against a domain account.

# Evidence
Screenshots and exported logs stored in ./evidence/

# Final Response
- Account monitoring and potential lockout
- Review of password policy
- Alerting on abnormal authentication failures
