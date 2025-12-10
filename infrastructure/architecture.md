# SOC Lab Architecture

# Network
- Internal isolated network: 192.168.100.0/24

# Machines
- Wazuh SIEM (Ubuntu)
- DC01 (Windows Server – Active Directory)
- WIN-CLIENT (Domain workstation)
- Kali Linux (Attacker)

# Active Directory
- Domain: soc.local
- Users:
  - user-low (standard user)
  - user-admin (domain admin)

# Monitoring
- Wazuh agents on DC01 and WIN-CLIENT
- Sysmon active on client
- Windows auditing enabled

This infrastructure replicates a real enterprise SOC environment.
