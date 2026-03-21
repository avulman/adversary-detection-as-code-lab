# Host Inventory

This document tracks the systems that make up the Adversary Detection as Code Lab, including their roles, operating systems, network placement, telemetry, and current project purpose.

---

## Lab Overview

The lab is designed to emulate a small enterprise environment with both host-based and network-based visibility. It supports adversary simulation, telemetry collection, detection development, and validation against MITRE ATT&CK techniques.

### Primary Objectives

- Generate realistic attacker behavior in a controlled environment
- Collect host and network telemetry
- Validate detections in Splunk and Security Onion
- Document MITRE ATT&CK coverage and detection quality
- Build a repeatable detection engineering workflow

---

## Network Summary

### Primary Lab Network
- **Subnet:** `10.10.10.0/24`
- **Purpose:** Internal VMNet enterprise network used by the domain controller, endpoint, Splunk server, Security Onion monitoring interface, and attacker VM.

### Security Onion Management Network
- **Subnet:** `192.168.116.0/24`
- **Purpose:** NAT-based management access for the Security Onion web interface and updates.

---

## Host Table

| Hostname | IP Address | OS | Role | Network | Key Function |
|---|---|---|---|---|---|
| `CORP-DC-01` | `10.10.10.10` | Windows Server 2025 | Domain Controller / DNS | `10.10.10.0/24` | Active Directory, DNS, authentication |
| `WIN-ENDPOINT-01` | `10.10.10.20` | Windows 11 Pro | Endpoint / Victim Host | `10.10.10.0/24` | Attack target, Sysmon telemetry, Atomic Red Team attack generation |
| `SPLUNK-SERVER` | `10.10.10.30` | Ubuntu Server | SIEM | `10.10.10.0/24` | Centralized ingestion and detection via Splunk |
| `SENSOR-NSM` | `10.10.10.40` / `192.168.116.130` | Security Onion | Network Detection / Monitoring | `10.10.10.0/24` and `192.168.116.0/24` | Zeek, Suricata, SOC visibility |
| `ATTACKER` | `10.10.10.50` | Ubuntu Server | Adversary Simulation Host | `10.10.10.0/24` | Reconnaissance, scan activity, attack generation |

---

## Individual Host Details

---

### 1. CORP-DC-01

- **Hostname:** `CORP-DC-01`
- **IP Address:** `10.10.10.10`
- **Operating System:** Windows Server 2025
- **Role:** Domain Controller and DNS server
- **Domain:** `corp.local`

#### Responsibilities
- Hosts Active Directory
- Provides DNS resolution for the lab
- Supports domain authentication and account management
- Generates authentication and directory-related telemetry

#### Example Accounts
- `corp\anton.admin`
- `corp\anton.user`

#### Detection Relevance
This host is critical for:
- Kerberos-related traffic
- SMB authentication patterns
- LDAP and directory service activity
- Lateral movement testing
- Internal enumeration and account activity

---

### 2. WIN-ENDPOINT-01

- **Hostname:** `WIN-ENDPOINT-01`
- **IP Address:** `10.10.10.20`
- **Operating System:** Windows 11 Pro
- **Role:** Primary Windows endpoint / simulated compromised host

#### Responsibilities
- Generates endpoint telemetry through Sysmon
- Forwards Windows logs and Sysmon logs to Splunk
- Serves as a target for attacker reconnaissance and later attack simulation
- Executes Windows-based adversary behaviors, including PowerShell and registry activity

#### Installed Tooling
- Sysmon
- Splunk Universal Forwarder
- Atomic Red Team / Invoke-AtomicRedTeam components
- Python
- Nmap

#### Detection Relevance
This host is critical for:
- Sysmon Event ID 1 (process creation)
- Sysmon Event ID 3 (network connection)
- Sysmon Event ID 11 (file creation)
- PowerShell execution detection
- Registry query detection
- Scheduled task and persistence testing

---

### 3. SPLUNK-SERVER

- **Hostname:** `SPLUNK-SERVER`
- **IP Address:** `10.10.10.30`
- **Operating System:** Ubuntu Server
- **Role:** SIEM / host telemetry analysis platform

#### Responsibilities
- Receives forwarded Windows logs
- Stores and searches Sysmon telemetry
- Supports detection development using SPL
- Serves as the primary platform for host-based detection engineering

#### Current Data Sources
- Windows Security logs
- Windows Application logs
- Sysmon Operational logs

#### Primary Indexes
- `aedl`
- `sysmon`

#### Detection Relevance
This host is critical for:
- SPL detection logic development
- Process creation analysis
- Parent-child process relationships
- Command-line detection
- Event correlation and validation

---

### 4. SENSOR-NSM

- **Hostname:** `SENSOR-NSM`
- **Management IP:** `192.168.116.130`
- **Lab IP:** `10.10.10.40`
- **Operating System:** Security Onion
- **Role:** Network Security Monitoring / NDR platform

#### Responsibilities
- Monitors traffic on the lab network
- Runs Zeek for network metadata
- Runs Suricata for IDS alerts
- Exposes the Security Onion SOC web interface
- Supports hunt and alert validation for network-based detections

#### Network Interfaces
- **Management Interface:** NAT-based interface for web access and updates
- **Monitoring Interface:** Attached to `10.10.10.0/24` for lab traffic visibility

#### Detection Relevance
This host is critical for:
- Network service discovery detection
- Internal scanning visibility
- DNS telemetry
- SMB and Kerberos network events
- East-west traffic analysis
- Zeek and Suricata alert generation

---

### 5. ATTACKER

- **Hostname:** `ATTACKER`
- **IP Address:** `10.10.10.50`
- **Operating System:** Ubuntu Server
- **Role:** Adversary simulation host

#### Responsibilities
- Generates network-based attack activity
- Performs scanning, enumeration, and recon against lab systems
- Produces clean, attributable attacker traffic for validation testing

#### Installed Tooling
- Nmap
- Net-tools
- DNS utilities
- Git

#### Detection Relevance
This host is critical for:
- MITRE ATT&CK T1046 (Network Service Discovery)
- Internal recon activity
- Scan detection validation
- Controlled source attribution for network alerts

---

## Data Flow Summary

### Host Telemetry Flow
`WIN-ENDPOINT-01`  
- Sysmon / Windows Event Logs  
-  Splunk Universal Forwarder  
- `SPLUNK-SERVER`  
- Detection development in Splunk

### Network Telemetry Flow
`ATTACKER`, `WIN-ENDPOINT-01`, `CORP-DC-01`, `SPLUNK-SERVER`  
- Lab traffic on `10.10.10.0/24`  
- `SENSOR-NSM` monitoring interface  
- Zeek / Suricata / Elastic  
- Security Onion SOC