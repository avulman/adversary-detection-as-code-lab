# Network Layout

## Overview
This lab simulates a small enterprise environment with centralized logging and network monitoring for detection engineering.

## Network Range
- Internal Lab Network: `10.10.10.0/24`
- Security Onion Network: `192.168.116.0/24`

## Systems

| System | Role | IP Address |
|------|------|-----------|
| Domain Controller | Active Directory / DNS | 10.10.10.10 |
| Windows Endpoint | User workstation (Sysmon) | 10.10.10.20 |
| Splunk Server | SIEM / Detection Platform | 10.10.10.30 |
| Security Onion | NDR (Zeek + Suricata) | 10.10.10.40 |
| Attacker VM | Adversary Simulation | 10.10.10.50 |

## Data Flow

- Endpoint → Splunk  
  - Sysmon logs forwarded via Splunk Universal Forwarder

- Network → Security Onion  
  - Traffic mirrored for Zeek and Suricata analysis

- Attacker → Lab Network  
  - Generates test activity (PowerShell, registry queries, nmap scans)

## Detection Coverage

- Host-based: Splunk (Sysmon logs)
- Network-based: Security Onion (Zeek, Suricata)

## Access

- Splunk Web UI: http://10.10.10.30:8000  
- Splunk API: https://10.10.10.30:8089