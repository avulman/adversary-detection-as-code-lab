# Adversary Detection as Code Lab

# AEDL Detection Lab

AEDL is an **Adversary Emulation Detection Lab** built to develop, validate, and document host-based and network-based detections against realistic attacker behavior.

The lab combines:

- **Active Directory**
- **Windows endpoint telemetry via Sysmon**
- **Splunk SIEM**
- **Security Onion for network detection**
- **An attacker VM for controlled adversary simulation**
- **MITRE ATT&CK-mapped validation scenarios**

The goal is not just to "run attacks," but to create a repeatable detection engineering workflow:

**simulate behavior > collect telemetry > write detection logic > validate results > document coverage**

---

## Project Goals

This project is designed to demonstrate practical detection engineering skills by:

- Building a realistic multi-host lab environment
- Generating adversary activity in a controlled way
- Collecting both host and network telemetry
- Writing and validating detections in Splunk and Security Onion
- Mapping detections to MITRE ATT&CK
- Tracking results through a detection validation matrix
- Organizing detections and validations like a detection-as-code project

---

## Lab Architecture

The lab currently includes the following systems:

| Hostname | IP Address | Role |
|---|---|---|
| `CORP-DC-01` | `10.10.10.10` | Domain Controller / DNS |
| `WIN-ENDPOINT-01` | `10.10.10.20` | Windows endpoint / victim host |
| `SPLUNK-SERVER` | `10.10.10.30` | SIEM |
| `SENSOR-NSM` | `10.10.10.40` / `192.168.116.130` | Security Onion network sensor |
| `ATTACKER` | `10.10.10.50` | Adversary simulation host |

Primary lab traffic flows across:

- **Internal lab network:** `10.10.10.0/24`
- **Security Onion management network:** `192.168.116.0/24`

---

## Telemetry Sources

### Host-Based Telemetry
- Windows Event Logs
- Sysmon Operational logs
- Splunk Universal Forwarder
- Indexed into Splunk for host-based detections

### Network-Based Telemetry
- Zeek
- Suricata
- Security Onion SOC
- Indexed into Security Onion / Elastic for hunt and alert validation

---

## Current Workflow

The current detection engineering workflow in this lab is:

1. Generate adversary behavior
2. Confirm telemetry appears in Splunk or Security Onion
3. Build detection logic
4. Validate the logic against the attack
5. Document the outcome
6. Map the result to MITRE ATT&CK

Additional ATT&CK techniques will be added as the lab expands.

## MITRE ATT&CK Definitions:
https://d3fend.mitre.org/offensive-technique/

